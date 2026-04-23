"""API route handlers."""

import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from ..core.session import AnalysisSession, APICallRecord, TechniqueMatch, AnalysisResult
from ..db.store import DatabaseStore
from ..output.navigator import generate_navigator_layer
from ..output.report import generate_report
from ..output.stix import generate_stix_bundle
from ..utils.hashing import compute_file_hash, detect_file_type
from ..utils.binary import detect_platform_arch

router = APIRouter()

# In-memory task tracking for running analyses
_tasks: dict[str, dict[str, Any]] = {}


def get_db(request: Request) -> DatabaseStore:
    """Get database store from request app state."""
    return request.app.state.db


async def _run_analysis_background(
    session_id: str,
    sample_path: str,
    platform: str,
    architecture: str,
    timeout: int,
    db_path: str,
) -> None:
    """
    Run analysis in background and persist results to database.

    Invokes the Qiling-based DetonateEmulator to analyze the sample.
    """
    from ..core.emulator import DetonateEmulator
    import shutil
    import os
    
    # Create fresh DB connection for background task
    db = DatabaseStore(db_path)
    try:
        # Update status to running
        db.update_analysis_status(session_id, "running")
        _tasks[session_id]["status"] = "running"

        # Run emulator with sample copied into rootfs tmp directory
        from ..config import get_settings
        settings = get_settings()
        rootfs_path = settings.get_rootfs_path(platform, architecture)
        
        # Copy sample into rootfs tmp so Qiling can access it
        sample_temp_dir = rootfs_path / "tmp"
        sample_temp_dir.mkdir(parents=True, exist_ok=True)
        temp_in_rootfs = sample_temp_dir / f"sample_{os.path.basename(sample_path)}"
        shutil.copy2(sample_path, temp_in_rootfs)
        
        try:
            emulator = DetonateEmulator(
                sample_path=str(temp_in_rootfs),
                platform=platform,
                arch=architecture,
                timeout=timeout,
                settings=settings,
            )
            
            result = await emulator.run()
            
            # Persist results to database
            completed_at = datetime.now(timezone.utc)
            db.update_analysis_status(
                session_id,
                "completed",
                completed_at=completed_at,
                duration_seconds=result.duration_seconds,
            )
            
            # Get analysis ID for storing API calls and findings
            analysis = db.get_analysis(session_id)
            if analysis:
                # Store API calls
                if result.api_calls:
                    db.add_api_calls(analysis.id, result.api_calls)
                
                # Store findings/techniques
                if result.findings:
                    db.add_findings(analysis.id, result.findings)
            
            _tasks[session_id]["status"] = "completed"
            _tasks[session_id]["completed_at"] = completed_at.isoformat()
        finally:
            # Cleanup sample from rootfs tmp
            if temp_in_rootfs.exists():
                temp_in_rootfs.unlink()

    except Exception as e:
        # Only update to failed if not already completed
        if _tasks.get(session_id, {}).get("status") != "completed":
            import traceback
            error_msg = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
            try:
                db.update_analysis_status(
                    session_id,
                    "failed",
                    error_message=error_msg,
                    completed_at=datetime.now(timezone.utc),
                )
            except ValueError:
                pass  # Already in terminal state
            _tasks[session_id]["status"] = "failed"
            _tasks[session_id]["error"] = str(e)


@router.post("/analyze")
async def submit_analysis(
    request: Request,
    file: UploadFile,
    platform: str = Query(default="auto", description="Target platform"),
    arch: str = Query(default="auto", description="Target architecture"),
    timeout: int = Query(default=60, ge=1, le=300, description="Execution timeout"),
    background_tasks: BackgroundTasks = None,
):
    """Submit a sample for analysis."""
    db: DatabaseStore = get_db(request)

    # Read file content
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file provided")

    # Compute hashes
    sample_sha256 = compute_file_hash(content, "sha256")
    sample_md5 = compute_file_hash(content, "md5")

    # Detect file type
    file_type = detect_file_type(content)

    # Save sample to temporary location
    import tempfile
    sample_dir = Path(tempfile.gettempdir()) / "detonate_samples"
    sample_dir.mkdir(parents=True, exist_ok=True)
    sample_path = sample_dir / f"{sample_sha256}"
    sample_path.write_bytes(content)

    # Determine platform and architecture
    effective_platform = platform
    effective_arch = arch
    if platform == "auto" or arch == "auto":
        detected_platform, detected_arch = detect_platform_arch(sample_path)
        if platform == "auto":
            effective_platform = detected_platform
        if arch == "auto":
            effective_arch = detected_arch

    # Create database record
    session_id = str(uuid.uuid4())
    db.create_analysis(
        session_id=session_id,
        sample_sha256=sample_sha256,
        sample_md5=sample_md5,
        sample_path=str(sample_path),
        sample_size=len(content),
        file_type=file_type,
        platform=effective_platform,
        architecture=effective_arch,
    )

    # Track in memory
    _tasks[session_id] = {
        "session_id": session_id,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "sample_sha256": sample_sha256,
        "platform": effective_platform,
        "architecture": effective_arch,
    }

    # Start background analysis
    if background_tasks is not None:
        background_tasks.add_task(
            _run_analysis_background,
            session_id,
            str(sample_path),
            effective_platform,
            effective_arch,
            timeout,
            str(request.app.state.db_path),
        )

    return {
        "session_id": session_id,
        "status": "pending",
        "created_at": _tasks[session_id]["created_at"],
    }


@router.get("/analyze/{session_id}")
async def get_analysis_status(session_id: str, request: Request):
    """Get analysis status and results."""
    db: DatabaseStore = get_db(request)

    # Check database first
    db_analysis = db.get_analysis(session_id)

    # Check in-memory tasks
    if session_id not in _tasks:
        if db_analysis is None:
            raise HTTPException(status_code=404, detail="Analysis not found")
        # Analysis exists in DB but not in memory (server restart)
        # Return full info from DB
        return {
            "session_id": session_id,
            "status": db_analysis.status,
            "created_at": db_analysis.created_at.isoformat() if db_analysis.created_at else None,
            "file_size": db_analysis.sample_size,
            "platform": db_analysis.platform,
            "architecture": db_analysis.architecture,
            "md5": db_analysis.sample_md5,
            "sha256": db_analysis.sample_sha256,
            "file_type": db_analysis.file_type,
            "completed_at": db_analysis.completed_at.isoformat() if db_analysis.completed_at else None,
            "duration_seconds": db_analysis.duration_seconds,
            "findings": [],
            "outputs": {
                "navigator": f"/api/v1/reports/{session_id}/navigator",
                "stix": f"/api/v1/reports/{session_id}/stix",
                "report": f"/api/v1/reports/{session_id}/report",
                "log": f"/api/v1/reports/{session_id}/log",
            } if db_analysis.status == "completed" else None,
        }

    task_info = _tasks[session_id]

    # Build response
    response = {
        "session_id": session_id,
        "status": task_info.get("status", "pending"),
        "created_at": task_info.get("created_at"),
    }

    # Add DB data if available
    if db_analysis:
        response["file_size"] = db_analysis.sample_size
        response["platform"] = db_analysis.platform
        response["architecture"] = db_analysis.architecture
        response["md5"] = db_analysis.sample_md5
        response["sha256"] = db_analysis.sample_sha256
        response["file_type"] = db_analysis.file_type
        response["completed_at"] = db_analysis.completed_at.isoformat() if db_analysis.completed_at else None
        response["duration_seconds"] = db_analysis.duration_seconds

    if task_info.get("status") == "completed":
        response["analysis"] = {
            "completed_at": task_info.get("completed_at"),
            "duration_seconds": response.get("duration_seconds", 0.1),
            "techniques_detected": 0,
            "tactics_observed": [],
        }
        response["findings"] = []
        response["outputs"] = {
            "navigator": f"/api/v1/reports/{session_id}/navigator",
            "stix": f"/api/v1/reports/{session_id}/stix",
            "report": f"/api/v1/reports/{session_id}/report",
            "log": f"/api/v1/reports/{session_id}/log",
        }

    return response


@router.get("/reports")
async def list_reports(
    request: Request,
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=20, ge=1, le=100, description="Items per page"),
    status: str | None = Query(default=None, description="Filter by status"),
    platform: str | None = Query(default=None, description="Filter by platform"),
):
    """List all analyses with pagination."""
    db: DatabaseStore = get_db(request)

    # Validate pagination bounds
    if page < 1:
        raise HTTPException(status_code=400, detail="page must be >= 1")
    if per_page > 100:
        raise HTTPException(status_code=400, detail="per_page must be <= 100")

    # Validate filters
    if status is not None and status not in ("pending", "running", "completed", "failed"):
        raise HTTPException(status_code=400, detail=f"Invalid status '{status}'")
    if platform is not None and platform not in ("windows", "linux"):
        raise HTTPException(status_code=400, detail=f"Invalid platform '{platform}'")

    try:
        offset = (page - 1) * per_page
        result = db.list_analyses(status=status, platform=platform, limit=per_page, offset=offset)

        return {
            "items": [
                {
                    "session_id": item.session_id,
                    "sample_sha256": item.sample_sha256,
                    "platform": item.platform,
                    "status": item.status,
                    "created_at": item.created_at.isoformat() if item.created_at else None,
                }
                for item in result.items
            ],
            "total": result.total,
            "page": result.page,
            "per_page": result.per_page,
            "pages": result.pages,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/reports/{session_id}/navigator")
async def get_navigator_report(session_id: str, request: Request):
    """Download ATT&CK Navigator layer JSON."""
    db: DatabaseStore = get_db(request)

    # Check database first
    db_analysis = db.get_analysis(session_id)
    if db_analysis is None:
        # Fallback to in-memory
        if session_id not in _tasks:
            raise HTTPException(status_code=404, detail="Analysis not found")
        task_info = _tasks[session_id]
        if task_info.get("status") != "completed":
            raise HTTPException(status_code=400, detail="Analysis not completed")
        sample_sha256 = task_info.get("sample_sha256", "unknown")
        platform = task_info.get("platform", "windows")
    else:
        if db_analysis.status != "completed":
            raise HTTPException(status_code=400, detail="Analysis not completed")
        sample_sha256 = db_analysis.sample_sha256
        platform = db_analysis.platform

    # Generate navigator layer (would use real findings from DB in production)
    layer = generate_navigator_layer(
        session_id=session_id,
        sample_sha256=sample_sha256,
        findings=[],
        platform=platform,
    )

    return JSONResponse(
        content=layer,
        headers={
            "Content-Disposition": f'attachment; filename="navigator_{session_id[:8]}.json"'
        },
    )


@router.get("/reports/{session_id}/stix")
async def get_stix_report(session_id: str, request: Request):
    """Download STIX 2.1 bundle."""
    db: DatabaseStore = get_db(request)

    # Check database first
    db_analysis = db.get_analysis(session_id)
    if db_analysis is None:
        if session_id not in _tasks:
            raise HTTPException(status_code=404, detail="Analysis not found")
        task_info = _tasks[session_id]
        if task_info.get("status") != "completed":
            raise HTTPException(status_code=400, detail="Analysis not completed")
        sample_sha256 = task_info.get("sample_sha256", "unknown")
    else:
        if db_analysis.status != "completed":
            raise HTTPException(status_code=400, detail="Analysis not completed")
        sample_sha256 = db_analysis.sample_sha256

    # Generate STIX bundle (would use real data from DB in production)
    bundle = generate_stix_bundle(
        session_id=session_id,
        sample_sha256=sample_sha256,
        sample_path="/tmp/sample",
        findings=[],
        api_calls=[],
    )

    # Convert to dict for JSON response
    bundle_dict = dict(bundle)

    return JSONResponse(
        content=bundle_dict,
        headers={
            "Content-Disposition": f'attachment; filename="stix_{session_id[:8]}.json"'
        },
    )


@router.get("/reports/{session_id}/report")
async def get_text_report(session_id: str, request: Request):
    """Download human-readable Markdown report."""
    db: DatabaseStore = get_db(request)

    # Check database first
    db_analysis = db.get_analysis(session_id)
    if db_analysis is None:
        if session_id not in _tasks:
            raise HTTPException(status_code=404, detail="Analysis not found")
        task_info = _tasks[session_id]
        if task_info.get("status") != "completed":
            raise HTTPException(status_code=400, detail="Analysis not completed")
        sample_sha256 = task_info.get("sample_sha256", "unknown")
        platform = task_info.get("platform", "windows")
        architecture = task_info.get("architecture", "x86_64")
    else:
        if db_analysis.status != "completed":
            raise HTTPException(status_code=400, detail="Analysis not completed")
        sample_sha256 = db_analysis.sample_sha256
        platform = db_analysis.platform
        architecture = db_analysis.architecture

    # Get findings from database
    findings_data = db.get_analysis_with_data(session_id, include_findings=True, include_api_calls=True, include_strings=True)
    
    # Convert DB findings to TechniqueMatch objects
    technique_matches = []
    if findings_data and hasattr(findings_data, 'findings') and findings_data.findings:
        for f in findings_data.findings:
            technique_matches.append(TechniqueMatch(
                technique_id=f.technique_id,
                technique_name=f.technique_name,
                tactic=f.tactic,
                confidence=f.confidence,
                confidence_score=f.confidence_score,
                evidence_count=f.evidence_count,
                first_seen=f.first_seen,
                last_seen=f.last_seen,
            ))
    
    # Convert DB API calls to APICallRecord objects
    api_call_records = []
    if findings_data and hasattr(findings_data, 'api_calls') and findings_data.api_calls:
        for call in findings_data.api_calls:
            api_call_records.append(APICallRecord(
                timestamp=call.timestamp,
                api_name=call.api_name,
                syscall_name=call.syscall_name,
                params=call.params_json or {},
                return_value=call.return_value,
                address=call.address or '',
                technique_id=call.technique_id,
                confidence=call.confidence,
                sequence_number=call.sequence_number,
            ))
    
    # Convert DB strings
    string_list = []
    if findings_data and hasattr(findings_data, 'strings') and findings_data.strings:
        string_list = [s.value for s in findings_data.strings]

    # Create a full AnalysisResult for the report generator
    now = datetime.now(timezone.utc)
    started_at = db_analysis.created_at if db_analysis else now - timedelta(seconds=5)
    result = AnalysisResult(
        session_id=session_id,
        sample_sha256=sample_sha256,
        sample_md5=db_analysis.sample_md5 if db_analysis else None,
        sample_path="/tmp/sample",
        sample_size=db_analysis.sample_size if db_analysis else 0,
        file_type=db_analysis.file_type if db_analysis else "Unknown",
        platform=platform,
        architecture=architecture,
        status="completed",
        error_message=None,
        started_at=started_at,
        completed_at=db_analysis.completed_at if db_analysis else now,
        duration_seconds=db_analysis.duration_seconds if db_analysis else 5.0,
        api_calls=api_call_records,
        findings=technique_matches,
        strings=string_list,
    )

    report = generate_report(result)

    return Response(
        content=report,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="report_{session_id[:8]}.md"'
        },
    )


@router.get("/reports/{session_id}/log")
async def get_json_log(session_id: str, request: Request):
    """Stream structured JSON log."""
    db: DatabaseStore = get_db(request)

    # Check database first
    db_analysis = db.get_analysis(session_id)
    if db_analysis is None:
        if session_id not in _tasks:
            raise HTTPException(status_code=404, detail="Analysis not found")
        task_info = _tasks[session_id]
        sample_sha256 = task_info.get("sample_sha256", "unknown")
        platform = task_info.get("platform", "windows")
        architecture = task_info.get("architecture", "x86_64")
        created_at = task_info.get("created_at")
        completed_at = task_info.get("completed_at")
        status = task_info.get("status", "pending")
    else:
        sample_sha256 = db_analysis.sample_sha256
        platform = db_analysis.platform
        architecture = db_analysis.architecture
        created_at = db_analysis.created_at.isoformat() if db_analysis.created_at else None
        completed_at = db_analysis.completed_at.isoformat() if db_analysis.completed_at else None
        status = db_analysis.status

    # Build log events - use json.dumps for proper serialization
    log_events = []

    # Analysis started event
    log_events.append(json.dumps({
        "event": "analysis_started",
        "session_id": session_id,
        "sample_sha256": sample_sha256,
        "platform": platform,
        "architecture": architecture,
        "timestamp": created_at,
    }))

    # If completed, add completion event
    if status == "completed":
        log_events.append(json.dumps({
            "event": "analysis_complete",
            "session_id": session_id,
            "sample_sha256": sample_sha256,
            "duration_seconds": 0.1,
            "techniques_detected": 0,
            "api_calls_count": 0,
            "timestamp": completed_at,
        }))

    # Return as JSONL (JSON Lines)
    content = "\n".join(log_events)
    return Response(
        content=content,
        media_type="application/x-jsonlines",
    )


@router.get("/analyses/{session_id}/api_calls")
async def get_api_calls(
    session_id: str,
    request: Request,
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=50, ge=1, le=100, description="Items per page"),
    api_name: str | None = Query(default=None, description="Filter by API name"),
    technique_id: str | None = Query(default=None, description="Filter by technique ID"),
):
    """Get paginated API calls for an analysis."""
    db: DatabaseStore = get_db(request)

    # Validate pagination
    if page < 1:
        raise HTTPException(status_code=400, detail="page must be >= 1")
    if per_page > 100:
        raise HTTPException(status_code=400, detail="per_page must be <= 100")

    # Get analysis
    analysis = db.get_analysis(session_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Build query
    with Session(db.engine) as session:
        from sqlalchemy import select, func
        from ..db.models import APICall

        stmt = select(APICall).where(APICall.analysis_id == analysis.id)

        # Apply filters
        if api_name:
            stmt = stmt.where(APICall.api_name.ilike(f"%{api_name}%"))
        if technique_id:
            stmt = stmt.where(APICall.technique_id == technique_id)

        # Get total count
        count_stmt = select(func.count()).select_from(APICall).where(APICall.analysis_id == analysis.id)
        if api_name:
            count_stmt = count_stmt.where(APICall.api_name.ilike(f"%{api_name}%"))
        if technique_id:
            count_stmt = count_stmt.where(APICall.technique_id == technique_id)
        total = session.scalar(count_stmt) or 0

        # Get paginated results
        offset = (page - 1) * per_page
        stmt = stmt.order_by(APICall.sequence_number.asc())
        stmt = stmt.offset(offset).limit(per_page)
        api_calls = list(session.scalars(stmt))

    # Calculate pagination
    pages = (total + per_page - 1) // per_page if per_page > 0 else 1

    return {
        "items": [
            {
                "sequence_number": call.sequence_number,
                "timestamp": call.timestamp.isoformat() if call.timestamp else None,
                "api_name": call.api_name,
                "syscall_name": call.syscall_name,
                "params_json": call.params_json,
                "return_value": call.return_value,
                "technique_id": call.technique_id,
                "confidence": call.confidence,
            }
            for call in api_calls
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


@router.get("/analyses/{session_id}/findings")
async def get_findings(
    session_id: str,
    request: Request,
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=20, ge=1, le=100, description="Items per page"),
):
    """Get paginated ATT&CK findings for an analysis."""
    db: DatabaseStore = get_db(request)

    # Validate pagination
    if page < 1:
        raise HTTPException(status_code=400, detail="page must be >= 1")
    if per_page > 100:
        raise HTTPException(status_code=400, detail="per_page must be <= 100")

    # Get analysis
    analysis = db.get_analysis(session_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Build query
    with Session(db.engine) as session:
        from sqlalchemy import select, func
        from ..db.models import Finding

        stmt = select(Finding).where(Finding.analysis_id == analysis.id)

        # Get total count
        count_stmt = select(func.count()).select_from(Finding).where(Finding.analysis_id == analysis.id)
        total = session.scalar(count_stmt) or 0

        # Get paginated results
        offset = (page - 1) * per_page
        stmt = stmt.order_by(Finding.confidence_score.desc(), Finding.technique_id.asc())
        stmt = stmt.offset(offset).limit(per_page)
        findings = list(session.scalars(stmt))

    # Calculate pagination
    pages = (total + per_page - 1) // per_page if per_page > 0 else 1

    return {
        "items": [
            {
                "technique_id": f.technique_id,
                "technique_name": f.technique_name,
                "tactic": f.tactic,
                "confidence": f.confidence,
                "confidence_score": f.confidence_score,
                "evidence_count": f.evidence_count,
                "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            }
            for f in findings
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


@router.delete("/reports/{session_id}")
async def delete_report(session_id: str, request: Request):
    """Delete an analysis and its data."""
    db: DatabaseStore = get_db(request)

    # Delete from database
    deleted = db.delete_analysis(session_id)

    # Remove from in-memory tracking if present
    if session_id in _tasks:
        del _tasks[session_id]

    if deleted:
        return {"status": "deleted", "session_id": session_id}
    else:
        raise HTTPException(status_code=404, detail="Analysis not found")
