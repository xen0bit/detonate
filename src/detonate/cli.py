"""CLI entry point using typer."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from typing_extensions import Annotated

from .config import get_settings
from .core.emulator import DetonateEmulator
from .core.session import APICallRecord, AnalysisResult, TechniqueMatch
from .db.init_db import init_database
from .db.store import DatabaseStore
from .output.json_log import setup_logging
from .output.report import generate_report
from .output.navigator import generate_navigator_layer
from .output.stix import generate_stix_bundle

app = typer.Typer(help="Detonate - Malware analysis platform with ATT&CK mapping", rich_markup_mode=None)


@app.command()
def analyze(
    sample_path: str = typer.Argument(..., help="Path to sample binary"),
    platform: str = typer.Option("auto", "--platform", "-p"),
    arch: str = typer.Option("auto", "--arch", "-a"),
    rootfs: Optional[str] = typer.Option(None, "--rootfs", "-r"),
    timeout: int = typer.Option(60, "--timeout", "-t"),
    output_format: str = typer.Option("all", "--format", "-f"),
    output_dir: str = typer.Option(".", "--output", "-o"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """
    Analyze a sample file.

    Supports Windows PE and Linux ELF binaries.
    """
    # Setup logging
    log_level = "DEBUG" if verbose else ("CRITICAL" if quiet else "INFO")
    setup_logging(log_level=log_level, log_format="text" if verbose else "json")

    settings = get_settings()

    # Validate sample exists
    sample = Path(sample_path)
    if not sample.exists():
        typer.echo(f"Error: Sample not found: {sample_path}", err=True)
        raise typer.Exit(1)

    # Create output directory
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Initialize database
    init_database(settings.database)
    db = DatabaseStore(settings.database)

    # Run analysis
    typer.echo(f"Analyzing: {sample_path}")
    typer.echo(f"Platform: {platform}, Architecture: {arch}")

    try:
        emulator = DetonateEmulator(
            sample_path=str(sample),
            rootfs_path=rootfs,
            platform=platform,
            arch=arch,
            timeout=timeout,
            settings=settings,
        )

        import asyncio

        result = asyncio.run(emulator.run())

        # Store in database
        analysis = db.create_analysis(
            session_id=result.session_id,
            sample_sha256=result.sample_sha256,
            sample_md5=result.sample_md5,
            sample_path=result.sample_path,
            sample_size=result.sample_size,
            file_type=result.file_type,
            platform=result.platform,
            architecture=result.architecture,
        )

        # Store findings
        for finding in result.findings:
            db.add_finding(
                analysis_id=analysis.id,
                technique_id=finding.technique_id,
                technique_name=finding.technique_name,
                tactic=finding.tactic,
                confidence=finding.confidence,
                confidence_score=finding.confidence_score,
                evidence_count=finding.evidence_count,
                first_seen=finding.first_seen or result.started_at,
                last_seen=finding.last_seen or result.completed_at,
            )

        # Update analysis status to completed
        db.update_analysis_status(
            analysis.session_id,
            result.status,
            completed_at=result.completed_at,
            duration_seconds=result.duration_seconds,
        )

        # Generate outputs
        formats = output_format.split(",") if output_format != "all" else ["all"]

        if "all" in formats or "report" in formats:
            report_path = out_dir / f"report_{result.sample_sha256[:8]}.md"
            report = generate_report(result)
            report_path.write_text(report)
            typer.echo(f"Report: {report_path}")

        if "all" in formats or "navigator" in formats:
            nav_path = out_dir / f"navigator_{result.sample_sha256[:8]}.json"
            nav_data = generate_navigator_layer(
                result.session_id,
                result.sample_sha256,
                result.findings,
                result.platform,
            )
            nav_path.write_text(json.dumps(nav_data, indent=2))
            typer.echo(f"Navigator: {nav_path}")

        if "all" in formats or "stix" in formats:
            stix_path = out_dir / f"stix_{result.sample_sha256[:8]}.json"
            stix_bundle = generate_stix_bundle(
                result.session_id,
                result.sample_sha256,
                result.sample_path,
                result.findings,
                result.api_calls,
            )
            import stix2.serialization
            stix_path.write_text(stix2.serialization.serialize(stix_bundle, pretty=True))
            typer.echo(f"STIX: {stix_path}")

        if "all" in formats or "json" in formats:
            json_path = out_dir / f"log_{result.sample_sha256[:8]}.jsonl"
            with json_path.open("w") as f:
                for call in result.api_calls:
                    f.write(json.dumps({
                        "timestamp": call.timestamp.isoformat(),
                        "api": call.api_name,
                        "syscall": call.syscall_name,
                        "params": call.params,
                        "technique_id": call.technique_id,
                    }) + "\n")
            typer.echo(f"JSON Log: {json_path}")

        typer.echo(f"\nAnalysis complete: {result.status}")
        typer.echo(f"Techniques detected: {len(result.findings)}")

    except FileNotFoundError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        raise typer.Exit(1)


@app.command()
def serve(
    host: Annotated[str, typer.Option("--host", "-h")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p")] = 8000,
    workers: Annotated[int, typer.Option("--workers", "-w")] = 1,
    database: Annotated[Optional[str], typer.Option("--database", "-d")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """
    Start the REST API server.
    """
    settings = get_settings()
    db_path = database or settings.database

    # Initialize database
    init_database(db_path)

    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    setup_logging(log_level=log_level, log_format="text")

    typer.echo(f"Starting Detonate API server...")
    typer.echo(f"Host: {host}, Port: {port}")
    typer.echo(f"Database: {db_path}")

    try:
        import uvicorn
        from .api.app import create_app

        app = create_app(db_path)

        uvicorn.run(
            app,
            host=host,
            port=port,
            workers=workers,
            log_level=log_level.lower(),
        )
    except ImportError:
        typer.echo("Error: FastAPI/uvicorn not installed", err=True)
        raise typer.Exit(1)


@app.command()
def list_analyses(
    status: Annotated[Optional[str], typer.Option("--status", "-s")] = None,
    platform: Annotated[Optional[str], typer.Option("--platform", "-p")] = None,
    limit: Annotated[int, typer.Option("--limit", "-l")] = 20,
    output_format: Annotated[str, typer.Option("--format", "-f")] = "table",
) -> None:
    """
    List past analyses from the database.
    """
    settings = get_settings()
    db = DatabaseStore(settings.database)

    list_result = db.list_analyses(status=status, platform=platform, limit=limit)
    analyses = list_result.items

    if output_format == "json":
        output = []
        for a in analyses:
            output.append({
                "session_id": a.session_id,
                "sample_sha256": a.sample_sha256,
                "platform": a.platform,
                "status": a.status,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            })
        typer.echo(json.dumps(output, indent=2))
    else:
        # Table format
        if not analyses:
            typer.echo("No analyses found.")
            return

        typer.echo(f"{'Session ID':<36} {'SHA256':<16} {'Platform':<10} {'Status':<12} {'Created'}")
        typer.echo("-" * 90)
        for a in analyses:
            created = a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else "N/A"
            typer.echo(f"{a.session_id:<36} {a.sample_sha256[:16]:<16} {a.platform:<10} {a.status:<12} {created}")


@app.command()
def show(
    session_id: str = typer.Argument(..., help="Session ID"),
    output_format: str = typer.Option("summary", "--format", "-f"),
) -> None:
    """
    Show details of a specific analysis.
    """
    settings = get_settings()
    db = DatabaseStore(settings.database)

    analysis = db.get_analysis(session_id)

    if not analysis:
        typer.echo(f"Error: Analysis not found: {session_id}", err=True)
        raise typer.Exit(1)

    if output_format == "json":
        output = {
            "session_id": analysis.session_id,
            "sample_sha256": analysis.sample_sha256,
            "platform": analysis.platform,
            "architecture": analysis.architecture,
            "status": analysis.status,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
            "completed_at": analysis.completed_at.isoformat() if analysis.completed_at else None,
        }
        typer.echo(json.dumps(output, indent=2))
    else:
        typer.echo(f"Session ID: {analysis.session_id}")
        typer.echo(f"SHA256: {analysis.sample_sha256}")
        typer.echo(f"Platform: {analysis.platform} ({analysis.architecture})")
        typer.echo(f"Status: {analysis.status}")
        typer.echo(f"Created: {analysis.created_at}")
        if analysis.error_message:
            typer.echo(f"Error: {analysis.error_message}")


# Database command group
db_app = typer.Typer(help="Database management commands")
app.add_typer(db_app, name="db", rich_help_panel="Commands")


@db_app.command("init")
def db_init(
    database: Annotated[Optional[str], typer.Option("--database", "-d")] = None,
) -> None:
    """
    Initialize the SQLite database.
    """
    settings = get_settings()
    db_path = database or settings.database

    init_database(db_path)
    typer.echo(f"Database initialized: {db_path}")


@db_app.command("migrate")
def db_migrate(
    database: Annotated[Optional[str], typer.Option("--database", "-d")] = None,
) -> None:
    """
    Run database migrations.
    
    For v0.1.0, this is a no-op as the schema is created fresh.
    Future versions will use alembic for schema migrations.
    """
    settings = get_settings()
    db_path = database or settings.database

    # Initialize database (creates tables if missing)
    init_database(db_path)
    
    typer.echo(f"Database migrations applied: {db_path}")
    typer.echo("Note: v0.1.0 uses fresh schema creation. Alembic migrations will be added in future versions.")


@app.command()
def export(
    session_id: str = typer.Argument(..., help="Session ID of analysis to export"),
    output_format: str = typer.Option("report", "-f", "--format", help="Output format: navigator, stix, report, log"),
    output_path: str = typer.Option("-", "-o", "--output", help="Output file path (use '-' for stdout)"),
) -> None:
    """
    Export analysis results to various formats.
    
    Supported formats: navigator, stix, report, log
    """
    settings = get_settings()
    db = DatabaseStore(settings.database)

    # Direct lookup with eager loading - O(1) instead of O(n) scan
    analysis = db.get_analysis_with_data(
        session_id,
        include_findings=True,
        include_api_calls=True,
        include_strings=True,
    )

    if analysis is None:
        typer.echo(f"Error: Analysis not found: {session_id}", err=True)
        raise typer.Exit(1)

    # Validate format
    valid_formats = {"navigator", "stix", "report", "log"}
    if output_format not in valid_formats:
        typer.echo(f"Error: Invalid format '{output_format}'. Must be one of: {valid_formats}", err=True)
        raise typer.Exit(1)

    try:
        if output_format == "navigator":
            from .output.navigator import generate_navigator_layer

            # Build findings from database records with None-safe access
            findings = []
            for f in analysis.findings:
                if not f.technique_id or not f.technique_name or not f.tactic:
                    typer.echo(f"Warning: Skipping finding with missing required fields", err=True)
                    continue

                # Convert naive datetimes from database to UTC-aware datetimes
                first_seen = f.first_seen
                if first_seen is not None and first_seen.tzinfo is None:
                    first_seen = first_seen.replace(tzinfo=timezone.utc)

                last_seen = f.last_seen
                if last_seen is not None and last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)

                findings.append(TechniqueMatch(
                    technique_id=f.technique_id,
                    technique_name=f.technique_name,
                    tactic=f.tactic,
                    confidence=f.confidence,
                    confidence_score=f.confidence_score,
                    evidence_count=f.evidence_count,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    evidence=[],  # Navigator doesn't need detailed evidence
                ))

            # Ensure analysis_date is timezone-aware (database returns naive datetime)
            analysis_date = analysis.created_at
            if analysis_date.tzinfo is None:
                analysis_date = analysis_date.replace(tzinfo=timezone.utc)

            content = generate_navigator_layer(
                session_id=analysis.session_id,
                sample_sha256=analysis.sample_sha256,
                findings=findings,
                platform=analysis.platform,
                analysis_date=analysis_date,
            )
            output_text = json.dumps(content, indent=2)
            content_type = "application/json"

        elif output_format == "stix":
            from .output.stix import generate_stix_bundle
            from .core.session import APICallRecord

            # Build findings with timezone-aware datetime conversion
            findings = []
            for f in analysis.findings:
                if not f.technique_id or not f.technique_name or not f.tactic:
                    continue

                # Convert naive datetimes from database to UTC-aware datetimes
                first_seen = f.first_seen
                if first_seen is not None and first_seen.tzinfo is None:
                    first_seen = first_seen.replace(tzinfo=timezone.utc)

                last_seen = f.last_seen
                if last_seen is not None and last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)

                findings.append(TechniqueMatch(
                    technique_id=f.technique_id,
                    technique_name=f.technique_name,
                    tactic=f.tactic,
                    confidence=f.confidence,
                    confidence_score=f.confidence_score,
                    evidence_count=f.evidence_count,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    evidence=[],
                ))

            # Build API call records with proper JSON handling and timezone conversion
            api_calls = []
            for c in analysis.api_calls:
                # Parse params_json if it's a string
                params = c.params_json
                if isinstance(params, str):
                    try:
                        params = json.loads(params)
                    except (json.JSONDecodeError, TypeError):
                        params = {}
                elif params is None:
                    params = {}

                # Convert naive timestamp to UTC-aware
                timestamp = c.timestamp
                if timestamp is not None and timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                api_calls.append(APICallRecord(
                    timestamp=timestamp,
                    api_name=c.api_name,
                    syscall_name=c.syscall_name,
                    address=c.address,
                    params=params,
                    return_value=c.return_value,
                    technique_id=c.technique_id,
                    confidence=c.confidence,
                ))

            # Convert analysis.created_at to UTC-aware if naive
            analysis_date = analysis.created_at
            if analysis_date.tzinfo is None:
                analysis_date = analysis_date.replace(tzinfo=timezone.utc)

            bundle = generate_stix_bundle(
                session_id=analysis.session_id,
                sample_sha256=analysis.sample_sha256,
                sample_path=analysis.sample_path,
                findings=findings,
                api_calls=api_calls,
                analysis_date=analysis_date,
            )
            # Use stix2's serialize method for proper JSON serialization
            import stix2.serialization
            output_text = stix2.serialization.serialize(bundle, pretty=True)
            content_type = "application/json"

        elif output_format == "report":
            from .output.report import generate_report
            from .core.session import AnalysisResult, APICallRecord

            # Build API call records with timezone conversion
            api_calls = []
            for c in analysis.api_calls:
                params = c.params_json
                if isinstance(params, str):
                    try:
                        params = json.loads(params)
                    except (json.JSONDecodeError, TypeError):
                        params = {}
                elif params is None:
                    params = {}

                # Convert naive timestamp to UTC-aware
                timestamp = c.timestamp
                if timestamp is not None and timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                api_calls.append(APICallRecord(
                    timestamp=timestamp,
                    api_name=c.api_name,
                    syscall_name=c.syscall_name,
                    address=c.address,
                    params=params,
                    return_value=c.return_value,
                    technique_id=c.technique_id,
                    confidence=c.confidence,
                ))

            # Build findings with timezone-aware datetime conversion
            findings = []
            for f in analysis.findings:
                if not f.technique_id or not f.technique_name or not f.tactic:
                    continue

                # Convert naive datetimes from database to UTC-aware datetimes
                first_seen = f.first_seen
                if first_seen is not None and first_seen.tzinfo is None:
                    first_seen = first_seen.replace(tzinfo=timezone.utc)

                last_seen = f.last_seen
                if last_seen is not None and last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)

                findings.append(TechniqueMatch(
                    technique_id=f.technique_id,
                    technique_name=f.technique_name,
                    tactic=f.tactic,
                    confidence=f.confidence,
                    confidence_score=f.confidence_score,
                    evidence_count=f.evidence_count,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    evidence=[],
                ))

            # Build strings list
            strings = [s.value for s in analysis.strings if s.value]

            # Convert analysis timestamps to UTC-aware if naive
            started_at = analysis.created_at
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=timezone.utc)

            completed_at = analysis.completed_at
            if completed_at is not None and completed_at.tzinfo is None:
                completed_at = completed_at.replace(tzinfo=timezone.utc)

            result = AnalysisResult(
                session_id=analysis.session_id,
                sample_sha256=analysis.sample_sha256,
                sample_md5=analysis.sample_md5,
                sample_path=analysis.sample_path,
                sample_size=analysis.sample_size,
                file_type=analysis.file_type,
                platform=analysis.platform,
                architecture=analysis.architecture,
                status=analysis.status,
                error_message=analysis.error_message,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=analysis.duration_seconds,
                findings=findings,
                api_calls=api_calls,
                strings=strings,
            )

            output_text = generate_report(result)
            content_type = "text/markdown"

        elif output_format == "log":
            # Build JSON lines log with timezone-aware timestamps
            lines = []
            for c in sorted(analysis.api_calls, key=lambda x: x.timestamp or datetime.min):
                # Parse params_json if it's a string
                params = c.params_json
                if isinstance(params, str):
                    try:
                        params = json.loads(params)
                    except (json.JSONDecodeError, TypeError):
                        params = {}
                elif params is None:
                    params = {}

                # Convert naive timestamp to UTC-aware before isoformat()
                timestamp = c.timestamp
                if timestamp is not None and timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                entry = {
                    "timestamp": timestamp.isoformat() if timestamp else None,
                    "api": c.api_name,
                    "syscall": c.syscall_name,
                    "params": params,
                    "technique_id": c.technique_id,
                    "confidence": c.confidence,
                }
                lines.append(json.dumps(entry))

            output_text = "\n".join(lines)
            content_type = "application/x-jsonlines"

        else:
            typer.echo(f"Error: Unsupported format: {output_format}", err=True)
            raise typer.Exit(1)

        # Write output
        if output_path == "-":
            typer.echo(output_text)
        else:
            out_file = Path(output_path)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(output_text)
            typer.echo(f"Exported {output_format} to: {output_path}")

    except Exception as e:
        typer.echo(f"Error exporting {output_format}: {e}", err=True)
        raise typer.Exit(1)


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
