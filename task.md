# Detonate Web UI Implementation Plan

## Overview

Build a simple, minimal Web UI for the Detonate malware analysis platform using:
- **Runtime:** Bun (for dev tasks, static file serving via FastAPI)
- **Styling:** PicoCSS v2 (vendored locally) with light/dark mode toggle
- **Interactivity:** Vanilla JavaScript only (no frameworks)
- **Deployment:** FastAPI serves static files from `/web` directory
- **Updates:** Polling every 5 seconds for running analyses
- **Charts:** Chart.js (vendored locally)
- **Markdown:** marked.js (vendored locally) for report preview

---

## Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Framework** | Vanilla JS + PicoCSS | Minimal, simple, easy to maintain |
| **Deployment** | FastAPI serves static files | Single container, no extra ports |
| **Authentication** | None | Internal tool, not needed yet |
| **Theme** | PicoCSS light/dark mode | Built-in, simple toggle |
| **Charts** | Chart.js (local) | Lightweight, simple API |
| **Markdown** | marked.js (local) | ~6KB, full MD support |
| **Client Hashes** | SHA256 only (Web Crypto) | Native, secure, MD5 not in Web Crypto |
| **API Pagination** | Server-side for API calls | Handle 1000+ calls efficiently |
| **Error Pages** | PicoCSS defaults | No custom error pages needed |
| **Primary Color** | `#d32f2f` (red) | Malware analysis theme |

---

## File Structure

```
detonate/
├── src/detonate/
│   ├── api/
│   │   ├── app.py              # MODIFY: add static files mount
│   │   ├── routes.py           # MODIFY: add pagination endpoints
│   │   └── web_routes.py       # NEW: HTML route handlers (optional)
│   └── db/
│       └── store.py            # MODIFY: add delete_analysis method
├── web/                         # NEW: Static web UI
│   ├── index.html              # Dashboard (entry point)
│   ├── submit.html             # Submit analysis form
│   ├── analyses.html           # List all analyses with filters
│   ├── analysis.html           # Detail view with tabs
│   ├── navigator.html          # Full ATT&CK matrix view
│   ├── css/
│   │   ├── pico.min.css        # Vendored PicoCSS (~25KB)
│   │   └── custom.css          # Custom styles (matrix, badges)
│   └── js/
│       ├── chart.min.js        # Vendored Chart.js (~60KB)
│       ├── marked.min.js       # Vendored marked.js (~6KB)
│       ├── app.js              # Main application logic
│       ├── dashboard.js        # Dashboard-specific code
│       ├── analysis.js         # Analysis detail + tabs + polling
│       ├── analyses.js         # List filtering + pagination
│       ├── submit.js           # Form handling + hash computation
│       └── navigator.js        # Matrix visualization
├── docker-compose.yml          # MODIFY: add web volume
├── Makefile                    # MODIFY: add web dev commands
└── task.md                     # THIS FILE
```

---

## Backend Changes (Phase 1)

### 1. Add Static Files Mount (`src/detonate/api/app.py`)

**Location:** After router setup in `create_app()`

```python
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Mount static files
app.mount("/web", StaticFiles(directory="web"), name="web")

# Root redirect
@app.get("/")
async def root_redirect():
    return FileResponse("web/index.html")
```

---

### 2. Implement Delete Endpoint (`src/detonate/api/routes.py`)

**Current:** No-op delete  
**Required:** Actual database deletion

**Step 1:** Add to `DatabaseStore` (`src/detonate/db/store.py`):

```python
def delete_analysis(self, session_id: str) -> bool:
    """
    Delete an analysis and all related data.
    
    Args:
        session_id: Analysis session UUID
    
    Returns:
        True if deleted, False if not found
    """
    with Session(self.engine) as session:
        stmt = select(Analysis).where(Analysis.session_id == session_id)
        analysis = session.scalar(stmt)
        
        if analysis is None:
            return False
        
        # Delete related records (cascade should handle this, but be explicit)
        for finding in analysis.findings:
            session.delete(finding)
        for api_call in analysis.api_calls:
            session.delete(api_call)
        for string in analysis.strings:
            session.delete(string)
        
        session.delete(analysis)
        session.commit()
        return True
```

**Step 2:** Update route handler:

```python
@router.delete("/reports/{session_id}")
async def delete_report(session_id: str, request: Request):
    """Delete an analysis and its data."""
    db: DatabaseStore = get_db(request)
    
    # Delete from database
    deleted = db.delete_analysis(session_id)
    
    # Remove from memory
    if session_id in _tasks:
        del _tasks[session_id]
    
    if deleted:
        return {"status": "deleted", "session_id": session_id}
    else:
        raise HTTPException(status_code=404, detail="Analysis not found")
```

---

### 3. Add Paginated API Calls Endpoint (`src/detonate/api/routes.py`)

```python
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
```

---

### 4. Add Paginated Findings Endpoint (`src/detonate/api/routes.py`)

```python
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
```

---

### 5. Update Docker Compose (`docker-compose.yml`)

Add web volume mount to the `volumes` section:

```yaml
volumes:
  - ./web:/app/web:ro              # NEW: Mount web UI (read-only)
  - ./dlls/x86:/opt/rootfs/x86_windows/dlls:ro
  - ./dlls/x86_64:/opt/rootfs/x8664_windows/dlls:ro
  - ./samples:/samples:ro
  - ./output:/output:rw
  - ./data/db:/var/lib/detonate:rw
```

---

### 6. Update Makefile

Add web development commands:

```makefile
# Web UI development
web-dev:
	@echo "Starting web development..."
	@echo "Open http://localhost:8000/web/ in your browser"

web-download-deps:
	@echo "Downloading web dependencies..."
	@mkdir -p web/js web/css
	@curl -L https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css -o web/css/pico.min.css
	@curl -L https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js -o web/js/chart.min.js
	@curl -L https://cdn.jsdelivr.net/npm/marked@12.0.0/marked.min.js -o web/js/marked.min.js
	@echo "Dependencies downloaded to web/js/ and web/css/"

web-lint:
	@echo "Web UI linting not configured (vanilla JS)"

web-build:
	@echo "Web UI build not required (static HTML)"

test-web:
	@echo "Web UI tests not configured"
```

---

## Web UI Pages (Phase 2)

### Page 1: Dashboard (`web/index.html`)

**Purpose:** System overview and quick access

**Components:**
- Header with navigation (Dashboard, Analyses, Submit, theme toggle)
- Statistics cards grid (4 cards)
- Recent analyses table (last 10)
- Activity chart (Chart.js, last 30 days)
- Quick action button

**JavaScript Functions:**
- `loadDashboardStats()` - Fetch and render statistics
- `loadRecentAnalyses()` - Populate recent table
- `renderActivityChart()` - Draw Chart.js graph
- `formatRelativeTime()` - Human-readable timestamps
- `toggleTheme()` - Light/dark mode switch

**API Calls:**
- `GET /api/v1/reports?per_page=10` - Recent analyses
- `GET /api/v1/reports?status=completed` - For statistics
- `GET /health` - System health check

---

### Page 2: Submit Analysis (`web/submit.html`)

**Purpose:** Upload and configure new analysis

**Components:**
- File upload zone (drag-and-drop + click)
- File info display (name, size, SHA256)
- Configuration form (platform, arch, timeout)
- Submit button with loading state
- Progress indicator
- Auto-redirect on success

**JavaScript Functions:**
- `handleFileSelect()` - Show file info after selection
- `computeFileHash()` - SHA256 via Web Crypto API
- `submitAnalysis()` - POST with progress tracking
- `handleSubmissionSuccess()` - Redirect to detail
- `handleSubmissionError()` - Show error message

**API Calls:**
- `POST /api/v1/analyze` - Multipart form submission

---

### Page 3: Analyses List (`web/analyses.html`)

**Purpose:** Browse, filter, and manage all analyses

**Components:**
- Filter form (status, platform, search)
- Results table (8 columns)
- Pagination controls
- Bulk actions (delete selected)

**JavaScript Functions:**
- `loadAnalyses()` - Fetch with current filters
- `applyFilters()` - Update URL params and reload
- `renderTable()` - Populate results
- `renderPagination()` - Build controls
- `deleteAnalysis()` - DELETE with confirmation
- `copyToClipboard()` - Copy hash

**API Calls:**
- `GET /api/v1/reports?page=X&per_page=Y&status=Z&platform=P`
- `DELETE /api/v1/reports/{sessionId}`

---

### Page 4: Analysis Detail (`web/analysis.html`)

**Purpose:** Comprehensive results viewer with tabs

**Layout:** Single page with 4 tabs

**Tab 1: Overview**
- Sample information (hashes, size, type, platform)
- Timeline (created, started, completed, duration)
- Status badge
- Executive summary (techniques count, tactics pie chart)

**Tab 2: ATT&CK Techniques**
- Techniques count summary
- Simple matrix grid (tactics as columns)
- Technique cards (ID, name, confidence, evidence)
- Click for details modal

**Tab 3: API Calls**
- Timeline table (sequence, timestamp, API, params, technique)
- Filter inputs (search API name, technique ID)
- Expandable JSON parameters
- Export buttons (JSON, CSV)

**Tab 4: Reports**
- Download buttons (4 formats)
- Markdown report preview (marked.js)
- Navigator layer mini-preview

**JavaScript Functions:**
- `loadAnalysisDetail()` - Fetch analysis data
- `switchTab()` - Tab navigation with URL hash
- `renderTechniquesMatrix()` - Build technique grid
- `renderAPICalls()` - Populate timeline
- `pollAnalysisStatus()` - Poll every 5s if pending/running
- `startPolling()` / `stopPolling()` - Manage poll loop
- `expandJson()` - Toggle JSON visibility
- `renderMarkdownPreview()` - Convert MD to HTML

**API Calls:**
- `GET /api/v1/analyze/{sessionId}` - Status + summary
- `GET /api/v1/analyses/{sessionId}/api_calls?page=1` - Paginated calls
- `GET /api/v1/analyses/{sessionId}/findings?page=1` - Paginated findings
- `GET /api/v1/reports/{sessionId}/navigator` - Download
- `GET /api/v1/reports/{sessionId}/report` - Download
- `GET /api/v1/reports/{sessionId}/log` - Download

**Polling Logic:**
```javascript
// Poll every 5 seconds if status is pending/running
// Stop on completed/failed or after 120 attempts (10 minutes)
// Reload page on completion to show results
```

---

### Page 5: ATT&CK Navigator (`web/navigator.html`)

**Purpose:** Full-screen interactive matrix

**Components:**
- Full ATT&CK matrix grid (all tactics, all techniques)
- Color-coded cells (red=high, orange=medium, yellow=low)
- Hover tooltips (technique name, confidence, evidence)
- Click modal (full details, all API evidence)
- Search/filter input
- Export button

**JavaScript Functions:**
- `loadNavigatorData()` - Fetch Navigator layer JSON
- `renderMatrix()` - Build full grid
- `showTechniqueModal()` - Display details popup
- `filterTechniques()` - Search/filter logic
- `exportLayer()` - Download JSON

**API Calls:**
- `GET /api/v1/reports/{sessionId}/navigator`

---

## CSS Specifications (`web/css/custom.css`)

```css
/* Theme variables */
:root {
  --primary: #d32f2f;
  --primary-hover: #b71c1c;
  --technique-high: rgba(255, 0, 0, 0.15);
  --technique-medium: rgba(255, 102, 0, 0.15);
  --technique-low: rgba(255, 170, 0, 0.15);
}

/* Navigation */
.navbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 2rem;
  border-bottom: 1px solid var(--muted-border-color);
}

/* Stats grid */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin: 2rem 0;
}

.stat-card {
  background: var(--card-background-color);
  padding: 1.5rem;
  border-radius: var(--border-radius);
  text-align: center;
}

.stat-card h3 {
  font-size: 0.875rem;
  color: var(--muted-color);
  margin-bottom: 0.5rem;
}

.stat-card p {
  font-size: 2rem;
  font-weight: bold;
  margin: 0;
}

/* Status badges */
.badge {
  display: inline-block;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: bold;
  text-transform: uppercase;
}

.badge.pending { background: #ffe082; color: #5d4037; }
.badge.running { background: #90caf9; color: #0d47a1; }
.badge.completed { background: #a5d6a7; color: #1b5e20; }
.badge.failed { background: #ef9a9a; color: #b71c1c; }

/* ATT&CK matrix */
.attack-matrix {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
  margin: 1rem 0;
  overflow-x: auto;
}

.tactic-column {
  background: var(--card-background-color);
  padding: 1rem;
  border-radius: var(--border-radius);
  min-width: 180px;
}

.tactic-column h4 {
  font-size: 0.875rem;
  text-transform: uppercase;
  color: var(--muted-color);
  margin-bottom: 0.75rem;
  border-bottom: 2px solid var(--primary);
  padding-bottom: 0.5rem;
}

.technique-item {
  display: block;
  padding: 0.5rem;
  margin: 0.25rem 0;
  border-radius: 4px;
  font-size: 0.8rem;
  cursor: pointer;
  transition: transform 0.1s;
}

.technique-item:hover {
  transform: translateX(4px);
}

.technique-item.high { background: var(--technique-high); }
.technique-item.medium { background: var(--technique-medium); }
.technique-item.low { background: var(--technique-low); }

/* Tabs */
.tabs {
  display: flex;
  gap: 0.5rem;
  border-bottom: 2px solid var(--muted-border-color);
  margin-bottom: 1.5rem;
}

.tab-button {
  padding: 0.75rem 1.5rem;
  background: transparent;
  border: none;
  border-bottom: 3px solid transparent;
  cursor: pointer;
  font-weight: 500;
  color: var(--muted-color);
  transition: all 0.2s;
}

.tab-button:hover {
  color: var(--primary);
}

.tab-button.active {
  color: var(--primary);
  border-bottom-color: var(--primary);
}

.tab-content {
  display: none;
}

.tab-content.active {
  display: block;
}

/* JSON viewer */
.json-viewer {
  background: var(--card-background-color);
  padding: 1rem;
  border-radius: var(--border-radius);
  font-family: monospace;
  font-size: 0.8rem;
  overflow-x: auto;
  white-space: pre-wrap;
}

/* Modal */
.modal {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.5);
  z-index: 1000;
  justify-content: center;
  align-items: center;
}

.modal.active {
  display: flex;
}

.modal-content {
  background: var(--card-background-color);
  padding: 2rem;
  border-radius: var(--border-radius);
  max-width: 600px;
  max-height: 80vh;
  overflow-y: auto;
}

/* Utility */
.copy-btn {
  padding: 0.25rem 0.5rem;
  font-size: 0.75rem;
  margin-left: 0.5rem;
}

.truncate {
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Dark mode adjustments */
[data-theme="dark"] .technique-item.high { background: rgba(255, 0, 0, 0.25); }
[data-theme="dark"] .technique-item.medium { background: rgba(255, 102, 0, 0.25); }
[data-theme="dark"] .technique-item.low { background: rgba(255, 170, 0, 0.25); }
```

---

## Implementation Phases

### Phase 1: Backend Changes (Days 1-2)

- [ ] **1.1** Add static files mount to `src/detonate/api/app.py`
- [ ] **1.2** Add `delete_analysis()` method to `src/detonate/db/store.py`
- [ ] **1.3** Update `DELETE /api/v1/reports/{sessionId}` route
- [ ] **1.4** Add `GET /api/v1/analyses/{sessionId}/api_calls` endpoint
- [ ] **1.5** Add `GET /api/v1/analyses/{sessionId}/findings` endpoint
- [ ] **1.6** Update `docker-compose.yml` with web volume
- [ ] **1.7** Update `Makefile` with web commands
- [ ] **1.8** Test all new endpoints with curl/Postman

---

### Phase 2: Setup & Foundation (Day 3)

- [ ] **2.1** Create `/web` directory structure
- [ ] **2.2** Download dependencies:
  - [ ] PicoCSS (`web/css/pico.min.css`)
  - [ ] Chart.js (`web/js/chart.min.js`)
  - [ ] marked.js (`web/js/marked.min.js`)
- [ ] **2.3** Create base HTML template (shared header/nav/footer)
- [ ] **2.4** Implement theme toggle (light/dark, localStorage)
- [ ] **2.5** Create `web/css/custom.css` with all custom styles
- [ ] **2.6** Create `web/js/app.js` with shared utilities:
  - `formatRelativeTime()`
  - `formatAbsoluteTime()`
  - `copyToClipboard()`
  - `toggleTheme()`
  - `getTheme()`
- [ ] **2.7** Test static file serving via FastAPI

---

### Phase 3: Dashboard (Day 4)

- [ ] **3.1** Build `web/index.html` structure
- [ ] **3.2** Create navigation header
- [ ] **3.3** Build statistics cards grid
- [ ] **3.4** Build recent analyses table
- [ ] **3.5** Create `web/js/dashboard.js`:
  - `loadDashboardStats()`
  - `loadRecentAnalyses()`
  - `renderActivityChart()`
- [ ] **3.6** Integrate Chart.js for activity graph
- [ ] **3.7** Test with live API data
- [ ] **3.8** Test theme toggle persistence

---

### Phase 4: Submit Analysis (Day 5)

- [ ] **4.1** Build `web/submit.html` form structure
- [ ] **4.2** Implement drag-and-drop file upload zone
- [ ] **4.3** Add file info display (name, size)
- [ ] **4.4** Create `web/js/submit.js`:
  - `handleFileSelect()`
  - `computeFileHash()` (Web Crypto SHA256)
  - `submitAnalysis()`
  - `handleSubmissionSuccess()`
  - `handleSubmissionError()`
- [ ] **4.5** Implement upload progress indicator
- [ ] **4.6** Add form validation (required fields)
- [ ] **4.7** Test file submission end-to-end
- [ ] **4.8** Test redirect to analysis detail

---

### Phase 5: Analyses List (Day 6)

- [ ] **5.1** Build `web/analyses.html` table structure
- [ ] **5.2** Create filter form (status, platform, search)
- [ ] **5.3** Build results table with all columns
- [ ] **5.4** Create `web/js/analyses.js`:
  - `loadAnalyses()`
  - `applyFilters()`
  - `renderTable()`
  - `renderPagination()`
  - `deleteAnalysis()`
  - `parseQueryParams()`
- [ ] **5.5** Implement pagination controls
- [ ] **5.6** Add delete with confirmation dialog
- [ ] **5.7** Add copy-to-clipboard for hashes
- [ ] **5.8** Test filtering with 100+ analyses

---

### Phase 6: Analysis Detail (Days 7-9)

- [ ] **6.1** Build `web/analysis.html` with tab structure
- [ ] **6.2** Implement tab switching with URL hash
- [ ] **6.3** Create `web/js/analysis.js`:
  - `loadAnalysisDetail()`
  - `switchTab()`
  - `renderTechniquesMatrix()`
  - `renderAPICalls()`
  - `pollAnalysisStatus()`
  - `startPolling()` / `stopPolling()`
  - `expandJson()`
  - `renderMarkdownPreview()`

**Tab 1: Overview**
- [ ] **6.4** Sample information card
- [ ] **6.5** Timeline display
- [ ] **6.6** Status badge with color
- [ ] **6.7** Executive summary with tactics pie chart

**Tab 2: ATT&CK Techniques**
- [ ] **6.8** Techniques count summary
- [ ] **6.9** Matrix grid layout
- [ ] **6.10** Technique cards with confidence badges
- [ ] **6.11** Click modal with details
- [ ] **6.12** Link to MITRE ATT&CK website

**Tab 3: API Calls**
- [ ] **6.13** Timeline table structure
- [ ] **6.14** Filter inputs (API name, technique ID)
- [ ] **6.15** Expandable JSON parameters
- [ ] **6.16** Pagination (Load More button)
- [ ] **6.17** Export buttons (JSON, CSV)

**Tab 4: Reports**
- [ ] **6.18** Download buttons (4 formats)
- [ ] **6.19** Markdown report preview (marked.js)
- [ ] **6.20** Navigator layer mini-preview

**Polling**
- [ ] **6.21** Implement 5-second polling for pending/running
- [ ] **6.22** Auto-stop on completion/failure
- [ ] **6.23** Auto-reload on completion
- [ ] **6.24** Max attempts timeout (120 attempts = 10 minutes)
- [ ] **6.25** Error handling for failed polls

- [ ] **6.26** Test with completed analyses
- [ ] **6.27** Test with pending/running analyses
- [ ] **6.28** Test with failed analyses

---

### Phase 7: ATT&CK Navigator (Day 10)

- [ ] **7.1** Build `web/navigator.html` full matrix structure
- [ ] **7.2** Create `web/js/navigator.js`:
  - `loadNavigatorData()`
  - `renderMatrix()`
  - `showTechniqueModal()`
  - `filterTechniques()`
  - `exportLayer()`
- [ ] **7.3** Implement full ATT&CK grid (all tactics)
- [ ] **7.4** Add color-coding by confidence
- [ ] **7.5** Implement hover tooltips
- [ ] **7.6** Build click modal with full details
- [ ] **7.7** Add search/filter functionality
- [ ] **7.8** Add export button
- [ ] **7.9** Test with complex analyses (20+ techniques)

---

### Phase 8: Polish & Testing (Day 11)

- [ ] **8.1** Add error handling throughout all pages
- [ ] **8.2** Add loading states/skeletons
- [ ] **8.3** Improve responsive design (mobile/tablet)
- [ ] **8.4** Add keyboard navigation (Tab, Enter, Escape)
- [ ] **8.5** Test cross-browser (Chrome, Firefox, Safari, Edge)
- [ ] **8.6** Performance optimization:
  - [ ] Minimize DOM manipulation
  - [ ] Debounce search inputs
  - [ ] Lazy load API calls
- [ ] **8.7** Test with edge cases:
  - [ ] Empty analyses list
  - [ ] 1000+ API calls
  - [ ] Very long strings
  - [ ] Special characters in filenames
- [ ] **8.8** Update README.md with web UI documentation

---

## Testing Strategy

### Backend Testing

```bash
# Test static file serving
curl http://localhost:8000/web/index.html

# Test new endpoints
curl http://localhost:8000/api/v1/analyses/{sessionId}/api_calls?page=1
curl http://localhost:8000/api/v1/analyses/{sessionId}/findings?page=1
curl -X DELETE http://localhost:8000/api/v1/reports/{sessionId}
```

### Frontend Testing

Manual testing checklist for each page:

**Dashboard:**
- [ ] Statistics cards display correct counts
- [ ] Recent analyses table shows 10 items
- [ ] Activity chart renders correctly
- [ ] Theme toggle works and persists
- [ ] Navigation links work

**Submit:**
- [ ] File drag-and-drop works
- [ ] File info displays after selection
- [ ] SHA256 hash computes correctly
- [ ] Form submission works
- [ ] Progress indicator shows
- [ ] Redirect to detail on success
- [ ] Error message on failure

**Analyses List:**
- [ ] Table displays all columns
- [ ] Filters work (status, platform, search)
- [ ] Pagination works
- [ ] Delete with confirmation works
- [ ] Copy-to-clipboard works

**Analysis Detail:**
- [ ] All tabs switch correctly
- [ ] Overview tab shows all info
- [ ] Techniques matrix renders
- [ ] API calls table paginates
- [ ] JSON expand/collapse works
- [ ] Markdown preview renders
- [ ] Download buttons work
- [ ] Polling works for pending analyses

**Navigator:**
- [ ] Full matrix renders
- [ ] Hover tooltips work
- [ ] Click modal shows details
- [ ] Search/filter works
- [ ] Export works

---

## Dependencies Download Script

```bash
#!/bin/bash
# Run from project root to download all dependencies

set -e

echo "Creating web directory structure..."
mkdir -p web/js web/css

echo "Downloading PicoCSS..."
curl -L https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css \
  -o web/css/pico.min.css

echo "Downloading Chart.js..."
curl -L https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js \
  -o web/js/chart.min.js

echo "Downloading marked.js..."
curl -L https://cdn.jsdelivr.net/npm/marked@12.0.0/marked.min.js \
  -o web/js/marked.min.js

echo "Setting permissions..."
chmod -R 755 web/

echo "Done! Dependencies downloaded to web/js/ and web/css/"
echo "Total size:"
du -sh web/
```

---

## API Reference

### Existing Endpoints (Used by Web UI)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/reports` | GET | List analyses with pagination |
| `/api/v1/reports/{sessionId}` | DELETE | Delete analysis |
| `/api/v1/analyze/{sessionId}` | GET | Get analysis status |
| `/api/v1/reports/{sessionId}/navigator` | GET | Download Navigator layer |
| `/api/v1/reports/{sessionId}/stix` | GET | Download STIX bundle |
| `/api/v1/reports/{sessionId}/report` | GET | Download Markdown report |
| `/api/v1/reports/{sessionId}/log` | GET | Download JSON log |
| `/health` | GET | Health check |

### New Endpoints (To Be Implemented)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/analyses/{sessionId}/api_calls` | GET | Paginated API calls |
| `/api/v1/analyses/{sessionId}/findings` | GET | Paginated findings |
| `/` | GET | Redirect to `/web/index.html` |

---

## Success Criteria

### Functional Requirements

- [x] Users can submit samples for analysis via web form
- [x] Users can view dashboard with system statistics
- [x] Users can browse and filter all analyses
- [x] Users can view detailed analysis results with tabs
- [x] Users can see ATT&CK techniques in matrix format
- [x] Users can download all report formats
- [x] Users can toggle light/dark theme
- [x] Running analyses poll for status updates

### Non-Functional Requirements

- [x] All static assets served locally (no CDN)
- [x] No JavaScript frameworks (vanilla only)
- [x] Single container deployment (FastAPI serves static)
- [x] No authentication required
- [x] Responsive design works on mobile/tablet
- [x] Page load time < 2 seconds
- [x] Polling interval: 5 seconds
- [x] All pages work in Chrome, Firefox, Safari, Edge

---

## Notes

- **MD5 Hash:** Not computed client-side (Web Crypto doesn't support). Server computes both MD5 and SHA256.
- **Error Pages:** Using PicoCSS defaults, no custom 404/500 pages.
- **Real-time Updates:** Polling only, no WebSocket/SSE.
- **Markdown Preview:** Uses marked.js (~6KB) for full Markdown support.
- **Primary Color:** `#d32f2f` (red) for malware analysis theme.

---

## Quick Start Commands

```bash
# Download dependencies
make web-download-deps

# Start development server
docker-compose up -d

# Open in browser
open http://localhost:8000/

# Test endpoints
curl http://localhost:8000/api/v1/reports
curl http://localhost:8000/web/index.html
```

---

**Last Updated:** 2026-04-22  
**Status:** Ready for implementation
