#!/bin/bash
set -e

# =============================================================================
# Detonate Container Entrypoint
# =============================================================================
# Handles graceful shutdown, database initialization, and command execution.
# Designed for security research use - explicit failure modes, no magic.
# =============================================================================

# Configuration from environment
DATABASE_PATH="${DETONATE_DATABASE:-/var/lib/detonate/detonate.db}"
ROOTFS_PATH="${DETONATE_ROOTFS:-/app/data/rootfs}"
LOG_LEVEL="${DETONATE_LOG_LEVEL:-info}"

# PID of the main process for signal forwarding
MAIN_PID=

# -----------------------------------------------------------------------------
# Logging functions
# -----------------------------------------------------------------------------
log_info() {
    echo "[INFO] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*"
}

log_error() {
    echo "[ERROR] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >&2
}

log_debug() {
    if [[ "${LOG_LEVEL}" == "debug" || "${LOG_LEVEL}" == "verbose" ]]; then
        echo "[DEBUG] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*"
    fi
}

# -----------------------------------------------------------------------------
# Signal handlers for graceful shutdown
# -----------------------------------------------------------------------------
cleanup() {
    local signal="$1"
    log_info "Received ${signal}, initiating graceful shutdown..."
    
    if [[ -n "${MAIN_PID}" ]] && kill -0 "${MAIN_PID}" 2>/dev/null; then
        log_info "Forwarding ${signal} to child process (PID: ${MAIN_PID})"
        kill -"${signal}" "${MAIN_PID}" 2>/dev/null || true
        
        # Wait for graceful termination (max 30 seconds)
        local timeout=30
        local elapsed=0
        while kill -0 "${MAIN_PID}" 2>/dev/null && [[ ${elapsed} -lt ${timeout} ]]; do
            sleep 1
            elapsed=$((elapsed + 1))
            log_debug "Waiting for process to terminate... ${elapsed}s"
        done
        
        # Force kill if still running
        if kill -0 "${MAIN_PID}" 2>/dev/null; then
            log_error "Process did not terminate gracefully, sending SIGKILL"
            kill -9 "${MAIN_PID}" 2>/dev/null || true
        fi
    fi
    
    log_info "Shutdown complete"
    exit 0
}

handle_sigterm() {
    cleanup "TERM"
}

handle_sigint() {
    cleanup "INT"
}

# Set up signal traps
trap handle_sigterm SIGTERM
trap handle_sigint SIGINT
# Also handle SIGHUP for completeness (e.g., terminal hangup)
trap 'log_info "Received SIGHUP, ignoring"; true' SIGHUP

# -----------------------------------------------------------------------------
# Database initialization
# -----------------------------------------------------------------------------
init_database() {
    log_info "Initializing database at ${DATABASE_PATH}"
    
    # Validate database directory exists and is writable
    local db_dir
    db_dir=$(dirname "${DATABASE_PATH}")
    
    if [[ ! -d "${db_dir}" ]]; then
        log_info "Creating database directory: ${db_dir}"
        mkdir -p "${db_dir}" || {
            log_error "Failed to create database directory: ${db_dir}"
            exit 1
        }
    fi
    
    # Check write permissions
    if [[ ! -w "${db_dir}" ]]; then
        log_error "Database directory is not writable: ${db_dir}"
        exit 1
    fi
    
    # Run database initialization if database doesn't exist
    # The detonate db init command uses DETONATE_DATABASE env var, not command line args
    if [[ ! -f "${DATABASE_PATH}" ]]; then
        log_info "Database does not exist, running initialization"
        export DETONATE_DATABASE="${DATABASE_PATH}"
        detonate db init || {
            log_error "Database initialization failed"
            exit 1
        }
        log_info "Database initialized successfully"
    else
        log_debug "Database already exists, skipping initialization"
    fi
}

# -----------------------------------------------------------------------------
# Validate rootfs path
# -----------------------------------------------------------------------------
validate_rootfs() {
    log_debug "Validating rootfs path: ${ROOTFS_PATH}"
    
    if [[ ! -d "${ROOTFS_PATH}" ]]; then
        log_error "Rootfs directory does not exist: ${ROOTFS_PATH}"
        log_error "Set DETONATE_ROOTFS environment variable to a valid path"
        exit 1
    fi
    
    # Check for at least one valid rootfs subdirectory
    if [[ ! -d "${ROOTFS_PATH}/x86_linux" && ! -d "${ROOTFS_PATH}/x8664_linux" ]]; then
        log_error "Rootfs missing required subdirectories (x86_linux or x8664_linux)"
        exit 1
    fi
    
    log_debug "Rootfs validation passed"
}

# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------
main() {
    log_info "Detonate container starting up"
    log_info "Database: ${DATABASE_PATH}"
    log_info "Rootfs: ${ROOTFS_PATH}"
    log_info "Log level: ${LOG_LEVEL}"
    
    # Validate environment
    validate_rootfs
    
    # Initialize database
    init_database
    
    # Determine command to run
    # If first arg is "detonate", strip it (for compatibility with CLI usage)
    if [[ "${1}" == "detonate" ]]; then
        shift
    fi
    
    local cmd="${1:-serve}"
    shift || true
    
    log_info "Executing command: ${cmd} $*"
    
    # Build command arguments based on command type
    local args=()
    
    case "${cmd}" in
        serve)
            # API server mode - pass database explicitly
            args+=("serve")
            args+=("--database" "${DATABASE_PATH}")
            args+=("--host" "0.0.0.0")
            args+=("--port" "8000")
            
            # Add any additional arguments from entrypoint
            while [[ $# -gt 0 ]]; do
                args+=("$1")
                shift
            done
            ;;
        
        analyze|list-analyses|show|export)
            # CLI commands - use DETONATE_DATABASE env var (commands read from settings)
            export DETONATE_DATABASE="${DATABASE_PATH}"
            args+=("${cmd}")
            
            # Add any additional arguments from entrypoint
            while [[ $# -gt 0 ]]; do
                args+=("$1")
                shift
            done
            ;;
        
        db)
            # Database commands - use DETONATE_DATABASE env var
            export DETONATE_DATABASE="${DATABASE_PATH}"
            args+=("db")
            
            # Add any additional arguments from entrypoint
            while [[ $# -gt 0 ]]; do
                args+=("$1")
                shift
            done
            ;;
        
        *)
            # Unknown command - pass through as-is
            args+=("${cmd}")
            while [[ $# -gt 0 ]]; do
                args+=("$1")
                shift
            done
            ;;
    esac
    
    # Execute the command and capture PID
    log_debug "Running: detonate ${args[*]}"
    detonate "${args[@]}" &
    MAIN_PID=$!
    
    # Wait for the main process
    log_info "Detonate running (PID: ${MAIN_PID})"
    wait "${MAIN_PID}"
    local exit_code=$?
    
    log_info "Detonate exited with code ${exit_code}"
    exit ${exit_code}
}

# Run main function with all arguments
main "$@"
