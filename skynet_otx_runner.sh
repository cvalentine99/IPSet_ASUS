#!/bin/bash
#
# Skynet OTX to Splunk ES Runner
#
# This script runs the OTX threat intelligence sync to Splunk ES.
# Designed to be run via cron for automated threat intel updates.
#
# Usage:
#   ./skynet_otx_runner.sh [--config /path/to/config.json]
#
# Cron example (every 4 hours):
#   0 */4 * * * /path/to/skynet_otx_runner.sh >> /var/log/skynet_otx.log 2>&1
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="${SCRIPT_DIR}/skynet_otx_splunk.py"
DEFAULT_CONFIG="${SCRIPT_DIR}/skynet_otx_config.json"

# Logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2
}

# Parse arguments
CONFIG_FILE="${DEFAULT_CONFIG}"
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--config /path/to/config.json]"
            echo ""
            echo "Environment variables:"
            echo "  SKYNET_OTX_CONFIG - Path to configuration file"
            echo "  OTX_API_KEY       - Override OTX API key from config"
            echo "  SPLUNK_HEC_TOKEN  - Override Splunk HEC token from config"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate requirements
if [[ ! -f "${PYTHON_SCRIPT}" ]]; then
    log_error "Python script not found: ${PYTHON_SCRIPT}"
    exit 1
fi

if [[ ! -f "${CONFIG_FILE}" ]]; then
    log_error "Configuration file not found: ${CONFIG_FILE}"
    exit 1
fi

# Check Python 3 availability
PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    # Verify it's Python 3
    if python --version 2>&1 | grep -q "Python 3"; then
        PYTHON_CMD="python"
    fi
fi

if [[ -z "${PYTHON_CMD}" ]]; then
    log_error "Python 3 not found"
    exit 1
fi

log "Starting Skynet OTX to Splunk ES sync"
log "Configuration: ${CONFIG_FILE}"
log "Python: ${PYTHON_CMD}"

# Export configuration path
export SKYNET_OTX_CONFIG="${CONFIG_FILE}"

# Run the sync
if ${PYTHON_CMD} "${PYTHON_SCRIPT}"; then
    log "Skynet OTX sync completed successfully"
    exit 0
else
    log_error "Skynet OTX sync failed"
    exit 1
fi
