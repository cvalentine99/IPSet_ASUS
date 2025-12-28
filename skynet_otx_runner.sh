#!/bin/sh
# Skynet OTX to Splunk ES Runner (BusyBox compatible)

SCRIPT_DIR="$(dirname "$0")"
PYTHON_SCRIPT="${SCRIPT_DIR}/skynet_otx_splunk.py"
CONFIG_FILE="${SCRIPT_DIR}/skynet_otx_config.json"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

if [ ! -f "${PYTHON_SCRIPT}" ]; then
    log "ERROR: Python script not found: ${PYTHON_SCRIPT}"
    exit 1
fi

if [ ! -f "${CONFIG_FILE}" ]; then
    log "ERROR: Config not found: ${CONFIG_FILE}"
    exit 1
fi

# Check Entware path first, then system
if [ -x /opt/bin/python3 ]; then
    PYTHON_CMD="/opt/bin/python3"
elif command -v python3 > /dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python > /dev/null 2>&1; then
    PYTHON_CMD="python"
else
    log "ERROR: Python not found. Install: opkg install python3"
    exit 1
fi

log "Starting Skynet OTX sync"
export SKYNET_OTX_CONFIG="${CONFIG_FILE}"

if ${PYTHON_CMD} "${PYTHON_SCRIPT}"; then
    log "Sync completed"
else
    log "ERROR: Sync failed"
    exit 1
fi
