# Skynet OTX to Splunk ES Integration

Pulls threat intelligence from AlienVault OTX and sends it to Splunk Enterprise Security.

## Files

| File | Purpose |
|------|---------|
| `skynet_otx_splunk.py` | Fetches OTX indicators, formats for ES, sends via HEC |
| `skynet_otx_runner.sh` | BusyBox-compatible shell wrapper |
| `skynet_otx_config.json` | API keys and settings |

## Requirements

- ASUS router with Entware
- Python 3: `opkg install python3`
- Splunk ES with HEC enabled
- AlienVault OTX account with API key

## Configuration

Edit `skynet_otx_config.json`:

```json
{
    "otx_api_key": "YOUR_OTX_API_KEY",
    "splunk_hec_url": "https://SPLUNK_IP:8088/services/collector/event",
    "splunk_hec_token": "YOUR_HEC_TOKEN",
    "splunk_index": "threat_activity",
    "splunk_sourcetype": "stash",
    "splunk_source": "OTX:AlienVault",
    "pulse_days": 30,
    "batch_size": 500,
    "verify_ssl": false
}
```

## Installation

```bash
# Copy files to router
cd /jffs/scripts
curl -O https://raw.githubusercontent.com/cvalentine99/IPSet_ASUS/main/skynet_otx_splunk.py
curl -O https://raw.githubusercontent.com/cvalentine99/IPSet_ASUS/main/skynet_otx_runner.sh
curl -O https://raw.githubusercontent.com/cvalentine99/IPSet_ASUS/main/skynet_otx_config.json

chmod +x skynet_otx_*.sh skynet_otx_*.py

# Edit config with your credentials
vi skynet_otx_config.json
```

## Usage

### Manual Run
```bash
/jffs/scripts/skynet_otx_runner.sh
```

### Schedule (cron)
```bash
# Every 4 hours
cru a SkynetOTX "0 */4 * * * /jffs/scripts/skynet_otx_runner.sh"

# Verify
cru l
```

### Persist Across Reboots
Add to `/jffs/scripts/services-start`:
```bash
cru a SkynetOTX "0 */4 * * * /jffs/scripts/skynet_otx_runner.sh"
```

## Splunk ES Fields

Events include these ES-required fields:

| Field | Description |
|-------|-------------|
| `indicator` | IOC value (IP, domain, hash, URL) |
| `indicator_type` | Normalized type: `ip`, `domain`, `file_hash`, `url`, `email` |
| `threat_key` | Unique ID for deduplication |
| `confidence` | Score 0-100 |
| `weight` | Threat weight for scoring |
| `description` | Pulse name |
| `threat_collection_name` | Collection identifier |
| `source` | Provider name |
| `src` / `dest` | For IP correlation |
| `domain` | For domain correlation |
| `file_hash` | For file hash correlation |

## Verify in Splunk

```spl
index=threat_activity source="OTX:AlienVault" | head 10
```

```spl
index=threat_activity | stats count by indicator_type
```

```spl
| tstats count from datamodel=Threat_Intelligence by _time, indicator_type
```

## Troubleshooting

### No pulses fetched
- Check OTX API key is valid
- Verify you have subscribed pulses in OTX
- Check `pulse_days` setting

### HEC errors
- Verify Splunk HEC is enabled
- Check token is valid
- Confirm `threat_activity` index exists

### SSL errors
- Set `verify_ssl: false` in config
- Install CA certs: `opkg install ca-certificates`

### Python not found
```bash
opkg update && opkg install python3
```

Note: Entware installs to `/opt/bin/python3`. The runner script checks this path.
