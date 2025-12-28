#!/usr/bin/env python3
"""
Skynet OTX to Splunk ES Threat Intelligence Integration

Fetches threat intel from AlienVault OTX and sends to Splunk ES threat_activity index.
Compliant with DA-ESS-ThreatIntelligence data model.
"""
import json, logging, hashlib, time, sys, os, ssl
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

OTX_TYPE_MAP = {
    "IPv4": "ip", "IPv6": "ip", "CIDR": "ip",
    "domain": "domain", "hostname": "domain",
    "URL": "url", "URI": "url",
    "FileHash-MD5": "file_hash", "FileHash-SHA1": "file_hash", "FileHash-SHA256": "file_hash",
    "email": "email"
}

def otx_fetch(api_key, days=30):
    """Fetch subscribed pulses from OTX."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    modified_since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={modified_since}&limit=50"
    pulses = []

    while url:
        req = Request(url, headers={"X-OTX-API-KEY": api_key})
        try:
            with urlopen(req, context=ctx, timeout=60) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                pulses.extend(data.get("results", []))
                url = data.get("next")
        except Exception as e:
            logger.error(f"OTX fetch error: {e}")
            break
    return pulses

def format_events(pulses, config):
    """Format OTX indicators into ES-compliant events."""
    events = []
    for pulse in pulses:
        for ind in pulse.get("indicators", []):
            ind_type = OTX_TYPE_MAP.get(ind.get("type"), "")
            if not ind_type:
                continue

            indicator = ind.get("indicator", "")
            threat_key = hashlib.sha256(f"{indicator}|{ind_type}|{pulse.get('id')}".encode()).hexdigest()[:32]

            event = {
                # ES Required Fields
                "indicator": indicator,
                "indicator_type": ind_type,
                "threat_key": threat_key,
                # ES Recommended Fields
                "confidence": 70,
                "weight": 2 if ind_type in ["ip", "domain", "file_hash"] else 1,
                "description": pulse.get("name", ""),
                "threat_collection_name": config.get("threat_collection_name", "otx_alienvault"),
                "source": config.get("splunk_source", "OTX:AlienVault"),
                # CIM Fields
                "threat_category": ",".join(pulse.get("tags", [])[:5]),
                "threat_group": pulse.get("adversary", ""),
                # Provenance
                "pulse_id": pulse.get("id", ""),
                "pulse_name": pulse.get("name", ""),
                "pulse_author": pulse.get("author_name", ""),
            }

            # Add type-specific correlation fields
            if ind_type == "ip":
                event["src"] = event["dest"] = indicator
            elif ind_type == "domain":
                event["domain"] = indicator
            elif ind_type == "file_hash":
                event["file_hash"] = indicator
                h = len(indicator)
                if h == 32: event["file_hash_md5"] = indicator
                elif h == 40: event["file_hash_sha1"] = indicator
                elif h == 64: event["file_hash_sha256"] = indicator
            elif ind_type == "url":
                event["url"] = indicator

            events.append(event)
    return events

def send_to_splunk(events, config):
    """Send events to Splunk via HEC."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    hec_url = config.get("splunk_hec_url", "")
    token = config.get("splunk_hec_token", "")
    if not hec_url or not token:
        logger.error("HEC not configured")
        return 0

    batch_size = config.get("batch_size", 500)
    sent = 0

    for i in range(0, len(events), batch_size):
        batch = events[i:i+batch_size]
        payload = "\n".join(json.dumps({
            "time": time.time(),
            "host": "skynet_otx",
            "index": config.get("splunk_index", "threat_activity"),
            "sourcetype": config.get("splunk_sourcetype", "stash"),
            "source": config.get("splunk_source", "OTX:AlienVault"),
            "event": e
        }) for e in batch).encode('utf-8')

        req = Request(hec_url, data=payload, headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json"
        }, method="POST")

        try:
            with urlopen(req, context=ctx, timeout=60) as resp:
                result = json.loads(resp.read().decode('utf-8'))
                if result.get("code") == 0:
                    sent += len(batch)
                    logger.info(f"Sent batch: {len(batch)} events")
                else:
                    logger.error(f"HEC error: {result}")
        except HTTPError as e:
            logger.error(f"HEC HTTP error: {e.code} - {e.read().decode()}")
        except Exception as e:
            logger.error(f"HEC error: {e}")
    return sent

def main():
    config_path = os.environ.get("SKYNET_OTX_CONFIG",
                                  os.path.join(os.path.dirname(__file__), "skynet_otx_config.json"))
    try:
        with open(config_path) as f:
            config = json.load(f)
    except FileNotFoundError:
        logger.error(f"Config not found: {config_path}")
        sys.exit(1)

    if not config.get("otx_api_key"):
        logger.error("OTX API key not configured")
        sys.exit(1)

    logger.info("Fetching from OTX...")
    pulses = otx_fetch(config["otx_api_key"], config.get("pulse_days", 30))
    logger.info(f"Fetched {len(pulses)} pulses")

    if not pulses:
        logger.warning("No pulses fetched")
        sys.exit(0)

    events = format_events(pulses, config)
    logger.info(f"Formatted {len(events)} indicators")

    if not events:
        logger.warning("No indicators to send")
        sys.exit(0)

    sent = send_to_splunk(events, config)
    logger.info(f"Sent {sent} events to Splunk ES")

if __name__ == "__main__":
    main()
