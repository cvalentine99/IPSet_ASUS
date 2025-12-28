#!/usr/bin/env python3
"""
Skynet OTX to Splunk ES Threat Intelligence Integration

This script fetches threat intelligence from AlienVault OTX and formats it
for ingestion into Splunk Enterprise Security's threat_activity index.

CRITICAL: All events are formatted to comply with:
- Splunk ES DA-ESS-ThreatIntelligence data model
- CIM Threat Intelligence schema
- ES threat_activity index requirements

Required ES fields emitted:
- indicator: The IOC value (IP, domain, hash, URL)
- indicator_type: Normalized type (ip, domain, file_hash, url, email)
- threat_key: Unique identifier for deduplication
- confidence: Numeric confidence score (0-100)
- weight: Numeric weight for threat scoring
- description: Human-readable description
- threat_collection_name: Source collection identifier
- source: Provider name (for CIM compliance)
"""

import json
import logging
import hashlib
import time
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import ssl

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# ES THREAT INTELLIGENCE FIELD MAPPING
# =============================================================================
# Maps OTX indicator types to Splunk ES normalized indicator_type values
# Reference: Splunk ES DA-ESS-ThreatIntelligence data model
OTX_TO_ES_INDICATOR_TYPE = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "file_hash",
    "FileHash-SHA1": "file_hash",
    "FileHash-SHA256": "file_hash",
    "email": "email",
    "CVE": "cve",
    "YARA": "yara",
    "CIDR": "ip",
}

# ES-required fields that must be present in every event
ES_REQUIRED_FIELDS = [
    "indicator",
    "indicator_type",
    "threat_key",
]

# ES-recommended fields for full functionality
ES_RECOMMENDED_FIELDS = [
    "confidence",
    "weight",
    "description",
    "threat_collection_name",
    "source",
]


class OTXClient:
    """AlienVault OTX API client."""

    def __init__(self, api_key: str, base_url: str = "https://otx.alienvault.com/api/v1"):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')

    def _make_request(self, endpoint: str) -> Optional[Dict]:
        """Make authenticated request to OTX API."""
        url = f"{self.base_url}/{endpoint}"
        headers = {"X-OTX-API-KEY": self.api_key}

        try:
            req = Request(url, headers=headers)
            ctx = ssl.create_default_context()
            with urlopen(req, context=ctx, timeout=30) as response:
                return json.loads(response.read().decode('utf-8'))
        except HTTPError as e:
            logger.error(f"HTTP error fetching {url}: {e.code}")
            return None
        except URLError as e:
            logger.error(f"URL error fetching {url}: {e.reason}")
            return None
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return None

    def get_subscribed_pulses(self, days: int = 30) -> List[Dict]:
        """Fetch subscribed pulses from the last N days."""
        modified_since = (datetime.utcnow() - timedelta(days=days)).isoformat()
        endpoint = f"pulses/subscribed?modified_since={modified_since}&limit=50"

        pulses = []
        while endpoint:
            data = self._make_request(endpoint)
            if not data:
                break
            pulses.extend(data.get("results", []))
            next_url = data.get("next")
            if next_url:
                # Extract relative endpoint from full URL
                endpoint = next_url.replace(self.base_url + "/", "")
            else:
                endpoint = None

        logger.info(f"Fetched {len(pulses)} pulses from OTX")
        return pulses


class SplunkESFormatter:
    """
    Formats OTX indicators into Splunk ES Threat Intelligence events.

    CRITICAL: This class ensures all events comply with:
    - DA-ESS-ThreatIntelligence data model requirements
    - CIM Threat Intelligence schema
    - threat_activity index expectations
    """

    def __init__(self, config: Dict):
        self.config = config
        self.threat_collection_name = config.get("threat_collection_name", "otx_alienvault")
        self.default_confidence = config.get("default_confidence", 70)
        self.default_weight = config.get("default_weight", 1)
        self.source = config.get("splunk_source", "OTX:AlienVault")

    def _generate_threat_key(self, indicator: str, indicator_type: str, pulse_id: str) -> str:
        """
        Generate unique threat_key for ES deduplication.

        The threat_key is REQUIRED by ES for:
        - Deduplication in KV store lookups
        - Threat artifact correlation
        - Dashboard aggregation
        """
        key_string = f"{indicator}|{indicator_type}|{pulse_id}"
        return hashlib.sha256(key_string.encode()).hexdigest()[:32]

    def _normalize_indicator_type(self, otx_type: str) -> str:
        """
        Normalize OTX indicator type to ES indicator_type.

        ES expects specific values:
        - ip (for IPv4, IPv6, CIDR)
        - domain (for domain, hostname)
        - url (for URL, URI)
        - file_hash (for MD5, SHA1, SHA256)
        - email
        """
        return OTX_TO_ES_INDICATOR_TYPE.get(otx_type, "unknown")

    def _calculate_confidence(self, pulse: Dict, indicator: Dict) -> int:
        """
        Calculate confidence score for ES.

        ES uses confidence for:
        - Risk scoring in dashboards
        - Alert prioritization
        - Threat correlation weighting

        Returns: Integer 0-100
        """
        base_confidence = self.default_confidence

        # Boost confidence for adversary-tagged pulses
        if pulse.get("adversary"):
            base_confidence = min(100, base_confidence + 10)

        # Boost for pulses with multiple references
        references = pulse.get("references", [])
        if len(references) >= 3:
            base_confidence = min(100, base_confidence + 5)

        # Boost for targeted industries (more specific intel)
        industries = pulse.get("targeted_countries", []) or pulse.get("industries", [])
        if industries:
            base_confidence = min(100, base_confidence + 5)

        return base_confidence

    def _calculate_weight(self, indicator_type: str) -> int:
        """
        Calculate weight for ES threat scoring.

        Weight affects:
        - Risk score calculations
        - Notable event generation
        - Correlation search priorities
        """
        # Higher weight for more actionable indicator types
        weights = {
            "ip": 2,
            "domain": 2,
            "url": 1,
            "file_hash": 3,
            "email": 1,
        }
        return weights.get(indicator_type, self.default_weight)

    def format_indicator(self, indicator_data: Dict, pulse: Dict) -> Optional[Dict]:
        """
        Format a single OTX indicator into ES-compliant event.

        CRITICAL ES FIELDS MAPPING:
        -------------------------
        indicator          <- OTX indicator value (REQUIRED)
        indicator_type     <- Normalized from OTX type (REQUIRED)
        threat_key         <- Generated unique key (REQUIRED)
        confidence         <- Calculated score 0-100 (RECOMMENDED)
        weight             <- Calculated weight (RECOMMENDED)
        description        <- Pulse name + indicator context (RECOMMENDED)
        threat_collection_name <- Config value (RECOMMENDED)
        source             <- Provider name for CIM (RECOMMENDED)

        ADDITIONAL CIM FIELDS:
        ---------------------
        threat_category    <- Pulse tags
        threat_group       <- Adversary attribution
        file_hash          <- For file_hash indicator_type
        src/dest           <- For IP indicator_type (correlation)
        """
        otx_type = indicator_data.get("type", "")
        indicator_value = indicator_data.get("indicator", "")

        if not indicator_value or not otx_type:
            return None

        # Normalize indicator type for ES
        es_indicator_type = self._normalize_indicator_type(otx_type)
        if es_indicator_type == "unknown":
            logger.debug(f"Skipping unknown indicator type: {otx_type}")
            return None

        # Generate threat_key for ES deduplication
        pulse_id = pulse.get("id", "unknown")
        threat_key = self._generate_threat_key(indicator_value, es_indicator_type, pulse_id)

        # Build ES-compliant event
        # =========================
        event = {
            # -----------------------------------------------------------------
            # REQUIRED ES FIELDS (DA-ESS-ThreatIntelligence)
            # -----------------------------------------------------------------
            "indicator": indicator_value,
            "indicator_type": es_indicator_type,
            "threat_key": threat_key,

            # -----------------------------------------------------------------
            # RECOMMENDED ES FIELDS
            # -----------------------------------------------------------------
            "confidence": self._calculate_confidence(pulse, indicator_data),
            "weight": self._calculate_weight(es_indicator_type),
            "description": f"{pulse.get('name', 'Unknown Pulse')} - {indicator_data.get('description', '')}".strip(" -"),
            "threat_collection_name": self.threat_collection_name,
            "source": self.source,

            # -----------------------------------------------------------------
            # CIM THREAT INTELLIGENCE FIELDS
            # -----------------------------------------------------------------
            "threat_category": ",".join(pulse.get("tags", [])[:5]) if pulse.get("tags") else "",
            "threat_group": pulse.get("adversary", ""),

            # -----------------------------------------------------------------
            # PROVENANCE FIELDS
            # -----------------------------------------------------------------
            "pulse_id": pulse_id,
            "pulse_name": pulse.get("name", ""),
            "pulse_author": pulse.get("author_name", ""),
            "pulse_created": pulse.get("created", ""),
            "pulse_modified": pulse.get("modified", ""),

            # -----------------------------------------------------------------
            # SPLUNK INTERNAL FIELDS
            # These ensure proper ES data model acceleration
            # -----------------------------------------------------------------
            "sourcetype": self.config.get("splunk_sourcetype", "stash"),
        }

        # Add type-specific CIM fields for correlation
        if es_indicator_type == "ip":
            # For IP correlation with Network Traffic data model
            event["src"] = indicator_value
            event["dest"] = indicator_value
        elif es_indicator_type == "domain":
            # For domain correlation
            event["domain"] = indicator_value
        elif es_indicator_type == "file_hash":
            # For file hash correlation with Endpoint data model
            event["file_hash"] = indicator_value
            # Identify hash type for more specific matching
            hash_len = len(indicator_value)
            if hash_len == 32:
                event["file_hash_md5"] = indicator_value
            elif hash_len == 40:
                event["file_hash_sha1"] = indicator_value
            elif hash_len == 64:
                event["file_hash_sha256"] = indicator_value
        elif es_indicator_type == "url":
            event["url"] = indicator_value

        return event

    def format_pulses(self, pulses: List[Dict]) -> List[Dict]:
        """Format all pulses into ES-compliant events."""
        events = []
        for pulse in pulses:
            indicators = pulse.get("indicators", [])
            for indicator in indicators:
                event = self.format_indicator(indicator, pulse)
                if event:
                    events.append(event)

        logger.info(f"Formatted {len(events)} indicators for Splunk ES")
        return events


class SplunkHECSender:
    """Sends events to Splunk via HTTP Event Collector."""

    def __init__(self, config: Dict):
        self.hec_url = config.get("splunk_hec_url", "").rstrip('/')
        self.hec_token = config.get("splunk_hec_token", "")
        self.index = config.get("splunk_index", "threat_activity")
        self.sourcetype = config.get("splunk_sourcetype", "stash")
        self.source = config.get("splunk_source", "OTX:AlienVault")
        self.batch_size = config.get("batch_size", 500)
        self.verify_ssl = config.get("verify_ssl", True)

    def _send_batch(self, events: List[Dict]) -> bool:
        """Send a batch of events to HEC."""
        if not events:
            return True

        # Format events for HEC
        hec_events = []
        for event in events:
            hec_event = {
                "time": time.time(),
                "host": "skynet_otx",
                "index": self.index,
                "sourcetype": self.sourcetype,
                "source": self.source,
                "event": event,
            }
            hec_events.append(json.dumps(hec_event))

        payload = "\n".join(hec_events).encode('utf-8')

        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json",
        }

        try:
            req = Request(self.hec_url, data=payload, headers=headers, method="POST")
            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            with urlopen(req, context=ctx, timeout=60) as response:
                result = json.loads(response.read().decode('utf-8'))
                if result.get("code") == 0:
                    return True
                else:
                    logger.error(f"HEC error: {result}")
                    return False
        except HTTPError as e:
            logger.error(f"HEC HTTP error: {e.code} - {e.read().decode()}")
            return False
        except Exception as e:
            logger.error(f"HEC error: {e}")
            return False

    def send_events(self, events: List[Dict]) -> int:
        """Send all events to Splunk in batches."""
        if not self.hec_url or not self.hec_token:
            logger.error("HEC URL or token not configured")
            return 0

        total_sent = 0
        for i in range(0, len(events), self.batch_size):
            batch = events[i:i + self.batch_size]
            if self._send_batch(batch):
                total_sent += len(batch)
                logger.info(f"Sent batch {i // self.batch_size + 1}: {len(batch)} events")
            else:
                logger.error(f"Failed to send batch {i // self.batch_size + 1}")

        return total_sent


def validate_es_compliance(events: List[Dict]) -> Dict[str, Any]:
    """
    Validate events against ES Threat Intelligence requirements.

    Returns validation report for logging/debugging.
    """
    report = {
        "total_events": len(events),
        "valid_events": 0,
        "missing_required_fields": {},
        "missing_recommended_fields": {},
        "indicator_type_distribution": {},
    }

    for event in events:
        # Check required fields
        missing_required = [f for f in ES_REQUIRED_FIELDS if not event.get(f)]
        if missing_required:
            for field in missing_required:
                report["missing_required_fields"][field] = report["missing_required_fields"].get(field, 0) + 1
        else:
            report["valid_events"] += 1

        # Check recommended fields
        missing_recommended = [f for f in ES_RECOMMENDED_FIELDS if not event.get(f)]
        for field in missing_recommended:
            report["missing_recommended_fields"][field] = report["missing_recommended_fields"].get(field, 0) + 1

        # Track indicator type distribution
        ind_type = event.get("indicator_type", "unknown")
        report["indicator_type_distribution"][ind_type] = report["indicator_type_distribution"].get(ind_type, 0) + 1

    return report


def main():
    """Main execution flow."""
    # Load configuration
    config_path = os.environ.get("SKYNET_OTX_CONFIG",
                                  os.path.join(os.path.dirname(__file__), "skynet_otx_config.json"))

    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration: {e}")
        sys.exit(1)

    # Set log level from config
    log_level = config.get("log_level", "INFO")
    logging.getLogger().setLevel(getattr(logging, log_level, logging.INFO))

    # Validate required configuration
    if not config.get("otx_api_key"):
        logger.error("OTX API key not configured")
        sys.exit(1)

    # Fetch indicators from OTX
    logger.info("Starting OTX fetch...")
    otx_client = OTXClient(
        api_key=config["otx_api_key"],
        base_url=config.get("otx_base_url", "https://otx.alienvault.com/api/v1")
    )
    pulses = otx_client.get_subscribed_pulses(days=config.get("pulse_days", 30))

    if not pulses:
        logger.warning("No pulses fetched from OTX")
        sys.exit(0)

    # Format for Splunk ES
    logger.info("Formatting indicators for Splunk ES...")
    formatter = SplunkESFormatter(config)
    events = formatter.format_pulses(pulses)

    if not events:
        logger.warning("No indicators formatted")
        sys.exit(0)

    # Validate ES compliance
    validation = validate_es_compliance(events)
    logger.info(f"ES Validation: {validation['valid_events']}/{validation['total_events']} events valid")
    if validation["missing_required_fields"]:
        logger.warning(f"Missing required fields: {validation['missing_required_fields']}")
    logger.info(f"Indicator types: {validation['indicator_type_distribution']}")

    # Send to Splunk
    if config.get("splunk_hec_url") and config.get("splunk_hec_token"):
        logger.info("Sending events to Splunk ES...")
        sender = SplunkHECSender(config)
        sent = sender.send_events(events)
        logger.info(f"Successfully sent {sent} events to Splunk ES threat_activity index")
    else:
        # Output to stdout for testing/debugging
        logger.info("HEC not configured, outputting to stdout...")
        for event in events[:5]:  # Sample output
            print(json.dumps(event, indent=2))
        logger.info(f"(showing 5 of {len(events)} events)")

    logger.info("Skynet OTX sync complete")


if __name__ == "__main__":
    main()
