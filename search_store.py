"""OpenSearch storage for ASSAS: keeps every raw log event and searches them."""
import logging
import os
import re
from datetime import datetime, timezone

import pandas as pd
from dotenv import load_dotenv
from opensearchpy import OpenSearch, helpers

load_dotenv()

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
INDEX = "assas-logs"

MAPPING = {
    "mappings": {
        "properties": {
            "timestamp":   {"type": "date", "format": "yyyy-MM-dd HH:mm:ss||strict_date_optional_time||epoch_millis"},
            "user":        {"type": "keyword"},
            "ip":          {"type": "keyword"},
            "event":       {"type": "keyword"},
            "status":      {"type": "keyword"},
            "level":       {"type": "keyword"},
            "os":          {"type": "keyword"},
            "message":     {"type": "text"},
            "source_file": {"type": "keyword"},
            "analysis_id": {"type": "integer"},
            "indexed_at":  {"type": "date"},
        }
    }
}

_client = None


def client():
    global _client
    if _client is None:
        # Fail fast when OpenSearch is down instead of retrying for ~40 s per request.
        _client = OpenSearch(OPENSEARCH_URL, timeout=5, max_retries=1, retry_on_timeout=False)
    return _client


def is_available():
    try:
        return client().ping()
    except Exception:
        return False


def ensure_index():
    if not client().indices.exists(index=INDEX):
        client().indices.create(index=INDEX, body=MAPPING)


def _clean_timestamp(value):
    ts = pd.to_datetime(value, errors="coerce")
    return ts.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(ts) else None


def index_logs(logs, source_file, analysis_id=None):
    """Send every log line of a DataFrame to OpenSearch. Returns how many were stored."""
    ensure_index()
    default_os = "linux" if source_file.lower().endswith((".log", ".txt")) else "unknown"
    now = datetime.now(timezone.utc).isoformat()

    def actions():
        for row in logs.fillna("").to_dict(orient="records"):
            yield {
                "_index": INDEX,
                "_source": {
                    "timestamp": _clean_timestamp(row.get("timestamp")),
                    "user": str(row.get("user", "")),
                    "ip": str(row.get("ip", "")),
                    "event": str(row.get("event", "")),
                    "status": str(row.get("status", "")),
                    "level": str(row.get("level", "")),
                    "os": str(row.get("os") or default_os),
                    "message": str(row.get("message", "")),
                    "source_file": source_file,
                    "analysis_id": analysis_id,
                    "indexed_at": now,
                },
            }

    stored, errors = helpers.bulk(client(), actions(), refresh=True, raise_on_error=False)
    if errors:
        logging.getLogger(__name__).warning("%d log events were rejected by OpenSearch", len(errors))
    return stored


def _escape_wildcard(value):
    """User input is matched literally: * ? and \\ would otherwise be wildcard syntax."""
    return re.sub(r"([*?\\])", r"\\\1", value)


def build_query(user="", ip="", event="", status="", os_name="", text="",
                date_from="", date_to=""):
    """Turn the search form into an OpenSearch query."""
    filters = []
    if user:
        filters.append({"wildcard": {"user": {"value": f"*{_escape_wildcard(user)}*", "case_insensitive": True}}})
    if ip:
        filters.append({"wildcard": {"ip": {"value": f"*{_escape_wildcard(ip)}*"}}})
    if event:
        filters.append({"term": {"event": event}})
    if status:
        filters.append({"term": {"status": status}})
    if os_name:
        filters.append({"term": {"os": os_name}})
    if date_from or date_to:
        rng = {}
        if date_from:
            rng["gte"] = date_from.replace("T", " ") + (":00" if len(date_from) == 16 else "")
        if date_to:
            rng["lte"] = date_to.replace("T", " ") + (":59" if len(date_to) == 16 else "")
        filters.append({"range": {"timestamp": rng}})

    must = [{"match": {"message": {"query": text, "operator": "and"}}}] if text else [{"match_all": {}}]
    return {"bool": {"must": must, "filter": filters}}


def search_logs(size=200, **filters):
    """Search stored logs. Returns (total, rows, facets)."""
    ensure_index()
    body = {
        "query": build_query(**filters),
        "sort": [{"timestamp": {"order": "desc", "missing": "_last"}}],
        "size": size,
        "track_total_hits": True,
        "aggs": {
            "events": {"terms": {"field": "event", "size": 20}},
            "statuses": {"terms": {"field": "status", "size": 20}},
            "systems": {"terms": {"field": "os", "size": 10}},
        },
    }
    res = client().search(index=INDEX, body=body)
    rows = [hit["_source"] for hit in res["hits"]["hits"]]
    facets = {name: [b["key"] for b in agg["buckets"]] for name, agg in res["aggregations"].items()}
    return res["hits"]["total"]["value"], rows, facets
