"""
YARA engine — compiles once at import time (compilation isn't free, and
rules don't change between events), reused for every scan.
"""

import glob
import os

import yara

from app.detection.mitre import technique_name

_RULES_DIR = os.path.join(os.path.dirname(__file__), "yara_rules")


def load_yara_rules() -> yara.Rules:
    filepaths = {
        os.path.splitext(os.path.basename(p))[0]: p
        for p in glob.glob(os.path.join(_RULES_DIR, "*.yar"))
    }
    return yara.compile(filepaths=filepaths)


def scan_message(compiled_rules: yara.Rules, message: str) -> list[dict]:
    return [
        {"rule": m.rule, "meta": dict(m.meta)}
        for m in compiled_rules.match(data=message)
    ]


def yara_match_to_alert_dict(event_id: str, message: str, match: dict) -> dict:
    meta = match["meta"]
    mitre = [meta["mitre_technique"]] if "mitre_technique" in meta else []
    technique_summary = ", ".join(technique_name(t) for t in mitre) if mitre else None

    summary = f"YARA match ({match['rule']}): {message}"
    if technique_summary:
        summary = f"{summary} [{technique_summary}]"

    return {
        "rule_id": f"yara.{match['rule']}",
        "rule_title": meta.get("description", match["rule"]),
        "detection_type": "yara",
        "severity": meta.get("severity", "medium"),
        "mitre_techniques": mitre,
        "source_event_id": event_id,
        "summary": summary,
        "details": {"yara_rule": match["rule"], "matched_message": message},
    }
