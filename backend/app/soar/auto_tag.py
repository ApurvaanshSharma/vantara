"""
Playbook 1: auto-tag. Pure — no DB writes, no external calls — since its
only job is computing a tag set that playbook 3 (auto_case_notify) reuses.
Kept separate from case creation logic anyway: tags are meaningful on
their own (shown directly on the alert/playbook-run in the UI) even for
alerts that don't cross the severity threshold for case creation.
"""

from app.models.alert import Alert


def compute_tags(alert: Alert) -> list[str]:
    tags = [f"severity:{alert.severity.value}", f"source:{alert.detection_type.value}"]
    tags.extend(f"mitre:{technique}" for technique in alert.mitre_techniques)
    return tags
