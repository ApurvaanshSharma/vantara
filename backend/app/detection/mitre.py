"""
MITRE ATT&CK technique reference — deliberately NOT the full ~600-technique
STIX bundle. This is a curated lookup for exactly the techniques this
phase's rules reference, so alerts can show a human-readable name
alongside the technique ID without shipping a dataset most of which would
never be used.

Importing the full official ATT&CK STIX bundle (via the attackcti or
mitreattack-python packages) is a legitimate stretch goal once more rule
coverage exists — noted here rather than silently deferred.
"""

MITRE_TECHNIQUES: dict[str, str] = {
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1059": "Command and Scripting Interpreter",
    "T1071": "Application Layer Protocol",
}


def technique_name(technique_id: str) -> str:
    return MITRE_TECHNIQUES.get(technique_id, technique_id)
