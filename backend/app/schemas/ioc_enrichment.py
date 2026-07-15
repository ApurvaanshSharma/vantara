from pydantic import BaseModel


class IOCLookupResult(BaseModel):
    indicator: str
    enrichable: bool
    combined_threat_score: int | None = None
    abuseipdb_score: int | None = None
    abuseipdb_total_reports: int | None = None
    otx_pulse_count: int | None = None
    otx_malware_families: list[str] = []
