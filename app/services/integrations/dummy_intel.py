import hashlib
import asyncio
from app.models.schemas import SourceReport, ThreatActor, MitreTTP

# Hardcoded safe and malicious IPs for demonstration
KNOWN_SAFE_IPS = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
KNOWN_MALICIOUS_IPS = ["185.159.231.1", "103.149.208.57", "94.156.71.115"]

async def fetch_dummy_virustotal_data(observable: str) -> SourceReport:
    # Simulate network latency
    await asyncio.sleep(0.5)
    
    if observable in KNOWN_SAFE_IPS:
        return SourceReport(source_name="VirusTotal (Sim)", malicious_votes=0, total_votes=90, tags=["whitelisted", "dns"])
    
    if observable in KNOWN_MALICIOUS_IPS:
        return SourceReport(source_name="VirusTotal (Sim)", malicious_votes=65, total_votes=90, tags=["malware", "botnet", "c2"])

    # Make results deterministic for unknown IPs based on hash
    hash_val = int(hashlib.md5(observable.encode()).hexdigest(), 16)
    if hash_val % 10 < 3: # 30% chance an unknown IP is marked malicious
        return SourceReport(source_name="VirusTotal (Sim)", malicious_votes=15, total_votes=90, tags=["suspicious", "phishing"])
    else:
        return SourceReport(source_name="VirusTotal (Sim)", malicious_votes=0, total_votes=90, tags=["clean"])

async def fetch_dummy_alienvault_data(observable: str) -> SourceReport:
    await asyncio.sleep(0.3)
    if observable in KNOWN_MALICIOUS_IPS:
        return SourceReport(source_name="AlienVault OTX (Sim)", malicious_votes=5, total_votes=5, tags=["apt29", "cobalt_strike"])
    return SourceReport(source_name="AlienVault OTX (Sim)", malicious_votes=0, total_votes=0, tags=[])

async def fetch_dummy_mitre_ttps(observable: str) -> list[MitreTTP]:
    if observable in KNOWN_MALICIOUS_IPS:
        return [
            MitreTTP(id="T1071", name="Application Layer Protocol", url="https://attack.mitre.org/techniques/T1071/"),
            MitreTTP(id="T1566", name="Phishing", url="https://attack.mitre.org/techniques/T1566/")
        ]
    # Check deterministic hash for random unknown IPs
    hash_val = int(hashlib.md5(observable.encode()).hexdigest(), 16)
    if hash_val % 10 < 3:
        return [MitreTTP(id="T1110", name="Brute Force", url="https://attack.mitre.org/techniques/T1110/")]
    return []

async def fetch_dummy_actors(observable: str) -> list[ThreatActor]:
    if observable in KNOWN_MALICIOUS_IPS:
        return [ThreatActor(name="Cozy Bear (APT29)", country="RU", description="Known Russian intelligence collection element.")]
    return []
