import asyncio
from app.models.schemas import RiskReport, ObservableType
from app.services.integrations.dummy_intel import (
    fetch_dummy_virustotal_data,
    fetch_dummy_alienvault_data,
    fetch_dummy_mitre_ttps,
    fetch_dummy_actors
)

async def analyze_ip(ip_address: str) -> RiskReport:
    """
    Orchestrates queries to various intel sources and calculates a risk score.
    """
    # Fetch data concurrently from all sources for speed
    vt_task = fetch_dummy_virustotal_data(ip_address)
    av_task = fetch_dummy_alienvault_data(ip_address)
    ttps_task = fetch_dummy_mitre_ttps(ip_address)
    actors_task = fetch_dummy_actors(ip_address)
    
    vt_result, av_result, ttps_result, actors_result = await asyncio.gather(
        vt_task, av_task, ttps_task, actors_task
    )
    
    # Simple Risk Scoring Engine
    risk_score = 0
    
    # Source 1: Virustotal ratio
    if vt_result.total_votes > 0:
        ratio = vt_result.malicious_votes / vt_result.total_votes
        risk_score += (ratio * 60) # VT contributes up to 60 points
        
    # Source 2: Alienvault mentions
    if av_result.malicious_votes > 0:
        risk_score += 30 # AV contributes 30 points if it flags it
        
    # Source 3: Known APT actors
    if len(actors_result) > 0:
        risk_score += 10 # APT association is severe, +10 points
        
    risk_score = min(int(risk_score), 100) # Cap at 100
    
    # Determine severity label
    if risk_score == 0:
        severity = "Low"
        summary = "No malicious activity detected. Safe observable."
    elif risk_score < 40:
        severity = "Medium"
        summary = "Some suspicious indicators found. Monitor activity."
    elif risk_score < 80:
        severity = "High"
        summary = "Malicious activity confirmed by multiple sources."
    else:
        severity = "Critical"
        summary = "Critical threat! Known APT infrastructure or widespread malware."

    return RiskReport(
        observable=ip_address,
        observable_type=ObservableType.IP,
        overall_risk_score=risk_score,
        severity=severity,
        sources=[vt_result, av_result],
        mitre_ttps=ttps_result,
        associated_actors=actors_result,
        summary=summary
    )
