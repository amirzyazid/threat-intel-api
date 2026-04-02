from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.models.schemas import RiskReport
from app.services.analyzer import analyze_ip
import uvicorn

app = FastAPI(
    title="SOC Threat Intel Enrichment API",
    description="An API to enrich observables (IPs, Domains, Hashes) with risk scores and MITRE ATT&CK mapping.",
    version="1.0.0"
)

# CORS middleware for when we potentially build a frontend dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Welcome to the Threat Intel Enrichment API. Go to /docs for the interactive Swagger UI."}

@app.get("/api/v1/analyze/ip/{ip_address}", response_model=RiskReport)
async def analyze_ip_endpoint(ip_address: str):
    """
    Submit an IP address to aggregate threat intelligence and calculate a risk score.
    """
    # Simple validation using basic python, in real life we could use an IP validation library
    parts = ip_address.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        raise HTTPException(status_code=400, detail="Invalid IPv4 address format.")
    
    report = await analyze_ip(ip_address)
    return report

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
