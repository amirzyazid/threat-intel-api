# SOC Threat Intel Enrichment API

An API to enrich observables (IPs, Domains, URLs) with threat intelligence, risk scores, and MITRE ATT&CK technique mappings. This tool aggregates data from multiple threat intelligence sources to provide comprehensive security risk assessments.

## Features

- **IP Address Analysis** - Analyze IPv4 addresses for malicious activity
- **URL & Domain Analysis** - Submit full URLs or domains to extract and analyze domains
- **Risk Scoring** - Aggregate threat intelligence from multiple sources with a normalized 0-100 risk score
- **MITRE ATT&CK Mapping** - Map threats to MITRE ATT&CK techniques and tactics
- **Threat Actor Attribution** - Identify associated threat actors and their countries
- **Multi-Source Intelligence** - Aggregate data from VirusTotal, AlienVault, and APT databases

## Quick Start

### Prerequisites

- Python 3.8+
- pip (Python package manager)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd threat-intel-api
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Running the API

Start the development server:
```bash
python -m app.main
```

The API will be available at `http://localhost:8000`

**Interactive API Documentation:** Visit `http://localhost:8000/docs` for the Swagger UI

## API Endpoints

### 1. Analyze IP Address

Analyzes an IPv4 address for malicious activity and threat indicators.

**Endpoint:** `GET /api/v1/analyze/ip/{ip_address}`

**Parameters:**
- `ip_address` (path parameter): Valid IPv4 address (e.g., `192.168.1.1`)

**Example Request:**
```bash
curl http://localhost:8000/api/v1/analyze/ip/8.8.8.8
```

**Example Response:**
```json
{
  "observable": "8.8.8.8",
  "observable_type": "ip",
  "overall_risk_score": 0,
  "severity": "Low",
  "sources": [
    {
      "source_name": "VirusTotal",
      "malicious_votes": 0,
      "total_votes": 10,
      "tags": []
    }
  ],
  "mitre_ttps": [],
  "associated_actors": [],
  "summary": "IP address appears to be safe based on current threat intelligence."
}
```

### 2. Analyze URL or Domain

Analyzes a URL or domain for malicious activity. The API automatically extracts the domain from full URLs.

**Endpoint:** `GET /api/v1/analyze/url/{url:path}`

**Parameters:**
- `url` (path parameter): Full URL (e.g., `https://example.com/path`) or domain (e.g., `example.com`)

**Example Requests:**
```bash
# Analyze a full URL
curl http://localhost:8000/api/v1/analyze/url/https://example.com/path/to/resource

# Analyze a domain directly
curl http://localhost:8000/api/v1/analyze/url/example.com
```

**Example Response:**
```json
{
  "observable": "example.com",
  "observable_type": "domain",
  "overall_risk_score": 15,
  "severity": "Low",
  "sources": [
    {
      "source_name": "VirusTotal",
      "malicious_votes": 2,
      "total_votes": 45,
      "tags": ["phishing", "malware-distribution"]
    }
  ],
  "mitre_ttps": [
    {
      "id": "T1566.002",
      "name": "Phishing: Spearphishing Link",
      "url": "https://attack.mitre.org/techniques/T1566/002/"
    }
  ],
  "associated_actors": [
    {
      "name": "Lazarus Group",
      "country": "North Korea",
      "description": "Suspected state-sponsored APT group"
    }
  ],
  "summary": "Domain has been associated with phishing campaigns. Low to medium risk."
}
```

## Response Schema

All threat analysis endpoints return a `RiskReport` object:

```json
{
  "observable": "string - The IP, domain, or URL analyzed",
  "observable_type": "string - Type: 'ip', 'domain', or 'hash'",
  "overall_risk_score": "integer - Risk score from 0 (Safe) to 100 (Critical)",
  "severity": "string - One of: 'Low', 'Medium', 'High', 'Critical'",
  "sources": [
    {
      "source_name": "string - Name of threat intelligence source",
      "malicious_votes": "integer - Number of sources flagging as malicious",
      "total_votes": "integer - Total sources voting on this observable",
      "tags": ["string - Tags or categories (e.g., 'malware', 'phishing')"]
    }
  ],
  "mitre_ttps": [
    {
      "id": "string - MITRE ATT&CK technique ID (e.g., 'T1566.002')",
      "name": "string - Technique name",
      "url": "string - Link to MITRE ATT&CK page"
    }
  ],
  "associated_actors": [
    {
      "name": "string - Threat actor name",
      "country": "string - Country of origin",
      "description": "string - Description of the actor"
    }
  ],
  "summary": "string - Human-readable summary of the threat assessment"
}
```

## Risk Score Interpretation

The API uses a normalized 0-100 risk score:

| Score Range | Severity | Interpretation |
|-------------|----------|-----------------|
| 0-25       | Low      | Safe, minimal risk |
| 26-50      | Medium   | Suspicious activity detected |
| 51-75      | High     | Strong indicators of compromise |
| 76-100     | Critical | Confirmed malicious, immediate action recommended |

## Risk Scoring Algorithm

The overall risk score is calculated by aggregating data from multiple threat intelligence sources:

1. **VirusTotal** - Up to 60 points based on detection ratio
2. **AlienVault OTX** - Up to 30 points based on pulse data
3. **APT Threat Actors** - Up to 10 points if associated with known APT groups
4. **Final Score** - Capped at 100 (maximum risk)

## Known Safe IPs

The following IPs are recognized as safe and return a risk score of 0:
- `8.8.8.8` (Google DNS)
- `1.1.1.1` (Cloudflare DNS)
- `8.8.4.4` (Google DNS Secondary)

## Known Malicious IPs

The following IPs are flagged as malicious:
- `185.159.231.1`
- `103.149.208.57`
- `94.156.71.115`

## Architecture

The API is built with FastAPI and follows a layered architecture:

```
app/
├── main.py                 # API routes and endpoint definitions
├── models/
│   └── schemas.py          # Pydantic data models and enums
└── services/
    ├── analyzer.py         # Core threat analysis logic
    ├── utils.py            # Utility functions (URL parsing, domain extraction)
    └── integrations/
        └── dummy_intel.py  # Mock threat intelligence data sources
```

### Key Components

- **analyzer.py**: Contains `analyze_ip()` and `analyze_url()` functions that orchestrate threat intelligence aggregation
- **utils.py**: Utility functions including `extract_domain_from_url()` for parsing URLs
- **dummy_intel.py**: Mock threat intelligence sources with deterministic data for testing and development
- **schemas.py**: Pydantic models defining API request/response structures

## Error Handling

The API returns appropriate HTTP status codes:

| Status Code | Meaning |
|------------|---------|
| 200        | Success - Observable analyzed successfully |
| 400        | Bad Request - Invalid observable format |
| 500        | Internal Server Error |

**Example Error Response:**
```json
{
  "detail": "Invalid IPv4 address format."
}
```

## Development

### Project Structure

```
threat-intel-api/
├── README.md               # This file
├── requirements.txt        # Python dependencies
├── .gitignore             # Git ignore rules
└── app/
    ├── __init__.py
    ├── main.py
    ├── models/
    │   └── schemas.py
    └── services/
        ├── analyzer.py
        ├── utils.py
        └── integrations/
            └── dummy_intel.py
```

### Running Tests

Currently, the project includes mock threat intelligence data for development. Tests can be run with:

```bash
# Note: Formal test suite coming soon
python -m pytest
```

## Future Enhancements

- [ ] DNS resolution for domains to IP addresses
- [ ] Domain-specific threat intelligence
- [ ] Hash analysis (MD5, SHA-1, SHA-256)
- [ ] Real threat intelligence source integrations (VirusTotal API, AlienVault OTX API)
- [ ] Caching layer for performance optimization
- [ ] Rate limiting and authentication
- [ ] Historical trend analysis
- [ ] Alert generation and webhooks

## Dependencies

- **fastapi** (0.111.0) - Modern web framework for building APIs
- **uvicorn** (0.30.1) - ASGI server for running FastAPI applications
- **pydantic** (2.7.4) - Data validation and serialization
- **httpx** (0.27.0) - HTTP client for async requests

## CORS Configuration

The API has CORS enabled with permissive settings for development. In production, update the `CORSMiddleware` configuration in `app/main.py` to restrict allowed origins.

## License

[Add your license information here]

## Contributing

[Add contribution guidelines here]

## Support

For issues and feature requests, please open an issue on the GitHub repository.
