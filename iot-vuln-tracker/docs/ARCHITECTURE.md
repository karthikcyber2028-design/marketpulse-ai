# IoT Manufacturer Vulnerability Tracker

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Frontend Dashboard                       │
│  ┌──────────┐ ┌────────────┐ ┌──────────┐ ┌──────────────────┐ │
│  │Dashboard │ │Vulns       │ │Mfg Profile│ │Alerts/Integrations│ │
│  └──────────┘ └────────────┘ └──────────┘ └──────────────────┘ │
└───────────────────────────┬─────────────────────────────────────┘
                            │ REST API
┌───────────────────────────┴─────────────────────────────────────┐
│                       FastAPI Application                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────────┐ │
│  │Vuln API  │ │Mfg API   │ │Alert API │ │Dashboard/Integ API │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────────┬───────────┘ │
│       │            │            │                  │              │
│  ┌────┴────────────┴────────────┴──────────────────┴──────────┐ │
│  │                    Core Services Layer                       │ │
│  │  ┌──────────────┐ ┌───────────────┐ ┌───────────────────┐  │ │
│  │  │Data Collectors│ │Risk Scoring   │ │Alerting Service   │  │ │
│  │  │NVD, ICS-CERT │ │Engine         │ │Multi-channel     │  │ │
│  │  │CVE, Bulletins│ │Weighted Comp. │ │Escalation Paths  │  │ │
│  │  └──────────────┘ └───────────────┘ └───────────────────┘  │ │
│  └─────────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                  Scheduler (APScheduler)                     │ │
│  │  NVD sync (1h) │ ICS-CERT (2h) │ Rescore (6h) │ Metrics   │ │
│  └─────────────────────────────────────────────────────────────┘ │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────┴─────────────────────────────────────┐
│                  SQLite / PostgreSQL Database                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────────┐ │
│  │Vulns     │ │Mfg/Device│ │Alerts    │ │Scores/Audit/Config │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Database Schema

### Core Tables

| Table | Purpose | Key Fields |
|-------|---------|------------|
| `vulnerabilities` | CVE records with risk scoring | cve_id, severity, cvss scores, risk_score, confidence_score |
| `manufacturers` | Manufacturer security profiles | name, slug, posture_score, patch_rate, risk_rating |
| `product_lines` | Product categories per manufacturer | name, category, support_status, eol_date |
| `devices` | Specific device models | model_name, category, deployment_context, estimated_units |
| `device_firmware` | Firmware version tracking | version, release_date, end_of_support_date |
| `vulnerability_tags` | Flexible metadata tagging | tag_name, tag_value |
| `vulnerability_mitigations` | Patches and workarounds | type, description, url, verified |
| `disputed_vulnerabilities` | Vulnerability dispute records | disputed_by, reason, resolution |
| `score_breakdowns` | Detailed scoring components | 7 weighted components + 5 impact scores |
| `risk_scores` | Composite risk scores | composite_score (0-10) |
| `alert_rules` | Configurable alert triggers | conditions JSON, notification_channels, cooldown |
| `alerts` | Generated alert instances | severity, status, assigned_to, escalation_level |
| `alert_deliveries` | Alert delivery tracking | channel, status, delivered_at, retry_count |
| `escalation_paths` | Multi-level escalation config | severity_trigger, levels JSON |
| `webhook_endpoints` | Webhook integrations | url, event_types, failure_count |
| `siem_integrations` | SIEM connections | siem_type, endpoint_url, event_format |
| `ticketing_integrations` | Ticketing system connections | platform, base_url, auto_create |
| `asset_management_syncs` | Asset management sync | platform, device_count, sync_interval |
| `vulnerability_sources` | Data source registry | source_type, api_url, reliability_score |
| `manufacturer_metrics` | Historical metrics snapshots | daily aggregates of vuln counts, posture scores |
| `audit_logs` | System audit trail | actor, action, entity_type, details |
| `data_retention_policies` | Retention config per entity | entity_type, retention_days |

### Association Tables

| Table | Purpose |
|-------|---------|
| `vulnerability_device_map` | Many-to-many: vulnerabilities <-> devices |

## Data Refresh Intervals

| Source | Default Interval | Configurable |
|--------|-----------------|--------------|
| NVD (NIST) | 1 hour | `NVD_SYNC_INTERVAL` |
| ICS-CERT (CISA) | 2 hours | `ICS_CERT_SYNC_INTERVAL` |
| Manufacturer Bulletins | 4 hours | `MANUFACTURER_BULLETIN_INTERVAL` |
| Zero-day Scan | 30 minutes | `ZERO_DAY_SCAN_INTERVAL` |
| Risk Score Recalculation | 6 hours | Fixed |
| Manufacturer Posture Update | 12 hours | Fixed |
| Alert Escalation Processing | 15 minutes | Fixed |
| Daily Metrics Snapshot | 24 hours | Fixed |

## Confidence Scoring for Unverified Disclosures

The system assigns a confidence score (0.0-1.0) to each vulnerability:

| Source | Base Confidence | Notes |
|--------|----------------|-------|
| NVD verified | 1.0 | Officially scored and published |
| ICS-CERT advisory | 0.98 | Government-verified |
| CVE Program | 0.99 | Standard disclosure |
| Manufacturer bulletin | 0.90 | Self-reported |
| Security researcher (with PoC) | 0.70 | Independent verification |
| Emerging zero-day (no PoC) | 0.30-0.50 | Based on researcher reputation |
| Unverified report | 0.30 | Minimum threshold |

Confidence is adjusted by:
- Presence of proof-of-concept exploit: +0.2
- Multiple independent confirmations: +0.15
- Vendor acknowledgment: +0.2
- Retraction or dispute: flags for review

## Risk Scoring Methodology

Composite Risk Score (0.0-10.0) using weighted components:

| Component | Weight | Source |
|-----------|--------|--------|
| CVSS Base Score | 30% | NVD or calculated |
| Exploit Availability | 15% | CVE references, exploit databases |
| Wild Exploitation | 15% | CISA KEV, threat intel feeds |
| Manufacturer Response History | 10% | Historical patch rates, TTP |
| Affected Device Population | 10% | Estimated units deployed |
| Deployment Context | 10% | Consumer vs. industrial vs. critical infra |
| Vulnerability Age | 10% | Time since publication |

### Deployment Context Multipliers
- Consumer: 0.7x
- Commercial: 0.9x
- Industrial: 1.2x
- Critical Infrastructure: 1.5x
- Medical: 1.4x
- Government: 1.3x

## Vulnerability Status Lifecycle

```
Analyzing → Confirmed → Unpatched → Partially Patched → Patched
    │           │           │
    └───────────┴───────────┴──→ Disputed → (Upheld | Retracted)
    │
    └──→ Retracted (false positive)
    └──→ End of Life (no fix planned)
```

## Dispute & Retraction Handling

1. **Dispute Recorded**: Vulnerability status set to `DISPUTED`
2. **Resolution Period**: 30-day default for manufacturer response
3. **Resolution Options**:
   - `upheld`: Vulnerability confirmed, status reverts to previous
   - `rejected`: Invalid vulnerability, status set to `RETRACTED`
   - `pending`: Extended investigation
4. **Impact on Scoring**: Disputed vulns flagged but not excluded from scoring
5. **Retracted Vulnerabilities**: Retained in database for 7 years with retracted flag

## Data Retention Policies

| Entity | Retention Period | Archive Before Delete |
|--------|-----------------|----------------------|
| Vulnerability Records | 7 years | No |
| Alert History | 1 year | No |
| Audit Logs | 7 years | No |
| Manufacturer Metrics | 3 years | No |
| Raw Sync Data | 90 days | No |

All historical vulnerability records and manufacturer accountability metrics are retained per compliance requirements. Retention policies are configurable via the `data_retention_policies` table.

## API Endpoints

### Vulnerabilities
- `GET /api/v1/vulnerabilities` - List with filtering/pagination
- `POST /api/v1/vulnerabilities` - Create new
- `GET /api/v1/vulnerabilities/{id}` - Get details
- `PATCH /api/v1/vulnerabilities/{id}` - Update
- `DELETE /api/v1/vulnerabilities/{id}` - Delete
- `GET /api/v1/vulnerabilities/{id}/score` - Score breakdown
- `POST /api/v1/vulnerabilities/{id}/rescore` - Recalculate score
- `GET /api/v1/vulnerabilities/{id}/mitigations` - List mitigations
- `POST /api/v1/vulnerabilities/{id}/mitigations` - Add mitigation
- `POST /api/v1/vulnerabilities/{id}/dispute` - File dispute
- `PATCH /api/v1/vulnerabilities/{id}/dispute/{did}/resolve` - Resolve dispute

### Manufacturers
- `GET /api/v1/manufacturers` - List with ranking
- `POST /api/v1/manufacturers` - Create
- `GET /api/v1/manufacturers/{id}` - Get profile
- `GET /api/v1/manufacturers/{id}/vulnerabilities` - List vulns
- `GET /api/v1/manufacturers/{id}/metrics` - Historical metrics
- `POST /api/v1/manufacturers/rescore` - Recalculate all scores

### Devices
- `GET /api/v1/devices` - List
- `POST /api/v1/devices` - Create
- `GET /api/v1/devices/{id}/firmware` - Firmware versions
- `POST /api/v1/devices/{id}/firmware` - Add firmware

### Alerts
- `GET /api/v1/alerts` - List
- `GET /api/v1/alerts/summary` - Aggregated summary
- `GET /api/v1/alerts/{id}` - Get with deliveries
- `PATCH /api/v1/alerts/{id}/acknowledge`
- `PATCH /api/v1/alerts/{id}/resolve`
- `PATCH /api/v1/alerts/{id}/assign`
- `GET /api/v1/alert-rules` - List rules
- `POST /api/v1/alert-rules` - Create rule
- `PATCH /api/v1/alert-rules/{id}/toggle` - Enable/disable

### Dashboard
- `GET /api/v1/dashboard/summary` - Executive summary
- `GET /api/v1/dashboard/manufacturer-rankings` - Security rankings
- `GET /api/v1/dashboard/vulnerability-trends` - Trend analysis
- `GET /api/v1/dashboard/risk-distribution` - Risk histogram
- `GET /api/v1/dashboard/compliance-mapping` - NIST/ISO/IEC mapping
- `GET /api/v1/dashboard/top-risk-devices` - Highest risk devices

### Integrations
- `GET /api/v1/webhooks` | `POST` | `DELETE` | `POST /{id}/test`
- `GET /api/v1/siem` | `POST`
- `GET /api/v1/ticketing` | `POST`
- `GET /api/v1/asset-management`
- `GET /api/v1/data-sources`
- `POST /api/v1/sync/nvd` - Trigger NVD sync
- `POST /api/v1/sync/ics-cert` - Trigger ICS-CERT sync

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Initialize and seed database
python run.py seed

# Start server
python run.py

# Run tests
python run.py test
```

Open http://localhost:8000 for dashboard or http://localhost:8000/docs for API docs.
