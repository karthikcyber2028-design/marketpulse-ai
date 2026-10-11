=====================================================================
 SELF-HEALING SOC AGENT v2 - COMPLETE WORKING GOOGLE COLAB PACKAGE
=====================================================================

CONTENTS
--------
  Self_Healing_SOC_Complete_Working.ipynb   <- upload this to Google Colab
  vscode_backend_reference/main.py          <- same backend, for your VS Code project
  README.txt                                <- this file

The notebook was built around a fully smoke-tested backend (16/16
endpoint checks passed: JWT login, RBAC, event generation, ML analysis,
MITRE mapping, self-healing, PDF reports, dashboard).

QUICK START (GOOGLE COLAB)
--------------------------
 1. Go to https://colab.research.google.com
 2. File -> Upload notebook -> select Self_Healing_SOC_Complete_Working.ipynb
 3. Runtime -> Run all   (or run cells top-to-bottom)
 4. In the "Open the complete SOC dashboard" step the dashboard appears
    INSIDE the notebook. If the frame is ever blank, open the printed
    "Dashboard URL" in a new browser tab.

DEMO LOGINS
-----------
  admin   / Admin@12345    (full access)
  analyst / Analyst@12345  (detect + heal)
  viewer  / Viewer@12345   (read-only - RBAC blocks actions)

WHAT IT INCLUDES
----------------
  - FastAPI backend + SQLite (runs on port 8000 inside Colab)
  - JWT authentication with roles: admin / analyst / viewer (RBAC)
  - 3 simulated endpoint agents: EDGE-01, EDGE-02, EDGE-03
  - Synthetic security events: login, brute_force, port_scan,
    suspicious_process, malware, dos, data_exfiltration
  - ML anomaly detection: Isolation Forest (statistical z-score fallback)
  - Risk scoring 0-100 with bands low/medium/high/critical
  - Explainable AI: per-event driver features (z-scores) in plain English
  - MITRE ATT&CK mapping (T1110, T1046, T1059, T1204, T1498, T1041, T1078)
  - Automatic incident creation for high/critical alerts
  - Simulated self-healing playbooks:
    Containment -> Healing -> Validation -> resolved (validated=true)
  - PDF incident reports (reportlab) with full response timeline
  - Single-page SOC dashboard served at /dashboard

NOTEBOOK STEPS AT A GLANCE
--------------------------
 Step 1  install dependencies (~30 s)
 Step 2  write backend application
 Step 3  start API on port 8000 ("API running")
 Step 4  open dashboard (in-notebook IFrame)
 Step 5  JWT login check incl. RBAC proof
 Step 6  generate telemetry from EDGE-01/02/03
 Step 7  analyze: ML -> risk -> explanation -> MITRE
 Step 8  incidents + self-healing simulation
 Step 9  download PDF report
 Step 10 (optional) train on your own CSV -> soc_model.joblib
 Step 11 (optional) temporary public URL via Cloudflare tunnel

TROUBLESHOOTING
---------------
 Problem                              Fix
 ----------------------------------  --------------------------------------
 port already in use / health fails   Runtime -> Restart session, then Run all
 dashboard frame blank                open printed Dashboard URL in new tab
 401 after long pause                 tokens expire after 12 h; rerun Step 5
 slow first cell                      normal, pip install takes ~30-60 s

VS CODE INTEGRATION (for the full final-year version)
-----------------------------------------------------
 1. Copy vscode_backend_reference/main.py into your VS Code project
    (e.g. backend/app/main.py).
 2. Optional: train on CIC-IDS2017 / UNSW-NB15 in Colab (Step 10),
    download soc_model.joblib and place it in backend/app/ml/.
 3. The scoring logic reads mean/std from that file, so any model you
    export with the same schema drops straight in.

DISCLAIMER
----------
 All events, detections and healing actions are SIMULATED.
 No real systems, hosts or networks are modified. Educational use only.
