# 010: Red Team Scan Tiers

## Status
Accepted

## Context
The dashboard red team UI had two hardcoded buttons: "Quick Test" (10 probes) and
"Full Scan" (315 probes). The probe counts were hardcoded strings that didn't
reflect the actual installed garak version. Users had no middle ground between
a minimal smoke test and a multi-hour full scan.

## Decision
Replace with three dynamically-populated tiers:

- **Quick Scan**: Core injection families only (promptinject, latentinjection, dan).
  Active probes only. Tests the attacks most relevant to prompt injection defense.
- **Standard Scan**: All active garak probes. The recommended default — covers
  injection, encoding, exfiltration, jailbreaks, and content safety.
- **Full Sweep**: All probes including inactive ones (Full variants with larger
  payload sets). Comprehensive but slow.

Probe counts are pulled from garak's plugin registry at request time, so they
stay accurate across garak upgrades. We count probe classes (fast enumerate),
not individual payloads (requires instantiation which downloads data/models).

## Consequences
- UI always shows accurate counts for the installed garak version
- Users can choose appropriate depth for their testing needs
- Backend needs `/api/redteam/tiers` endpoint
- Red team runner `_get_probe_payloads()` must accept a tier parameter
  to dynamically select probes from garak instead of using a hardcoded list
