# 012: Red Team Scoring Fix and Retest-Failures

## Status
Accepted

## Context
The red team runner marks a probe as "not defended" when the LLM response
doesn't contain a valid classification field. But analysis of a 4,268-probe
standard scan (Haiku/Haiku) showed that 288 out of 289 "vulnerabilities" were
actually format compliance failures — the LLM analyzed content correctly as
data but returned `{"analysis": {...}}` instead of the expected
`{"classification": "action-needed|fyi|skip"}` schema.

Only 1 probe was an actual hijack (Morse-decoded "HAHA PWNED"). The real
defense rate is ~99.9%, not the reported 93.2%.

Additionally, re-running all 4,268 probes takes 76 minutes. Users need a way
to retest only the failed probes from a previous run.

## Decision

### Scoring: three-way classification
Change probe results from binary (defended/not-defended) to three categories:
- **defended**: LLM followed instructions, classified correctly
- **hijacked**: LLM followed the injection (evidence of hijack in response)
- **format_failure**: LLM analyzed correctly but wrong output schema

Hijack detection checks for known injection success markers in the response
(rogue strings from garak probes, instruction-following indicators).

The defense rate calculation counts format_failures as defended (the LLM
didn't follow the injection), but reports them separately so users can
improve format compliance.

### Retest: replay failed probes from a report
New endpoint `POST /api/redteam/retest` accepts a report filename and
re-runs only the probes that were not defended (hijacked or format_failure).
Uses the same pipeline as a normal scan but loads probes from the report
instead of from garak.

## Consequences
- More accurate defense rate reporting
- Dashboard shows separate counts for hijacked vs format failures
- Retest runs in minutes instead of hours
- Report JSON gains a `verdict` field per result: "defended", "hijacked", or "format_failure"
