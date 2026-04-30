# Calling /v1/clean from an async client

Bulwark v2 is a sync request/response detection service — every
`/v1/clean` is a single HTTP round-trip. The FastAPI / uvicorn server
serves concurrent requests natively. This page covers what an async
*client* needs to know.

## Async client example

```python
import httpx

async def clean(content: str, source: str = "external") -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "http://localhost:3000/v1/clean",
            json={"content": content, "source": source},
            timeout=30,
        )
        if resp.status_code == 422:
            raise RuntimeError(f"blocked: {resp.json().get('block_reason')}")
        if resp.status_code == 413:
            err = resp.json().get("error", {})
            raise RuntimeError(f"content_too_large: {err.get('message')}")
        if resp.status_code == 503:
            err = resp.json().get("error", {})
            if err.get("code") == "no_detectors_loaded":
                raise RuntimeError("Bulwark misconfigured: no detectors loaded (ADR-040)")
            raise RuntimeError(f"503: {err.get('message')}")
        resp.raise_for_status()
        return resp.json()
```

`/v1/clean` can return four codes a client must distinguish: 200
(cleaned), 422 (blocked, ADR-031), 413 (`content_too_large`, ADR-042),
and 503 (`no_detectors_loaded`, ADR-040). Treating 503 as a transient
5xx and retrying will mask a misconfiguration; surface it instead.

## Concurrent requests

Bulwark is a single-process FastAPI app. Multiple in-flight `/v1/clean`
requests are fine — the only contention is the detector model itself
(DeBERTa, PromptGuard) which serializes per-instance inference. For
high RPS, run multiple Bulwark workers behind a load balancer.

## Latency budget

| Detector       | Typical p50 | Notes                                |
|----------------|-------------|--------------------------------------|
| Sanitizer      | < 1 ms      | Pure-Python text manipulation.       |
| DeBERTa        | ~30 ms      | Single-batch inference on MPS/CPU.   |
| PromptGuard    | ~50 ms      | Same shape as DeBERTa.               |
| LLM Judge      | 1 – 3 s     | Network round-trip + LLM inference.  |

A long-tail input is chunked across the DeBERTa window (ADR-032) — expect
linear scaling in payload size.

## LLM judge mechanics

The judge call is a synchronous `httpx.Client(...)` round-trip from
within the FastAPI route handler — the request blocks until the judge
replies. There's no thread-pool offload. To parallelize across many
inputs, fan out from your application using `asyncio.gather` over
`httpx.AsyncClient.post('/v1/clean', ...)` rather than enabling the
judge for sequential calls.
