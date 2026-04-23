# Async Usage

Bulwark v2 is a stateless detection service. Concurrency is handled by the
client — the HTTP API itself is FastAPI / uvicorn, so it already serves
concurrent requests.

## Calling /v1/clean from an async client

```python
import httpx

async def clean(content: str, source: str = "external") -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "http://localhost:3001/v1/clean",
            json={"content": content, "source": source},
            timeout=30,
        )
        if resp.status_code == 422:
            raise RuntimeError(f"blocked: {resp.json().get('block_reason')}")
        resp.raise_for_status()
        return resp.json()
```

## Concurrent requests

Bulwark is a single-process, async-capable FastAPI app. Multiple in-flight
`/v1/clean` requests are fine — the only contention is the detector model
itself (DeBERTa, PromptGuard) which serializes per-instance inference. For
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

## Async LLM judge

The LLM judge is invoked from inside `/v1/clean` synchronously (in a thread)
so the request stays linear from the caller's perspective. If you want
parallel client-side judging across many inputs, do it from your application
with `asyncio.gather` over `httpx.AsyncClient.post('/v1/clean', ...)`.
