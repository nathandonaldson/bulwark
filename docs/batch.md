# Batch processing

There is no built-in batch endpoint. `/v1/clean` processes one input per
request — that's intentional. Detectors are stateless per request, so
batching at the HTTP layer would only complicate the contract.

## Recommended pattern

Hold concurrency on the client, one HTTP call per item:

```python
import asyncio
import httpx

async def clean_many(items: list[str]) -> list[dict]:
    async with httpx.AsyncClient() as client:
        async def one(text: str) -> dict:
            r = await client.post(
                "http://localhost:3000/v1/clean",
                json={"content": text, "source": "batch"},
                timeout=30,
            )
            return {"input": text, "status": r.status_code, "body": r.json()}
        return await asyncio.gather(*(one(t) for t in items))
```

## Why no `MapReduceIsolator`

v1 had a `MapReduceIsolator` for processing untrusted lists with cross-item
isolation. v2 removed it (ADR-031): isolation between inputs is what
`/v1/clean` already provides — every request is independent, and the
detectors share no state across calls. Iterate yourself with the snippet
above.

## Throughput

A single Bulwark worker serializes inference per-detector — single-process
throughput is detector-bound, so benchmark on your hardware (CPU vs GPU,
batch shape, model). Run multiple workers behind a load balancer for
higher throughput; each worker holds its own DeBERTa instance.
