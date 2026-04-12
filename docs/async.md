# Async Support

Pipeline supports both sync and async callables. Use `run_async()` for async execution.

```python
result = await pipeline.run_async("untrusted content", source="email")
```

Both `analyze_fn` and `execute_fn` can be sync or async — Bulwark detects and handles both:

```python
async def my_async_analyze(prompt: str) -> str:
    response = await client.messages.create(...)
    return response.content[0].text

pipeline = Pipeline.default(analyze_fn=my_async_analyze)
result = await pipeline.run_async(content, source="email")
```

Mixed sync/async works too:

```python
pipeline = Pipeline.default(
    analyze_fn=sync_function,      # sync
    execute_fn=async_function,     # async
)
result = await pipeline.run_async(content, source="email")
```
