# Runtime benchmark

This benchmark measures the incremental cost of governance layers rather than
external model or network latency. The OPA scenario uses the real `OPAClient`
and `OPAMiddleware` parsing path with an in-process transport so results remain
reproducible; live OPA latency belongs to the integration suite.

Run the reliability matrix:

```bash
python benchmarks/benchmark_runtime.py \
  --requests 100,500,1000,5000 \
  --concurrency 100 \
  --output benchmarks/results/latest.json
```

The output records environment metadata, throughput, mean latency, p50/p95/p99
latency, and peak traced memory for:

- no middleware;
- one deterministic rule;
- rule plus OPA;
- rule plus OPA plus audit;
- rule plus OPA plus audit plus OpenTelemetry;
- ten pass-through gating middleware.

The output also records mean and p50/p95/p99 admission wait latency while
multiple tasks contend for a single FIFO runtime permit. The default zero-hold
case yields once per owner to isolate admission handoff and scheduling from
tool latency. This
isolates bulkhead scheduling behavior from tool and middleware latency.

The v0.5 release evidence is committed as
`results/v0.5.0-windows-python312.json`. Treat it as a regression baseline for
the recorded environment, not as a general service-level objective.

Results are not treated as universal performance claims. Compare runs on the
same pinned environment and investigate regressions in both tail latency and
memory before release.
