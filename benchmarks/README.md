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

Results are not treated as universal performance claims. Compare runs on the
same pinned environment and investigate regressions in both tail latency and
memory before release.
