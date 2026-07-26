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
- a strict read-only runtime without an action contract;
- the same strict runtime with bind and executor-boundary action verification.

The output also records mean and p50/p95/p99 admission wait latency while
multiple tasks contend for a single FIFO runtime permit. The default zero-hold
case yields once per owner, isolating bulkhead scheduling behavior from tool
and middleware latency.

The v0.5 release evidence is committed as
`results/v0.5.0-windows-python312.json`. Treat it as a regression baseline for
the recorded environment, not as a general service-level objective.

The v0.6 budget compares the two strict scenarios from the same process and
run, reducing host-to-host noise while measuring the incremental bind and
verification cost. Validate a result with:

```bash
python scripts/check_benchmark_budget.py benchmarks/results/latest.json
```

Budget increases must be reviewed separately from the implementation that
exceeds them. A feature pull request may keep or tighten the committed budget;
it must not make its own regression pass by relaxing the threshold.

The committed Windows/Python 3.12 release-candidate run at 1,000 requests and
100-way concurrency measured the contracted scenario at 2.188x mean latency,
1.851x p95 latency, 1.760x p99 latency, and 1.049x peak traced memory relative
to its paired strict baseline. These ratios are point-in-time evidence from
`results/v0.6.0-rc-windows-python312.json`, not universal service claims.

Results are not treated as universal performance claims. Compare runs on the
same pinned environment and investigate regressions in both tail latency and
memory before release.
