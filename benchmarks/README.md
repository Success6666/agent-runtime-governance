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
run. Each strict scenario is sampled three times in alternating order and each
reported metric is the median of those samples. This reduces order, thermal,
and transient host noise while measuring the incremental bind and verification
cost. `--paired-repetitions` accepts a positive odd override. Validate a result
with:

```bash
python scripts/check_benchmark_budget.py benchmarks/results/latest.json
```

Budget increases must be reviewed separately from the implementation that
exceeds them. A feature pull request may keep or tighten the committed budget;
it must not make its own regression pass by relaxing the threshold.

The committed final Windows/Python 3.12 run at 1,000 requests and 100-way
concurrency measured the contracted scenario at 1.553x mean latency, 1.720x
p95 latency, 1.850x p99 latency, and 1.040x peak traced memory relative to its
strict baseline. Each value is the median of three alternating paired samples.
These ratios are point-in-time evidence from
`results/v0.6.0-windows-python312.json`, not universal service claims. The
earlier pre-release record remains in
`results/v0.6.0-rc-windows-python312.json` for comparison.

Results are not treated as universal performance claims. Compare runs on the
same pinned environment and investigate regressions in both tail latency and
memory before release.

## Extension-dispatch matrix

The v0.8 dispatch matrix exercises the Runtime-owned extension boundary with
paired local callbacks: a native coroutine using `asyncio.sleep` and a legacy
synchronous callback using `time.sleep`. It intentionally makes no network
calls. Each pair uses the same interpreter and host, runs in alternating order,
and reports the median of an odd number of repetitions.

Run the CI-sized matrix locally:

```bash
python benchmarks/benchmark_runtime.py \
  --skip-runtime-matrix \
  --dispatch-matrix \
  --dispatch-requests-per-cell 20 \
  --paired-repetitions 3 \
  --output benchmarks/results/extension-dispatch.json

python scripts/check_benchmark_budget.py \
  benchmarks/results/extension-dispatch.json \
  --budget benchmarks/budgets/v0.8.0-extension-dispatch.json
```

The default dispatch cells cover 5 ms, 20 ms, and 50 ms synthetic I/O at
concurrency 1, 16, 100, and 500. Each cell records end-to-end p50/p95/p99 and
mean latency, throughput, traced peak memory, event-loop lag percentiles,
callback queue-wait percentiles, process/extension worker thread peaks, and
dispatcher worker, executor-queue, and admission-waiter peaks.

The budget compares legacy sync results against the native async result from
the same cell, not against an external service-level objective. Limits widen
only with the configured four-worker queue depth; this catches unexpected
scheduler or allocation regressions without treating a synthetic local sleep
as a production latency promise. Change the budget only in a separate reviewed
change with new same-host evidence.
