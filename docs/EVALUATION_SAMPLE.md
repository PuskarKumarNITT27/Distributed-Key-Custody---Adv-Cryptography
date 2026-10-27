# Evaluation run record

- Command: `python -m keycustody.evaluate`
- Python: 3.13.5
- Platform: Linux-6.18.55-x86_64-with-glibc2.41
- Setup: 10 in-process localhost TCP nodes; benchmark mean over 5 runs per configuration.
- Results are also in `results.md` and `results.json`.
- These are measurements from this execution environment, not universal performance claims.

# Evaluation results (localhost, 10 in-process nodes)

## Latency (mean of 5, ms)

| t | n | store | recover | refresh |
|---|---|---|---|---|
| 2 | 3 | 37 | 28 | 55 |
| 3 | 5 | 63 | 49 | 93 |
| 4 | 7 | 75 | 57 | 118 |
| 7 | 10 | 130 | 88 | 207 |

## Crash fault tolerance (t=4, n=7)

| nodes down | recovered | expected |
|---|---|---|
| 0 | True | True |
| 1 | True | True |
| 2 | True | True |
| 3 | True | True |
| 4 | False | False |
| 5 | False | False |
| 6 | False | False |
| 7 | False | False |

## Byzantine nodes returning corrupted shares (t=4, n=7)

| corrupt nodes | recovered |
|---|---|
| 0 | True |
| 1 | True |
| 2 | True |
| 3 | True |
| 4 | False |
