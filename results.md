# Evaluation results (localhost, 10 in-process nodes)

## Latency (mean of 5, ms)

| t | n | store | recover | refresh |
|---|---|---|---|---|
| 2 | 3 | 53 | 41 | 75 |
| 3 | 5 | 81 | 63 | 128 |
| 4 | 7 | 119 | 82 | 183 |
| 7 | 10 | 200 | 132 | 311 |

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
