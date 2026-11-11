# Benchmarks

Local measurements, not a production capacity claim.

| Test | Result |
|---|---:|
| Detection | 1,788,290 inputs/s |
| Generation | 243,926 hashes/s |
| Dictionary crack (no rules) | 32,021 words/s |
| Dictionary crack (rules) | 859,663 candidates/s |

```text
CPU threads: 12
Wordlist: 7,776 words
Rules: 35 variants/word
Detection: 0.0112s for 20,000 inputs
Generation: 0.9839s for 20,000 plaintexts
Crack (no rules): 0.2428s
Crack (rules): 0.3166s
```
