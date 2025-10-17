# Hellman Time-Memory Tradeoff (TMTO) Demo
A simple, configurable CLI script that builds Hellman-style time-memory tradeoff tables using truncated hashes and attempts randomized preimage attacks against those tables.
## How it works
A Hellman time-memory tradeoff (TMTO) precomputes many short chains of reduced hash values so later hash inversion queries are much faster. Instead of storing every `input -> hash` pair, the program stores only chain endpoints. During an attack it locates matching endpoint and then regenerates the corresponding chain to recover a candidate preimage.
### Overview - core idea
- **Truncated hash:**  
Compute `Trunc(H(r || x))` by taking the last `t` bytes of the hash digest. Truncation reduces the effective search space to <code>N = 2<sup>8t</sup></code>, which increases the probability of collisions in the truncated space.
- **Tables:**  
Each table gets a random salt `r` (so `len(r) + t = m`). The salt reduces overlap between the portions of the space tables cover.
- **Chains:**  
Each chain starts with a random <code>x<sub>0</sub></code> of `t` bytes. Chain values are computed as <code>x<sub>i+1</sub> = Trunc(H(r || x<sub>i</sub>))</code>.  
After `L` steps final value is stored in the table as a mapping <code>x<sub>L</sub> -> x<sub>0</sub></code>.
- **Attack:**  
    1. Given a target message `message`, compute `h = Trunc(H(message))`.
    2. For each table, repeatedly compute the next chain value from `h` using table's salt `r` (treating `h` as if it could be part of a chain) and check each value against the table's endpoints. Continue up to `L` steps or until value matches a known endpoint.
    3. For a matching endpoint, expand the chain forward from stored <code>x<sub>0</sub></code> to find message that produces `h`.
## Features
- Build multiple Hellman tables in parallel (`multiprocessing`).
- High number of configuration options.
- Progress bars (`tqdm`) with queit mode.
- Saves timings, configuration and results to a JSON output file (even if interrupted).
## Requirements
Script need `tqdm` module for progress bars and should be installed with:  
```markdown
pip install tqdm
```
## Usage
```markdown
usage: tmto_hellman.py [-h] [-K K] [-T T] [-A A] [-L L] [-m m] [-t t] [-w w] [-a a] [-o PATH] [-q]

Hellman time-memory tradeoff attack demo

options:
  -h, --help            show this help message and exit
  -K K, --chains K      Number of chains per Hellman table (K > 0). (default: 4096)
  -T T, --tables T      Number of Hellman tables to build (T > 0). (default: 1)
  -A A, --attacks A     Number of random-message attack attempts to perform (A > 0). (default: 10000)
  -L L, --chain-length L
                        Length of each chain in the Hellman tables (L > 0). (default: 64)
  -m m, --message-length m
                        Length in bytes of each random message and hash input (m > 0). (default: 32)
  -t t, --truncate-length t
                        Number of bytes to keep from the end of each hash digest (0 <= t < m). 
                        (default: 2)
  -w w, --workers w     Number of worker processes for parallel table building and attacks (w > 0,                    
                        defaults to CPU count). (default: None)
  -a a, --algorithm a   Hash algorithm to use for all hashing (any supported by hashlib).             
                        (default: sha512)
  -o PATH, --output PATH
                        Path to output file for saving results. 
                        (default: tmto_hellman_YYYY-MM-DD_hh.mm.ss.json)
  -q, --quiet           Suppress progress bars and extra output. (default: False)
```
## Output format
```markdown
{
  "arguments": {
    "--num-chains": 4096,
    "--num-tables": 1,
    "--num-attacks": 10000,
    "--chain-length": 64,
    "--message-length": 32,
    "--truncate": 2,
    "--workers": null,
    "--algorithm": "sha512",
    "--output": "tmto_hellman_YYYY-MM-DD_hh.mm.ss.json",
    "--quiet": false
  },
  "precomputation_time": 0.8716628551483154,
  "attack_time": 51.340028285980225,
  "preimages_found": 529,
  "results": [
    {
      "message": "702dc85b415653e2be9b5d66068fe4fe47f96f579776fdcfb8f3ae205b4ad2e9",
      "hash": "8e3b",
      "preimage": "99d9174972f1eb53db0f2cd99779e28ac5e86fe40002f63f1785752edd9c37c8",
      "steps": 27
    },
    ...
  ]
}
```
## License
MIT License &copy; 2025 Yurii Ptashnyk