# Hellman Time-Memory Tradeoff (TMTO) Demo
A simple, configurable script that builds Hellman-style time-memory tradeoff tables using truncated hashes and attempts randomized preimage attacks against those tables.
## How it works
A Hellman time-memory tradeoff (TMTO) precomputes many short chains of reduced hash values so later hash invertion queries are much faster. Instead of storing every `input -> hash` pair, the program stores only chain endpoints. During an attack it locates matching endpoint and then regenerates the corresponding chain to recover a candidate preimage.
### Overview - core idea
- Build many chains that cover parts of the reduced hash space.
- Save only each chain's endpoint -> start mapping.
- At query time, walk possible chain positions backwards to find an endpoint, then expand that chain forward to verify a true preimage.
### Steps
 
1. Truncated hash:  
    In a demo truncated suffixes (last `t` digest) of the actual hashes (`H(r || x)`) are used in order to reduce possible hash-bytes combinations.
2. Tables:  
    For each table a single salt `r` is randomly chosen to prevent table overlapping.
3. Chains:  
    Each chain start with random `x0` of `t` bytes from which following chain values are computed (`x_{i+1} = Trunc(H(r || x))`). After `L` steps final values is stored in the table mapping (`final -> x0`).
4. Attack:
    For a random message `message` the truncated hash `h` is computed.
    Using Hellman lookups the algorightm searches for a chain that could generate `h`. If an endpoint matches, the corresponding chain head `x0` is expanded forward to try to find the exact preimage. 
## Features
- Build multiple Hellman tables in parallel (`multiprocessing`).
- High number of configuration options.
- Progress bars (`tqdm`) with queit mode.
- Saves timings, configuration and results to a JSON output file.
## Requirements
Script need `tqdm` module for progress bars and should be installed with:  
`pip install tqdm`
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
```