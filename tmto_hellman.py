"""
Hellman Time–Memory Tradeoff Demo

Builds Hellman tables with truncated hashes and then attempts to invert
random hashes via a time–memory tradeoff attack. Uses multiprocessing
for both table construction and attack.
"""

# TODO: refactor code
# annotations; change print() to logging()
import argparse
import dataclasses
import hashlib
import json
import multiprocessing
import os
import signal
import sys
import time
from datetime import datetime
from random import getrandbits
from typing import Dict, List, Optional, Tuple

from tqdm.auto import tqdm


@dataclasses.dataclass
class TMTOConfig:
    num_chains: int
    num_tables: int
    num_attacks: int
    chain_length: int
    message_length: int
    truncate_length: int
    max_workers: Optional[int]
    hash_algorithm: str
    output: str
    quiet_mode: bool


def truncated_hash(
    data: bytes, hash_algorithm: str, truncate_length: int
) -> bytes:
    """Compute hash with algorithm `hash_algorithm` on `data` and return last `truncate_length` bytes."""
    h = hashlib.new(hash_algorithm)
    h.update(data)
    digest = h.digest()
    return digest[-truncate_length:]


def redundancy_function(r: bytes, x: bytes) -> bytes:
    """Reduction: prepend the salt `r` to input `x`."""
    return r + x


def precompute_table(
    num_chains: int,
    chain_length: int,
    hash_algorithm: str,
    truncate_length: int,
    message_length: int,
) -> Tuple[Dict[bytes, bytes], bytes]:
    """
    Build one Hellman table of `num_chains` chains (length `chain_length`) using `hash_algorithm` and truncate to `truncate_length` bytes.
    Salt length is chosen so that len(r) + `truncate_length` = `message_length`.
    """
    salt_len = message_length - truncate_length
    r = getrandbits(8 * salt_len).to_bytes(salt_len, "big")

    table = {}
    for _ in range(num_chains):
        x0 = getrandbits(8 * truncate_length).to_bytes(truncate_length, "big")
        xi = x0
        for _ in range(chain_length):
            xi = truncated_hash(
                redundancy_function(r, xi), hash_algorithm, truncate_length
            )
        table[xi] = x0
    return table, r


def precompute_table_wrapper(
    task: Tuple[int, int, str, int, int],
) -> Tuple[Dict[bytes, bytes], bytes]:
    """Unpacks `task` for `precompute_table()`."""
    return precompute_table(*task)


def build_tables(config: TMTOConfig) -> List[Tuple[Dict[bytes, bytes], bytes]]:
    """
    Build `tables` Hellman tables in parallel using original functions.
    Returns list of (table, salt).
    """
    tasks = [
        (
            config.num_chains,
            config.chain_length,
            config.hash_algorithm,
            config.truncate_length,
            config.message_length,
        )
    ] * config.num_tables

    old_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    with multiprocessing.Pool(processes=config.max_workers) as pool:
        signal.signal(signal.SIGINT, old_handler)
        results = []

        try:
            for table in tqdm(
                pool.imap_unordered(precompute_table_wrapper, tasks),
                total=config.num_tables,
                desc="Building tables",
                disable=config.quiet_mode,
            ):
                results.append(table)
        except KeyboardInterrupt:
            pool.terminate()
            pool.join()
            sys.exit(1)

    return results


def search_preimage(
    h: bytes,
    precomputed_tables: List[Tuple[Dict[bytes, bytes], bytes]],
    chain_length: int,
    hash_algorithm: str,
    truncate_length: int,
) -> Optional[Tuple[bytes, int]]:
    """
    Try to find x such that H(r||x)=`h` using Hellman tables.

    :param h: Description
    :type h: bytes
    :param precomputed_tables: Description
    :type precomputed_tables: list[tuple[dict[bytes, bytes], bytes]]
    :param chain_length: Description
    :type chain_length: int
    :param hash_algorithm: Description
    :type hash_algorithm: str
    :param truncate_length: Description
    :type truncate_length: int
    :return: Description
    :rtype: tuple[bytes, int] | None
    """
    cur = [h] * len(precomputed_tables)
    for j in range(chain_length):
        for idx, (tbl, r) in enumerate(precomputed_tables):
            y = cur[idx]
            if y in tbl:
                x0 = tbl[y]
                x = x0
                for _ in range(chain_length - j - 1):
                    x = truncated_hash(
                        redundancy_function(r, x),
                        hash_algorithm,
                        truncate_length,
                    )
                    if (
                        truncated_hash(
                            redundancy_function(r, x),
                            hash_algorithm,
                            truncate_length,
                        )
                        == h
                    ):
                        return (redundancy_function(r, x), j)
            else:
                cur[idx] = truncated_hash(
                    redundancy_function(r, y), hash_algorithm, truncate_length
                )
    return None


def perform_attack(
    precomputed_tables: List[Tuple[Dict[bytes, bytes], bytes]],
    chain_length: int,
    hash_algorithm: str,
    truncate_length: int,
    message_length: int,
) -> Optional[Dict[str, str | int]]:
    """Perform one random-message attack trial."""
    message = getrandbits(8 * message_length).to_bytes(message_length, "big")
    h = truncated_hash(message, hash_algorithm, truncate_length)
    found = search_preimage(
        h, precomputed_tables, chain_length, hash_algorithm, truncate_length
    )
    if found:
        preimage, steps = found
        return {
            "message": message.hex(),
            "hash": h.hex(),
            "preimage": preimage.hex(),
            "steps": steps,
        }
    return None


def perform_attack_wrapper(
    task: Tuple[List[Tuple[Dict[bytes, bytes], bytes]], int, str, int, int],
) -> Optional[Dict[str, str | int]]:
    """
    Docstring for perform_attack_wrapper

    :param task: Description
    :type task: tuple[list[tuple[dict[bytes, bytes], bytes]], int, str, int, int]
    :return: Description
    :rtype: dict[str, Any] | None
    """
    return perform_attack(*task)


def run_attacks(
    precomputed_tables: List[Tuple[Dict[bytes, bytes], bytes]],
    config: TMTOConfig,
):
    """Perform `attacks` attack(s) and return list of results."""
    tasks = [
        (
            precomputed_tables,
            config.chain_length,
            config.hash_algorithm,
            config.truncate_length,
            config.message_length,
        )
    ] * config.num_attacks

    interrupt_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    with multiprocessing.Pool(processes=config.max_workers) as pool:
        signal.signal(signal.SIGINT, interrupt_handler)
        results = []
        interrupted = False

        try:
            for attack in tqdm(
                pool.imap_unordered(perform_attack_wrapper, tasks),
                total=config.num_attacks,
                desc="Attacking",
                disable=config.quiet_mode,
            ):
                if attack:
                    results.append(attack)
        except KeyboardInterrupt:
            interrupted = True
            pool.terminate()
            pool.join()
        finally:
            with open(config.output, "r+") as output_file:
                data = json.load(output_file)
                data["results"] = results
                data["preimages_found"] = len(results)
                json.dump(data, output_file, indent=4)

            if interrupted:
                sys.exit(1)


def validate_arguments(parser: argparse.ArgumentParser) -> TMTOConfig:
    """Validate CLI arguments."""
    args = parser.parse_args()
    positive_entries = {
        "K": "num_chains",
        "T": "num_tables",
        "A": "num_attacks",
        "L": "chain_length",
        "m": "message_length",
    }

    for short_name, name in positive_entries.items():
        arg = getattr(args, name)
        if arg <= 0:
            parser.error(
                f"argument --{name.replace('_', '-')}: invalid value: {arg} (choose {short_name} > 0)",
            )

    h = hashlib.new(args.hash_algorithm)
    h.update(getrandbits(8).to_bytes(1, "big"))
    digest = h.digest()
    if args.truncate_length > len(digest):
        parser.error(
            f"argument --truncate-length: invalid value: {args.truncate_length} (choose t < {len(digest)})",
        )
    if args.truncate_length < 0:
        parser.error(
            f"argument --truncate-length: invalid value: {args.truncate_length} (choose t >= 0)",
        )
    if args.truncate_length > args.message_length:
        parser.error(
            f"argument --truncate-length: invalid value: {args.truncate_length} (choose t < m)",
        )

    if args.max_workers is not None and args.max_workers <= 0:
        parser.error(
            f"argument --workers: invalid value: {args.max_workers} (choose w > 0)",
        )

    if args.output:
        output_dir = os.path.dirname(args.output) or "."

        if not os.path.exists(output_dir):
            parser.error(
                f"argument --output: invalid path: directory '{output_dir}' doesn't exist",
            )

        if not os.access(output_dir, os.W_OK):
            parser.error(
                f"argument --output: invalid path: no write permission for directory '{output_dir}'"
            )

        if os.path.exists(args.output):
            parser.error(
                f"argument --output: invalid path: output file '{args.output}' already exists"
            )

    return TMTOConfig(**vars(args))


def setup_argparse() -> TMTOConfig:
    parser = argparse.ArgumentParser(
        description="Hellman time-memory tradeoff attack demo",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-K",
        "--chains",
        dest="num_chains",
        type=int,
        default=2**12,
        help="number of chains",
    )
    parser.add_argument(
        "-T",
        "--tables",
        dest="num_tables",
        type=int,
        default=1,
        help="number of tables",
    )
    parser.add_argument(
        "-A",
        "--attacks",
        dest="num_attacks",
        type=int,
        default=10000,
        help="number of attack attempts",
    )
    parser.add_argument(
        "-L",
        "--chain-length",
        dest="chain_length",
        type=int,
        default=2**6,
        help="chain length",
    )
    parser.add_argument(
        "-m",
        "--message-length",
        dest="message_length",
        type=int,
        default=32,
        help="length of random-messages in bytes",
    )
    parser.add_argument(
        "-t",
        "--truncate-length",
        dest="truncate_length",
        type=int,
        default=2,
        help="number of bytes to truncate from digest",
    )
    parser.add_argument(
        "-w",
        "--workers",
        dest="max_workers",
        type=int,
        default=None,
        help="number of worker processes to use for table building/attack (defaults to CPU count)",
    )
    parser.add_argument(
        "-a",
        "--algorithm",
        dest="hash_algorithm",
        choices=hashlib.algorithms_available,
        default="sha512",
        help="hash algorithm (any supported by hashlib)",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        type=str,
        metavar="PATH",
        default=f"tmto_hellman_{datetime.now().strftime('%Y-%m-%d_%H.%M.%S')}.json",
        help="Path to output file where results will be saved",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        dest="quiet_mode",
        action="store_true",
        help="suppress progress bars and extra output",
    )

    return validate_arguments(parser)


def main():
    config = setup_argparse()

    output_template = {
        "arguments": {
            "--num-chains": config.num_chains,
            "--num-tables": config.num_tables,
            "--num-attacks": config.num_attacks,
            "--chain-length": config.chain_length,
            "--message-length": config.message_length,
            "--truncate": config.truncate_length,
            "--workers": config.max_workers,
            "--algorithm": config.hash_algorithm,
            "--output": config.output,
            "--quiet": config.quiet_mode,
        },
        "precomputation_time": None,
        "attack_time": None,
        "preimages_found": None,
        "results": [],
    }

    with open(config.output, "w") as output_file:
        json.dump(output_template, output_file, indent=4)

    # Precomputation
    start_time = time.time()
    precomputed_tables = build_tables(config)
    precomp_time = time.time() - start_time

    with open(config.output, "r+") as output_file:
        data = json.load(output_file)
        data["precomputation_time"] = precomp_time

        output_file.seek(0)
        json.dump(data, output_file, indent=4)
        output_file.truncate()
    if not config.quiet_mode:
        print(
            f"Built {config.num_tables} table(s) [algo={config.hash_algorithm}, trunc={config.truncate_length}] in {precomp_time:.2f}s"
        )

    # Attacks
    start_time = time.time()
    run_attacks(precomputed_tables, config)
    attack_time = time.time() - start_time

    with open(config.output, "r") as output_file:
        data = json.load(output_file)
        preimages_found = data["preimages_found"]
    if not config.quiet_mode:
        print(
            f"Attacks: {preimages_found}/{config.num_attacks} succeeded in {attack_time:.2f}s"
        )


if __name__ == "__main__":
    main()
