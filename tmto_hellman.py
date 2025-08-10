"""
Hellman Time–Memory Tradeoff Demo

Features:
- Builds Hellman tables using truncated hashes for time–memory tradeoff attacks.
- Supports configurable number of tables, chains, chain length, and hash/message/truncate lengths.
- Allows selection of hash algorithm from those supported by hashlib.
- Uses multiprocessing for efficient parallel table construction and attack execution.
- Performs a configurable number of random-message attacks to attempt hash inversion.
- Saves results, timings, and configuration to a JSON output file.
- Supports progress bars and quiet mode for reduced output.
"""

import argparse
import dataclasses
import hashlib
import json
import logging
import multiprocessing
import os
import signal
import sys
import time
from datetime import datetime
from random import getrandbits
from typing import Dict, List, Optional, Tuple, Union

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
    """
    Computes the hash of the `data` using `hash_algorithm` and returns the last `truncate_length` bytes.

    :param data: Input data to hash.
    :type data: bytes
    :param hash_algorithm: Hash algorithm name (e.g., 'sha256', 'sha512').
    :type hash_algorithm: str
    :param truncate_length: Number of bytes to keep from the end of the hash.
    :type truncate_length: int
    :return: Truncated hash digest.
    :rtype: bytes
    """
    h = hashlib.new(hash_algorithm)
    h.update(data)
    digest = h.digest()
    return digest[-truncate_length:]


def apply_salt(r: bytes, x: bytes) -> bytes:
    """
    Applies the salt `r` to the input `x`.

    :param r: Salt value.
    :type r: bytes
    :param x: Input value.
    :type x: bytes
    :return: Salted input.
    :rtype: bytes
    """
    return r + x


def precompute_table(
    num_chains: int,
    chain_length: int,
    hash_algorithm: str,
    truncate_length: int,
    message_length: int,
) -> Tuple[Dict[bytes, bytes], bytes]:
    """
    Builds a Hellman table with the `num_chains` number of chains and `chain_length` chain length, using `hash_algorithm` and truncation.
    The salt length is chosen so that len(salt) + `truncate_length` = `message_length`.

    :param num_chains: Number of chains in the table.
    :type num_chains: int
    :param chain_length: Length of each chain.
    :type chain_length: int
    :param hash_algorithm: Hash algorithm name (e.g., 'sha256', 'sha512').
    :type hash_algorithm: str
    :param truncate_length: Number of bytes to keep from the end of the hash.
    :type truncate_length: int
    :param message_length: Length of random messages in bytes.
    :type message_length: int
    :return: Tuple containing the precomputed table (dict mapping final hash to initial value) and the salt used for the chains.
    :rtype: Tuple[Dict[bytes, bytes], bytes]
    """
    salt_len = message_length - truncate_length
    r = getrandbits(8 * salt_len).to_bytes(salt_len, "big")

    table = {}
    for _ in range(num_chains):
        x0 = getrandbits(8 * truncate_length).to_bytes(truncate_length, "big")
        xi = x0
        for _ in range(chain_length):
            xi = truncated_hash(
                apply_salt(r, xi), hash_algorithm, truncate_length
            )
        table[xi] = x0
    return table, r


def wrapper_precompute_table(
    task: Tuple[int, int, str, int, int],
) -> Tuple[Dict[bytes, bytes], bytes]:
    """
    Unpacks `task` for `precompute_table()`.

    :param task: Tuple of arguments for `precompute_table()`.
    :type task: Tuple[int, int, str, int, int]
    :return: Tuple containing the precomputed table (dict mapping final hash to initial value) and the salt used for the chains.
    :rtype: Tuple[Dict[bytes, bytes], bytes]
    """
    return precompute_table(*task)


def build_tables(config: TMTOConfig) -> List[Tuple[Dict[bytes, bytes], bytes]]:
    """
    Builds multiple Hellman tables in parallel according to the `config`.

    :param config: TMTOConfig object containing configuration parameters.
    :type config: TMTOConfig
    :return: List of tuples, each containing a precomputed table (dict mapping final hash to initial value) and the salt used for the chains.
    :rtype: List[Tuple[Dict[bytes, bytes], bytes]]
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
                pool.imap_unordered(wrapper_precompute_table, tasks),
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
    Attempts to find a preimage x such that H(r||x) equals the target hash `h` using the Hellman tables.

    :param h: Target truncated hash to find a preimage for.
    :type h: bytes
    :param precomputed_tables: List of precomputed tables, each a tuple of (table, salt).
    :type precomputed_tables: List[Tuple[Dict[bytes, bytes], bytes]]
    :param chain_length: Length of each chain.
    :type chain_length: int
    :param hash_algorithm: Hash algorithm name (e.g., 'sha256', 'sha512').
    :type hash_algorithm: str
    :param truncate_length: Number of bytes to keep from the end of the hash.
    :type truncate_length: int
    :return: Tuple containing the found preimage and the number of steps taken to find it, or None if no preimage is found.
    :rtype: Optional[Tuple[bytes, int]]
    """
    cur = [h] * len(precomputed_tables)
    for j in range(chain_length):
        for table_idx, (table, r) in enumerate(precomputed_tables):
            y = cur[table_idx]
            if y in table:
                x = table[y]
                for _ in range(chain_length - j - 1):
                    x = truncated_hash(
                        apply_salt(r, x), hash_algorithm, truncate_length
                    )
                    if (
                        truncated_hash(
                            apply_salt(r, x), hash_algorithm, truncate_length
                        )
                        == h
                    ):
                        return (apply_salt(r, x), j)
            else:
                cur[table_idx] = truncated_hash(
                    apply_salt(r, y),
                    hash_algorithm,
                    truncate_length,
                )
    return None


def perform_attack(
    precomputed_tables: List[Tuple[Dict[bytes, bytes], bytes]],
    chain_length: int,
    hash_algorithm: str,
    truncate_length: int,
    message_length: int,
) -> Optional[Dict[str, Union[str, int]]]:
    """
    Performs a single attack attempt on a random message using the Hellman tables.

    :param precomputed_tables: List of precomputed tables, each a tuple of (table, salt).
    :type precomputed_tables: List[Tuple[Dict[bytes, bytes], bytes]]
    :param chain_length: Length of each chain.
    :type chain_length: int
    :param hash_algorithm: Hash algorithm name (e.g., 'sha256', 'sha512').
    :type hash_algorithm: str
    :param truncate_length: Number of bytes to keep from the end of the hash.
    :type truncate_length: int
    :param message_length: Length of random messages in bytes.
    :type message_length: int
    :return: Dictionary containing the original message, its hash, the found preimage, and the number of steps taken to find it, or None if no preimage is found.
    :rtype: Optional[Dict[str, Union[str, int]]]
    """
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


def wrapper_perform_attack(
    task: Tuple[List[Tuple[Dict[bytes, bytes], bytes]], int, str, int, int],
) -> Optional[Dict[str, Union[str, int]]]:
    """
    Unpacks `task` for `perform_attack()`.

    :param task: Tuple of arguments for `perform_attack()`.
    :type task: Tuple[List[Tuple[Dict[bytes, bytes], bytes]], int, str, int, int]
    :return: Dictionary containing the original message, its hash, the found preimage, and the number of steps taken to find it, or None if no preimage is found.
    :rtype: Optional[Dict[str, Union[str, int]]]
    """
    return perform_attack(*task)


def run_attacks(
    precomputed_tables: List[Tuple[Dict[bytes, bytes], bytes]],
    config: TMTOConfig,
    start_time: float,
) -> None:
    """
    Runs multiple attack attempts in parallel and saves results to the output file.

    :param precomputed_tables: List of precomputed tables, each a tuple of (table, salt).
    :type precomputed_tables: List[Tuple[Dict[bytes, bytes], bytes]]
    :param config: TMTOConfig object containing configuration parameters.
    :type config: TMTOConfig
    :param start_time: Start time of the attack process, used to calculate total attack time.
    :type start_time: float
    :return: None
    :rtype: None
    """
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
                pool.imap_unordered(wrapper_perform_attack, tasks),
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
                attack_time = time.time() - start_time
                data["attack_time"] = attack_time
                data["results"] = results
                data["preimages_found"] = len(results)

                output_file.seek(0)
                json.dump(data, output_file, indent=2)
                output_file.truncate()

            if interrupted:
                sys.exit(1)


def validate_arguments(parser: argparse.ArgumentParser) -> TMTOConfig:
    """
    Validates command-line arguments and returns a TMTOConfig object.

    :param parser: Argument parser instance to validate arguments against.
    :type parser: argparse.ArgumentParser
    :return: TMTOConfig object containing validated configuration parameters.
    :rtype: TMTOConfig
    """
    args = parser.parse_args()
    positive_entries = {
        "K": "num_chains",
        "T": "num_tables",
        "A": "num_attacks",
        "L": "chain_length",
        "m": "message_length",
    }

    # Check that all positive arguments are greater than 0
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
    """
    Set up and validate command-line arguments.

    :return: TMTOConfig object containing validated configuration parameters.
    :rtype: TMTOConfig
    """
    parser = argparse.ArgumentParser(
        description="Hellman time-memory tradeoff attack demo",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-K",
        "--chains",
        dest="num_chains",
        type=int,
        metavar="K",
        default=2**12,
        help="Number of chains per Hellman table (K > 0).",
    )
    parser.add_argument(
        "-T",
        "--tables",
        dest="num_tables",
        type=int,
        metavar="T",
        default=1,
        help="Number of Hellman tables to build (T > 0).",
    )
    parser.add_argument(
        "-A",
        "--attacks",
        dest="num_attacks",
        type=int,
        metavar="A",
        default=10000,
        help="Number of random-message attack attempts to perform (A > 0).",
    )
    parser.add_argument(
        "-L",
        "--chain-length",
        dest="chain_length",
        type=int,
        metavar="L",
        default=2**6,
        help="Length of each chain in the Hellman tables (L > 0).",
    )
    parser.add_argument(
        "-m",
        "--message-length",
        dest="message_length",
        type=int,
        metavar="m",
        default=32,
        help="Length in bytes of each random message and hash input (m > 0).",
    )
    parser.add_argument(
        "-t",
        "--truncate-length",
        dest="truncate_length",
        type=int,
        metavar="t",
        default=2,
        help="Number of bytes to keep from the end of each hash digest (0 <= t < m).",
    )
    parser.add_argument(
        "-w",
        "--workers",
        dest="max_workers",
        type=int,
        metavar="w",
        default=None,
        help="Number of worker processes for parallel table building and attacks (w > 0, defaults to CPU count).",
    )
    parser.add_argument(
        "-a",
        "--algorithm",
        dest="hash_algorithm",
        choices=hashlib.algorithms_available,
        metavar="a",
        default="sha512",
        help="Hash algorithm to use for all hashing (any supported by hashlib).",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        type=str,
        metavar="PATH",
        default=f"tmto_hellman_{datetime.now().strftime('%Y-%m-%d_%H.%M.%S')}.json",
        help="Path to output file for saving results.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        dest="quiet_mode",
        action="store_true",
        help="Suppress progress bars and extra output.",
    )

    return validate_arguments(parser)


def main():
    config = setup_argparse()

    logging.basicConfig(
        level=logging.INFO if not config.quiet_mode else logging.WARNING,
        format="%(message)s",
    )

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
        json.dump(output_template, output_file, indent=2)

    # Precomputation
    start_time = time.time()
    precomputed_tables = build_tables(config)
    precomp_time = time.time() - start_time

    with open(config.output, "r+") as output_file:
        data = json.load(output_file)
        data["precomputation_time"] = precomp_time

        output_file.seek(0)
        json.dump(data, output_file, indent=2)
        output_file.truncate()

    logging.info(
        f"Built {config.num_tables} table(s) [algorithm={config.hash_algorithm}, truncate-length={config.truncate_length}] in {precomp_time:.2f}s"
    )

    # Attacks
    start_time = time.time()
    run_attacks(precomputed_tables, config, start_time)

    with open(config.output, "r") as output_file:
        data = json.load(output_file)
        preimages_found = data["preimages_found"]
        attack_time = data["attack_time"]

    logging.info(
        f"Attacks: {preimages_found}/{config.num_attacks} succeeded in {attack_time:.2f}s"
    )


if __name__ == "__main__":
    main()
