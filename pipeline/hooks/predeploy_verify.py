#!/usr/bin/env python3
"""Pre-deploy verification for scan artifacts and commit integrity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path



def compute_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(8192), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_checksums(path: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        parts = line.split('  ', 1)
        if len(parts) != 2:
            continue
        mapping[parts[1].strip()] = parts[0].strip()
    return mapping


def verify_scan(checksums: dict[str, str], artifacts_dir: Path) -> None:
    scan_path = artifacts_dir / 'scan.json'
    if not scan_path.exists():
        raise SystemExit('scan.json missing in artifacts')
    expected = checksums.get('scan.json')
    if not expected:
        raise SystemExit('scan.json checksum missing in checksums.txt')
    actual = compute_sha256(scan_path)
    if actual != expected:
        raise SystemExit('scan.json checksum mismatch')


def verify_commit(expected_commit: str) -> None:
    env_commit = os.getenv('SOURCE_COMMIT') or os.getenv('CODEPIPELINE_RESOLVED_SOURCE_VERSION') or os.getenv('CODEBUILD_RESOLVED_SOURCE_VERSION')
    if env_commit != expected_commit:
        raise SystemExit(f'Commit mismatch: expected {expected_commit}, got {env_commit}')


def main() -> None:
    parser = argparse.ArgumentParser(description='Verify scan artifact integrity before deploy')
    parser.add_argument('--checksums', required=True, type=Path)
    parser.add_argument('--artifacts-dir', required=True, type=Path)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()

    checksums = load_checksums(args.checksums)
    verify_scan(checksums, args.artifacts_dir)
    verify_commit(args.commit)

    print('Pre-deploy verification passed.')


if __name__ == '__main__':
    main()
