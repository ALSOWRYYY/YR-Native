"""Read-only disk reserve preflight with an explicit opt-in command wrapper.

The preflight itself writes and deletes nothing; a command passed to --run may
perform its ordinary changes. Free-space readings are point-in-time volume
observations, not allocation or a hard quota. Wrap only authorized commands.
Existing test runners retain integrity, evidence-loss, and output-budget checks.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

GIB = 1024 ** 3
DEFAULT_MINIMUM = 10 * GIB


def nearest_existing_directory(path):
    if not path.is_absolute():
        raise ValueError('path must be absolute')
    path = Path(os.path.abspath(path))
    while not path.exists():
        parent = path.parent
        if parent == path:
            raise ValueError('path has no existing directory ancestor')
        path = parent
    if not path.is_dir():
        raise ValueError('the output path or nearest existing ancestor is not a directory')
    return path


def plan(path, expected_bytes, *, minimum_free_bytes=DEFAULT_MINIMUM, usage_reader=shutil.disk_usage):
    """Fail closed when disk information or a positive output estimate is unavailable."""
    if type(expected_bytes) is not int or expected_bytes <= 0:
        raise ValueError('a positive expected output allocation in bytes is required')
    if type(minimum_free_bytes) is not int or minimum_free_bytes < 0:
        raise ValueError('minimum free bytes must be nonnegative')
    directory = nearest_existing_directory(Path(path))
    usage = usage_reader(directory)
    total, free = usage.total, usage.free
    if type(total) is not int or type(free) is not int or total <= 0 or not 0 <= free <= total:
        raise ValueError('disk free-space measurement unavailable or invalid')
    reserve = max(minimum_free_bytes, (total + 19) // 20)
    projected = free - expected_bytes
    allowed = projected >= reserve
    return dict(schema='yr-storage-budget-v1', action='ALLOW' if allowed else 'BLOCK',
        requested_path=str(path), measured_directory=str(directory),
        volume_total_bytes=total, volume_free_bytes=free,
        estimated_new_allocated_bytes=expected_bytes, reserved_free_bytes=reserve,
        projected_free_bytes=projected,
        low_space_warning=projected < 2 * reserve,
        estimate_is_caller_supplied=True, reading_is_point_in_time=True,
        command_output_location_enforced=False, per_process_quota_enforced=False,
        evidence_complete_proved=False)


def positive_int(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('expected a positive integer') from exc
    if number <= 0:
        raise argparse.ArgumentTypeError('expected a positive integer')
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--path', required=True, type=Path,
        help='absolute target output directory, or its yet-to-be-created child')
    parser.add_argument('--expected-bytes', required=True, type=positive_int,
        help='conservative allocated-byte estimate for this entire operation')
    parser.add_argument('--minimum-free-bytes', type=positive_int, default=DEFAULT_MINIMUM,
        help='minimum free-space reserve; default 10 GiB, with a 5%% volume floor')
    parser.add_argument('--run', action='store_true', help='run the command after -- only if preflight allows')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command
    if command and command[0] == '--':
        command = command[1:]
    if args.run and not command:
        parser.error('--run requires a command after --')
    if command and not args.run:
        parser.error('a command is accepted only with --run')
    try:
        result = plan(args.path, args.expected_bytes, minimum_free_bytes=args.minimum_free_bytes)
    except (OSError, ValueError) as exc:
        print(json.dumps(dict(schema='yr-storage-budget-v1',action='BLOCK',
            error=type(exc).__name__+': '+str(exc),child_started=False)))
        return 2
    result.update(child_started=False, dry_run=not args.run)
    print(json.dumps(result), flush=True)
    if result['action'] != 'ALLOW':
        return 2
    if not args.run:
        return 0
    try:
        child = subprocess.run(command, shell=False, check=False)
    except OSError as exc:
        print(json.dumps(dict(schema='yr-storage-budget-v1',action='LAUNCH_ERROR',
            error=type(exc).__name__+': '+str(exc),child_started=False)), flush=True)
        return 2
    try:
        current = shutil.disk_usage(Path(result['measured_directory']))
        if type(current.free) is not int or not 0 <= current.free <= current.total:
            raise ValueError('invalid final free-space reading')
        after = current.free
        status = 'POST_RUN_LOW_SPACE' if after < result['reserved_free_bytes'] else 'POST_RUN_OBSERVED'
        observation_error = None
    except (OSError, ValueError) as exc:
        after = None
        status = 'POST_RUN_SPACE_UNKNOWN'
        observation_error = type(exc).__name__+': '+str(exc)
    net_drop_exceeds_estimate = (None if after is None else
        result['volume_free_bytes'] - after > result['estimated_new_allocated_bytes'])
    print(json.dumps(dict(schema='yr-storage-budget-v1',action=status,child_started=True,
        child_returncode=child.returncode,volume_free_after_bytes=after,
        volume_free_change_bytes=None if after is None else after-result['volume_free_bytes'],
        net_volume_drop_exceeds_estimate=net_drop_exceeds_estimate,
        volume_change_attributable_to_child=False,evidence_complete_proved=False,
        observation_error=observation_error)), flush=True)
    if child.returncode != 0:
        return child.returncode if child.returncode > 0 else 1
    return 0 if status == 'POST_RUN_OBSERVED' else 2


if __name__ == '__main__':
    raise SystemExit(main())