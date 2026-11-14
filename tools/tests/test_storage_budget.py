"""Bounded disk preflight: no process, game, or resource launch."""
import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from tools import storage_budget as api


class StorageBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)

    @staticmethod
    def usage(total, free):
        return shutil._ntuple_diskusage(total=total, used=total-free, free=free)

    def test_volume_floor_reserve_and_exact_boundary(self):
        usage = lambda _: self.usage(1000, 150)
        allowed = api.plan(self.path, 100, minimum_free_bytes=10, usage_reader=usage)
        blocked = api.plan(self.path, 101, minimum_free_bytes=10, usage_reader=usage)
        self.assertEqual(allowed['reserved_free_bytes'], 50)
        self.assertEqual(allowed['action'], 'ALLOW')
        self.assertEqual(blocked['action'], 'BLOCK')
        self.assertEqual(blocked['projected_free_bytes'], 49)
        self.assertFalse(allowed['evidence_complete_proved'])

    def test_ancestor_and_minimum_reserve(self):
        usage = lambda _: self.usage(1000, 550)
        result = api.plan(self.path/'new'/'case', 300, minimum_free_bytes=250, usage_reader=usage)
        self.assertEqual(result['measured_directory'], str(self.path))
        self.assertEqual(result['reserved_free_bytes'], 250)
        self.assertEqual(result['action'], 'ALLOW')
        self.assertTrue(result['low_space_warning'])

    def test_unknown_or_invalid_measurements_fail_closed(self):
        for usage in (self.usage(0, 0), self.usage(100, 101)):
            with self.subTest(usage=usage), self.assertRaises(ValueError):
                api.plan(self.path, 1, usage_reader=lambda _: usage)
        with self.assertRaises(OSError):
            api.plan(self.path, 1, usage_reader=lambda _: (_ for _ in ()).throw(OSError('unavailable')))
        for bad in (0, -1, True, 1.0):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                api.plan(self.path, bad)

    def test_dry_run_never_starts_child(self):
        with patch.object(api.subprocess, 'run', side_effect=AssertionError('must not run')), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            code = api.main(['--path', str(self.path), '--expected-bytes', '1'])
        self.assertEqual(code, 0)
        report = json.loads(out.getvalue())
        self.assertFalse(report['child_started'])
        self.assertTrue(report['dry_run'])

    def test_low_space_refuses_real_run_without_launch(self):
        with patch.object(api.shutil, 'disk_usage', return_value=self.usage(100, 5)), \
             patch.object(api.subprocess, 'run', side_effect=AssertionError('must not run')), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            # Patch the default-bound reader explicitly: real main calls plan.
            with patch.object(api, 'plan', side_effect=lambda p, e, minimum_free_bytes:
                    api_plan(p, e, minimum_free_bytes=minimum_free_bytes,
                        usage_reader=lambda _: self.usage(100, 5))):
                code = api.main(['--path', str(self.path), '--expected-bytes', '1',
                    '--run', '--', 'not-a-real-command'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())['action'], 'BLOCK')

    def test_allowed_run_preserves_argv_and_reports_unattributed_volume_change(self):
        calls = []
        def child(argv, *, shell, check):
            calls.append((argv, shell, check))
            return type('Child', (), {'returncode': 0})()
        measurements = iter([self.usage(1000, 900), self.usage(1000, 800)])
        def reader(_): return next(measurements)
        with patch.object(api, 'plan', side_effect=lambda p, e, minimum_free_bytes:
                api_plan(p, e, minimum_free_bytes=minimum_free_bytes, usage_reader=reader)), \
             patch.object(api.shutil, 'disk_usage', side_effect=reader), \
             patch.object(api.subprocess, 'run', side_effect=child), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            code = api.main(['--path', str(self.path), '--expected-bytes', '10',
                '--minimum-free-bytes', '50', '--run', '--', 'program', 'two words'])
        self.assertEqual(code, 0)
        self.assertEqual(calls, [(['program', 'two words'], False, False)])
        before, after = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(before['action'], 'ALLOW')
        self.assertEqual(after['volume_free_change_bytes'], -100)
        self.assertTrue(after['net_volume_drop_exceeds_estimate'])
        self.assertFalse(after['volume_change_attributable_to_child'])
        self.assertFalse(after['evidence_complete_proved'])

    def test_postrun_missing_measurement_is_not_success(self):
        good = lambda _: self.usage(1000, 900)
        with patch.object(api, 'plan', side_effect=lambda p, e, minimum_free_bytes:
                api_plan(p, e, minimum_free_bytes=minimum_free_bytes, usage_reader=good)), \
             patch.object(api.shutil, 'disk_usage', side_effect=OSError('unavailable')), \
             patch.object(api.subprocess, 'run', return_value=type('Child', (), {'returncode': 0})()), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            code = api.main(['--path', str(self.path), '--expected-bytes', '10',
                '--minimum-free-bytes', '50', '--run', '--', 'program'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue().splitlines()[-1])['action'], 'POST_RUN_SPACE_UNKNOWN')


api_plan = api.plan

if __name__ == '__main__':
    unittest.main()