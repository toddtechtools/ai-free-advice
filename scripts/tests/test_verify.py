"""Regression checks for failure modes that could incorrectly permit release."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('verify', Path(__file__).resolve().parents[1]/'verify.py')
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base/'candidate with spaces'
        self.root.mkdir()
        self.logs = self.base/'logs'
        self.logs.mkdir()
        self.gate = mod.Gate(self.root, self.logs, .4, 20, .1)

    def tearDown(self):
        self.tmp.cleanup()

    def test_timeout_kills_child_group_and_preserves_log(self):
        pidfile = self.base/'pid'
        code = 'import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); open(sys.argv[1],"w").write(str(p.pid)); print("panic before hang",flush=True); time.sleep(60)'
        result = self.gate.run('hang', self.root, [sys.executable, '-c', code, str(pidfile)])
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('Timeout', result['reason'])
        self.assertTrue((self.logs/result['log']).is_file())
        self.assertEqual(len(result['log_sha256']), 64)
        pid = int(pidfile.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_diagnostic_above_tail_survives(self):
        result = self.gate.run('failure', self.root, [sys.executable,'-c','print("Error: root cause"); print("detail\\n"*40); raise SystemExit(1)'])
        self.assertEqual(result['status'], 'FAIL')
        self.assertNotIn('Error: root cause', result['output_tail'])
        self.assertIn('Error: root cause', result['diagnostic_excerpt'][0]['text'])
        self.assertIn('Error: root cause', (self.logs/result['log']).read_text())

    def test_flaky_test_stays_fail(self):
        flag = self.base/'flag'
        code = 'from pathlib import Path; import sys; p=Path(sys.argv[1]); old=p.exists(); p.touch(); sys.exit(0 if old else 1)'
        self.gate.run('test', self.root, [sys.executable,'-c',code,str(flag)], retry=True)
        self.assertEqual([r['status'] for r in self.gate.rows], ['FAIL','FAIL'])
        self.assertIn('flaky', self.gate.rows[1]['reason'])
        self.assertEqual(len(list(self.logs.glob('*.log'))), 2)

    def test_missing_tool_is_hold(self):
        row = self.gate.run('missing', self.root, ['nonexistent-tool-971001'])
        self.assertEqual(row['status'], 'HOLD')
        self.assertIsNone(row['exit_code'])

    def test_argv_cannot_inject_shell(self):
        payload = '$(touch '+str(self.base/'BAD')+');`false`'
        row = self.gate.run('path', self.root, [sys.executable,'-c','import sys; print(sys.argv[1])',payload])
        self.assertEqual(row['status'], 'PASS')
        self.assertEqual(row['output_tail'], [payload])
        self.assertFalse((self.base/'BAD').exists())

    def test_discovery_includes_nested_modules_excludes_dependencies(self):
        for rel in ['a/go.mod','b/go.mod','node_modules/dep/go.mod']:
            path = self.root/rel
            path.parent.mkdir(parents=True,exist_ok=True)
            path.touch()
        paths = {str(p.relative_to(self.root)) for p in self.gate.files()}
        self.assertEqual(paths, {'a/go.mod','b/go.mod'})

    def test_checksum_traversal_and_symlink_fail(self):
        manifest = self.root/'SHA256SUMS'
        outside = self.base/'outside'
        outside.write_text('secret')
        manifest.write_text('0'*64+'  ../outside\n')
        self.gate.checksums(manifest)
        self.assertEqual(self.gate.rows[-1]['status'],'FAIL')
        (self.root/'link').symlink_to(outside)
        manifest.write_text('0'*64+'  link\n')
        self.gate.checksums(manifest)
        self.assertEqual(self.gate.rows[-1]['status'],'FAIL')

    def test_checksum_twice(self):
        artifact = self.root/'artifact.bin'
        artifact.write_text('content')
        manifest = self.root/'SHA256SUMS'
        manifest.write_text(mod.digest(artifact)+'  artifact.bin\n')
        self.gate.checksums(manifest)
        passes = [r for r in self.gate.rows if r['check'].startswith('sha256.pass')]
        self.assertEqual([r['status'] for r in passes], ['PASS','PASS'])
        self.assertEqual(self.gate.rows[-1]['check'],'sha256.coverage')

    def test_detached_descendant_fails_and_log_is_stable(self):
        child = 'import time; time.sleep(.15); print("late output",flush=True); time.sleep(60)'
        code = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c",sys.argv[1]], start_new_session=True)'
        row = self.gate.run('detached', self.root, [sys.executable,'-c',code,child])
        self.assertEqual(row['status'],'FAIL')
        self.assertIn('descendants',row['reason'])
        self.assertFalse(self.gate.descendants())
        self.assertEqual(mod.digest(self.logs/row['log']),row['log_sha256'])

    def test_supervisor_exception_keeps_attempt_record(self):
        real = self.gate.stop
        calls = []
        def cleanup(proc):
            real(proc)
            calls.append(1)
            raise RuntimeError('injected supervisor failure')
        self.gate.stop = cleanup
        row = self.gate.run('cleanup',self.root,[sys.executable,'-c','import time; time.sleep(60)'])
        self.assertTrue(calls)
        self.assertEqual(row['status'],'FAIL')
        self.assertEqual(row['check'],'cleanup')
        self.assertIn('injected supervisor failure',row['reason'])
        self.assertTrue(row['command'])
        self.assertTrue((self.logs/row['log']).is_file())

    def test_normalized_checksum_duplicates_fail(self):
        artifact = self.root/'x'
        artifact.write_text('x')
        sha = mod.digest(artifact)
        manifest = self.root/'SHA256SUMS'
        manifest.write_text(sha+'  x\n'+sha+'  ./x\n')
        self.gate.checksums(manifest)
        self.assertEqual(self.gate.rows[-1]['status'],'FAIL')
        self.assertIn('duplicate',self.gate.rows[-1]['reason'])

    def test_large_log_line_summary_is_bounded(self):
        row = self.gate.run('large',self.root,[sys.executable,'-c','print("Error: "+"x"*2000000)'])
        self.assertEqual(row['status'],'PASS')
        self.assertLessEqual(len(row['output_tail'][0]),4096)
        self.assertLessEqual(len(row['diagnostic_excerpt'][0]['text']),4096)
        self.assertGreater((self.logs/row['log']).stat().st_size,2000000)

    def test_sigterm_retains_ledger_and_kills_active_command(self):
        bindir = self.base/'bin'
        bindir.mkdir()
        marker = self.base/'started'
        ruff = bindir/'shellcheck'
        ruff.write_text('#!/usr/bin/env python3\nimport os,time\nfrom pathlib import Path\nPath('+repr(str(marker))+').write_text(str(os.getpid()))\ntime.sleep(60)\n')
        ruff.chmod(0o755)
        (self.root/'check.sh').write_text('#!/bin/sh\ntrue\n')
        out = self.base/'terminated.json'
        wrapper = Path(__file__).resolve().parents[1]/'verify.sh'
        proc = subprocess.Popen(['bash',str(wrapper),str(self.root),'--out',str(out),'--grace','.1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=dict(os.environ,PATH=str(bindir)+os.pathsep+os.environ['PATH']))
        import time
        end = time.monotonic()+5
        while not marker.exists() and time.monotonic()<end:
            time.sleep(.02)
        self.assertTrue(marker.exists())
        proc.send_signal(signal.SIGTERM)
        stdout,stderr = proc.communicate(timeout=5)
        self.assertNotEqual(proc.returncode,0,stderr)
        ledger = json.loads(out.read_text())
        self.assertTrue(ledger['partial'])
        self.assertTrue(any(r['status']=='FAIL' and 'Interrupted' in r['reason'] for r in ledger['gates']))
        with self.assertRaises(ProcessLookupError):
            os.kill(int(marker.read_text()),0)

    def test_sigterm_during_hash_retains_attempt(self):
        old_handler = signal.signal(signal.SIGTERM,lambda *args: setattr(self.gate,'interrupted',True))
        real = mod.digest
        fired = []
        def interrupt(path, deadline=None):
            if not fired:
                fired.append(1)
                os.kill(os.getpid(),signal.SIGTERM)
            return real(path,deadline)
        mod.digest = interrupt
        try:
            row = self.gate.run('hash-interrupt',self.root,[sys.executable,'-c','print("done")'])
        finally:
            mod.digest = real
            signal.signal(signal.SIGTERM,old_handler)
        self.assertEqual(row['status'],'FAIL')
        self.assertTrue(row['command'])
        self.assertEqual(row['exit_code'],0)
        self.assertTrue((self.logs/row['log']).exists())
        self.assertTrue(self.gate.interrupted)

    def test_budget_exhaustion_is_hold(self):
        self.gate.deadline = 0
        row = self.gate.run('remaining', self.root, [sys.executable,'-c','pass'])
        self.assertEqual(row['status'],'HOLD')

    def test_cli_emits_retained_nonzero_partial_ledger(self):
        out = self.base/'ledger.json'
        wrapper = Path(__file__).resolve().parents[1]/'verify.sh'
        proc = subprocess.run(['bash',str(wrapper),str(self.root),'--out',str(out),'--timeout','2','--grace','.1'],capture_output=True,text=True,timeout=20)
        self.assertEqual(proc.returncode,1,proc.stderr)
        ledger = json.loads(out.read_text())
        self.assertEqual(ledger['decision'],'NOT READY')
        self.assertGreater(ledger['counts']['HOLD'],0)
        evidence = Path(ledger['evidence_directory'])
        self.assertTrue(evidence.is_dir())
        self.assertEqual(sum(ledger['counts'].values()),len(ledger['gates']))
        for row in ledger['gates']:
            if row.get('log_sha256'):
                self.assertEqual(mod.digest(evidence/row['log']),row['log_sha256'])
        again = subprocess.run(['bash',str(wrapper),str(self.root),'--out',str(out)],capture_output=True,text=True,timeout=5)
        self.assertNotEqual(again.returncode,0)
        self.assertEqual(json.loads(out.read_text()),ledger)


if __name__ == '__main__':
    unittest.main()
