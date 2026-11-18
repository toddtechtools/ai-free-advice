#!/usr/bin/env python3
"""Bounded, evidence-preserving verification. Standard library only."""
import argparse
import collections
import ctypes
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

EXCLUDE = {'.git', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__',
           '.pytest_cache', '.ruff_cache', '.mypy_cache', 'dist', 'build', '.next'}
DIAGNOSTIC = re.compile(r'FAIL|Error|panic|warning|Traceback|fatal', re.I)


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def digest(path, deadline=None):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError('Budget exhausted reading evidence')
            h.update(block)
    return h.hexdigest()


class Gate:
    def __init__(self, root, evidence, timeout, budget, grace):
        self.root, self.evidence = root, evidence
        self.timeout, self.grace = timeout, grace
        self.deadline = time.monotonic() + budget
        self.rows, self.versions, self.exclusions = [], {}, []
        self.interrupted = False
        self.supervision = False
        if sys.platform.startswith('linux') and Path('/proc/self/status').is_file():
            try:
                # Adopt orphaned descendants, including children that detach sessions.
                libc = ctypes.CDLL(None, use_errno=True)
                self.supervision = libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
            except (OSError, AttributeError):
                pass
        self.baseline = set()
        self.proc_pid = int(Path('/proc/self/stat').read_text().split()[0]) if self.supervision else 0
        self.pid_index = 0
        if self.supervision:
            ns = next(line.split()[1:] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('NSpid:'))
            self.pid_index = len(ns)-1

    def scope(self, path):
        return str(path.relative_to(self.root)) or '.'

    def row(self, check, cwd, status, reason, **fields):
        row = dict(check=check, scope=self.scope(cwd), status=status,
                   reason=reason, exit_code=None, command=[], **fields)
        self.rows.append(row)
        return row

    def run(self, check, cwd, argv, retry=False, env=None):
        """Every subprocess uses this supervisor, including probes and retries."""
        if self.interrupted or time.monotonic() >= self.deadline:
            return self.row(check, cwd, 'HOLD', 'Run interrupted or total budget exhausted')
        if not self.supervision:
            return self.row(check, cwd, 'HOLD', 'Linux /proc child-subreaper supervision unavailable')
        tool = shutil.which(argv[0])
        if not tool:
            return self.row(check, cwd, 'HOLD', 'Required tool unavailable: ' + argv[0])
        attempt = 1
        while True:
            n = len(self.rows) + 1
            log = self.evidence / ('%04d.log' % n)
            start, then = utc(), time.monotonic()
            limit = min(self.timeout, max(0.01, self.deadline - then))
            status, reason, rc, proc = 'FAIL', '', None, None
            try:
                self.baseline = set()
                self.baseline = set(self.descendants())
                with log.open('xb') as output:
                    proc = subprocess.Popen(argv, cwd=cwd, stdout=output,
                                            stderr=subprocess.STDOUT, start_new_session=True,
                                            env=dict(os.environ, **(env or {})))
                    try:
                        end = time.monotonic()+limit
                        while True:
                            if self.interrupted:
                                raise KeyboardInterrupt
                            remaining = end-time.monotonic()
                            if remaining <= 0:
                                raise subprocess.TimeoutExpired(argv,limit)
                            try:
                                rc = proc.wait(timeout=min(.1,remaining))
                                break
                            except subprocess.TimeoutExpired:
                                continue
                        status = 'PASS' if rc == 0 else 'FAIL'
                        reason = 'Command completed' if rc == 0 else 'Command returned nonzero'
                    except subprocess.TimeoutExpired:
                        reason = 'Timeout after %.3fs' % limit
                        self.stop(proc)
                        rc = proc.returncode
                    except KeyboardInterrupt:
                        self.interrupted = True
                        reason = 'Interrupted after launch'
                        self.stop(proc)
                        rc = proc.returncode
                    if self.descendants():
                        self.stop(proc)
                        status, reason = 'FAIL', reason + '; background descendants terminated'
            except (Exception, KeyboardInterrupt) as exc:
                if isinstance(exc, KeyboardInterrupt):
                    self.interrupted = True
                reason = 'Launch/supervision/evidence failure: ' + str(exc)
                status = 'FAIL'
                if proc is not None:
                    try:
                        self.stop(proc)
                    except Exception as cleanup:
                        reason += '; cleanup failed: ' + str(cleanup)
            tail, matches, count = [], [], 0
            try:
                last = collections.deque(maxlen=25)
                with log.open(errors='replace') as stream:
                    lineno, summary, diagnostic = 1, '', None
                    while True:
                        if self.interrupted:
                            raise InterruptedError('Interrupted during evidence processing')
                        if time.monotonic() >= self.deadline:
                            raise TimeoutError('Budget exhausted processing log')
                        chunk = stream.readline(65536)
                        if not chunk:
                            break
                        summary += chunk[:max(0, 4096-len(summary))]
                        match = DIAGNOSTIC.search(chunk)
                        if match and diagnostic is None:
                            diagnostic = chunk[max(0,match.start()-100):match.start()+3996].rstrip('\n')
                        if chunk.endswith('\n'):
                            last.append(summary.rstrip('\n'))
                            if diagnostic is not None:
                                count += 1
                                if len(matches) < 80:
                                    matches.append({'line':lineno,'text':diagnostic})
                            lineno, summary, diagnostic = lineno+1, '', None
                    if summary:
                        last.append(summary)
                        if diagnostic is not None:
                            count += 1
                            if len(matches) < 80:
                                matches.append({'line':lineno,'text':diagnostic})
                tail, sha = list(last), digest(log, self.deadline)
            except (OSError, KeyboardInterrupt) as exc:
                if isinstance(exc, KeyboardInterrupt):
                    self.interrupted = True
                status, reason, sha = 'FAIL', reason + '; required evidence incomplete: ' + str(exc), None
            if self.interrupted:
                status, reason = 'FAIL', reason + '; interrupted before attempt finalized'
            row = self.row(check, cwd, status, reason, attempt=attempt,
                           log=log.name, log_sha256=sha, output_tail=tail,
                           diagnostic_excerpt=matches, diagnostic_matches=count,
                           diagnostic_truncated=max(0, count-len(matches)), summary_line_max_chars=4096,
                           start_utc=start, end_utc=utc(), duration_s=time.monotonic()-then,
                           timeout_s=limit, termination_grace_s=self.grace)
            row.update(command=argv, command_display=shlex.join(argv), exit_code=rc)
            if attempt == 2 and status == 'PASS':
                row.update(status='FAIL', reason='FAIL (flaky): diagnostic retry passed')
            if not (retry and attempt == 1 and status == 'FAIL' and rc is not None
                    and rc > 0 and rc not in (124, 137) and reason == 'Command returned nonzero'
                    and not self.interrupted and time.monotonic() < self.deadline):
                return row
            attempt += 1

    def descendants(self):
        parents, found, namespace = {}, {}, {}
        for path in Path('/proc').iterdir():
            if not path.name.isdigit():
                continue
            try:
                stat = (path/'stat').read_text()
                fields = stat[stat.rfind(')')+2:].split()
                parents[int(path.name)] = (int(fields[1]), fields[0])
                ns = next(line.split()[1:] for line in (path/'status').read_text().splitlines() if line.startswith('NSpid:'))
                if len(ns) > self.pid_index:
                    namespace[int(path.name)] = int(ns[self.pid_index])
            except (OSError, ValueError, IndexError, StopIteration):
                continue
        ancestors = {self.proc_pid}
        while True:
            added = {pid for pid,(parent,state) in parents.items()
                     if parent in ancestors and pid not in ancestors}
            if not added:
                break
            ancestors |= added
        for pid in ancestors - {self.proc_pid}:
            if pid not in namespace:
                raise RuntimeError('Cannot map descendant PID namespace')
            visible = namespace[pid]
            if visible not in self.baseline:
                found[visible] = parents[pid][1]
        return found

    def stop(self, proc):
        def terminate(sig):
            for pid in self.descendants():
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                pass

        terminate(signal.SIGTERM)
        end = time.monotonic() + self.grace
        while time.monotonic() < end:
            proc.poll()
            self.reap(proc.pid)
            if not self.descendants():
                break
            time.sleep(min(.02, max(0,end-time.monotonic())))
        terminate(signal.SIGKILL)
        proc.wait(timeout=1)
        # Reap adopted grandchildren; do not hash logs while descendants can write.
        end = time.monotonic()+1
        while self.descendants() and time.monotonic() < end:
            terminate(signal.SIGKILL)
            self.reap(proc.pid)
            time.sleep(.01)
        if self.descendants():
            raise RuntimeError('Descendant cleanup could not be verified')

    def reap(self, leader):
        for pid in self.descendants():
            if pid != leader:
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass

    def probe(self, tool, args):
        if tool not in self.versions:
            row = self.run('tool.version.' + tool, self.root, [tool] + args)
            self.versions[tool] = dict(status=row['status'], output=row.get('output_tail', []))
        return self.versions[tool]['status'] == 'PASS'

    def files(self):
        files = []
        for base, dirs, names in os.walk(self.root, followlinks=False,
                                        onerror=lambda e: self.row('scope.discovery', self.root, 'HOLD', str(e))):
            parent = Path(base)
            kept = []
            for name in sorted(dirs):
                path = parent / name
                if name in EXCLUDE or path.is_symlink():
                    self.exclusions.append(dict(path=self.scope(path), reason='Dependency/generated/Git directory or symlink'))
                else:
                    kept.append(name)
            dirs[:] = kept
            for name in sorted(names):
                path = parent / name
                if path.is_symlink():
                    self.row('scope.symlink', parent, 'HOLD', 'Unverified symlink: ' + self.scope(path))
                elif path.is_file():
                    files.append(path)
            if time.monotonic() >= self.deadline:
                self.row('scope.discovery', self.root, 'HOLD', 'Total budget exhausted during discovery')
                break
        return files

    def snapshot(self, files):
        result = {}
        for path in files:
            if time.monotonic() >= self.deadline:
                self.row('candidate.manifest', self.root, 'HOLD', 'Budget exhausted hashing source')
                break
            try:
                result[self.scope(path)] = digest(path, self.deadline)
            except OSError as exc:
                self.row('candidate.manifest', self.root, 'HOLD', str(exc))
        return result

    def gates(self, files):
        gos = sorted({p.parent for p in files if p.name == 'go.mod'})
        for cwd in gos:
            self.probe('go', ['version'])
            for name, args in [('verify', ['mod', 'verify']), ('build', ['build', './...']),
                               ('vet', ['vet', './...'])]:
                self.run('go.'+name, cwd, ['go']+args)
            env = self.run('go.environment', cwd, ['go', 'env', 'CGO_ENABLED', 'GOOS', 'GOARCH', 'CC'])
            values = env.get('output_tail', [])
            compiler = shlex.split(values[3]) if len(values) == 4 else []
            if env['status'] != 'PASS' or len(values) != 4 or values[0] != '1' or not compiler or not shutil.which(compiler[0]):
                self.row('go.race', cwd, 'HOLD', 'CGO/compiler prerequisite unavailable or unverified')
            else:
                self.probe(compiler[0], ['--version'])
                self.run('go.race', cwd, ['go', 'test', '-race', '-count=1', './...'])
            for tool in ('staticcheck', 'govulncheck'):
                self.probe(tool, ['-version'])
                self.run('go.'+tool, cwd, [tool, './...'])
        for p in files:
            if p.name == 'go.work':
                self.row('go.workspace', p.parent, 'HOLD', 'Workspace member/integration coverage requires project plan')
        if not gos:
            self.row('go', self.root, 'SKIP', 'No first-party go.mod discovered')

        pyroots = {p.parent for p in files if p.name == 'pyproject.toml' or p.match('requirements*.txt')}
        pys = [p for p in files if p.suffix == '.py']
        if pys or pyroots:
            # Environment provenance cannot be inferred from an active venv or global tools.
            for cwd in sorted(pyroots or {self.root}):
                self.row('python.dependencies', cwd, 'HOLD', 'Declared reproducible environment requires project-specific evidence; Python checks blocked')
                for name in ('ruff', 'pyright', 'pytest'):
                    self.row('python.'+name, cwd, 'HOLD', 'Blocked by python.dependencies')
        else:
            self.row('python', self.root, 'SKIP', 'No Python sources or declarations discovered')

        for suffix, tool in [('.sh', 'shellcheck'), ('.spec', 'rpmlint')]:
            targets = [p for p in files if p.suffix == suffix]
            if targets:
                self.probe(tool, ['--version'])
                for p in targets:
                    self.run(tool, p.parent, [tool, str(p)])
            else:
                self.row(tool, self.root, 'SKIP', 'No applicable '+suffix+' files')

        packages = [p for p in files if p.name == 'package.json']
        # Safe default: never modify the supplied candidate with npm ci automatically.
        # Agent prepares an isolated candidate, then reruns with explicit --prepare-node.
        for p in packages:
            cwd = p.parent
            try:
                raw, size = [], 0
                with p.open('rb') as stream:
                    while True:
                        chunk = stream.read(65536)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > 8*1024*1024 or time.monotonic() >= self.deadline:
                            raise ValueError('package.json exceeds size or budget limit')
                        raw.append(chunk)
                data = json.loads(b''.join(raw))
                if not isinstance(data,dict):
                    raise ValueError('package.json must be an object')
            except (OSError, ValueError) as exc:
                self.row('node.manifest', cwd, 'FAIL', str(exc))
                continue
            blocked = None
            if data.get('workspaces') or any(q.parent in cwd.parents for q in packages):
                blocked = 'Workspace dependency ownership/coverage requires project-specific plan'
            elif data.get('packageManager', 'npm').split('@')[0] != 'npm':
                blocked = 'Declared package manager requires project-specific frozen-lock preparation'
            elif not (cwd/'package-lock.json').is_file() and not (cwd/'npm-shrinkwrap.json').is_file():
                blocked = 'Committed npm lockfile required'
            elif not self.prepare_node:
                blocked = 'Run --prepare-node only in an isolated candidate; existing node_modules is insufficient'
            if blocked:
                self.row('node.dependencies', cwd, 'HOLD', blocked)
            else:
                self.probe('npm', ['--version'])
                install = self.run('node.dependencies', cwd, ['npm', 'ci'], env={'CI': 'true'})
                if install['status'] != 'PASS':
                    blocked = 'Blocked by node.dependencies'
            scripts = data.get('scripts', {})
            for name in ('build', 'lint', 'test'):
                if blocked:
                    self.row('node.'+name, cwd, 'HOLD', blocked)
                elif not isinstance(scripts.get(name), str) or not scripts[name].strip():
                    self.row('node.'+name, cwd, 'HOLD', 'Script missing; applicability requires project decision')
                elif re.search(r'\b(echo|true)\b|--watch|--passWithNoTests', scripts[name]):
                    self.row('node.'+name, cwd, 'HOLD', 'Script coverage/watch/no-op semantics require review')
                else:
                    self.run('node.'+name, cwd, ['npm', 'run', name], retry=(name == 'test'), env={'CI': 'true'})
        if not packages:
            self.row('node', self.root, 'SKIP', 'No package.json discovered')

        sums = [p for p in files if p.name == 'SHA256SUMS' or p.suffix == '.sha256']
        for p in sums:
            self.checksums(p)
        if not sums:
            self.row('sha256', self.root, 'SKIP', 'No checksum manifests discovered')
        self.probe('git', ['--version'])
        git = self.run('git.identity', self.root, ['git', 'rev-parse', '--show-toplevel'])
        if git['status'] == 'PASS':
            self.run('git.candidate', self.root, ['git', 'status', '--porcelain=v1', '--untracked-files=all'])
            self.run('git.commit', self.root, ['git', 'rev-parse', 'HEAD'])
            self.run('git.submodules', self.root, ['git', 'submodule', 'status', '--recursive'])
            self.probe('gitleaks', ['version'])
            self.run('security.secrets.files', self.root, ['gitleaks', 'dir', '--redact', '--no-banner', '.'])
            self.run('security.secrets.history', self.root, ['gitleaks', 'git', '--redact', '--no-banner', '.'])
        elif any((self.root/part).exists() for part in ('.git',)):
            self.row('security.secrets', self.root, 'HOLD', 'Git identity unavailable')
        else:
            # Non-Git exit is not a failed verification command.
            if git.get('exit_code') == 128:
                git.update(status='SKIP', reason='Not a Git tree; file manifest identifies candidate')
            self.row('security.secrets.history', self.root, 'SKIP', 'No Git history')
            self.probe('gitleaks', ['version'])
            self.run('security.secrets.files', self.root, ['gitleaks', 'dir', '--redact', '--no-banner', '.'])

    def checksums(self, manifest):
        try:
            seen = set()
            with manifest.open() as stream:
                lines = []
                total = 0
                while True:
                    line = stream.readline(8193)
                    if not line:
                        break
                    total += len(line)
                    if len(line) > 8192 or total > 16*1024*1024 or time.monotonic() >= self.deadline:
                        raise ValueError('Manifest exceeds size, path-length or budget limit')
                    lines.append(line.rstrip('\n'))
            for line in lines:
                match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *](.+)', line)
                if not match:
                    raise ValueError('Malformed checksum manifest entry')
                name = match[2]
                path = Path(name)
                target = manifest.parent/path
                if path.is_absolute() or '..' in path.parts or str(target.resolve()) in seen:
                    raise ValueError('Unsafe or duplicate manifest path: '+name)
                if not target.resolve().is_relative_to(manifest.parent.resolve()) or not target.is_file():
                    raise ValueError('Missing or escaping checksum target: '+name)
                seen.add(str(target.resolve()))
            if not seen:
                raise ValueError('Empty checksum manifest')
        except (OSError, ValueError) as exc:
            self.row('sha256.paths', manifest.parent, 'FAIL', str(exc))
            return
        self.probe('sha256sum', ['--version'])
        for attempt in (1, 2):
            self.run('sha256.pass%d'%attempt, manifest.parent, ['sha256sum', '-c', manifest.name])
        self.row('sha256.coverage', manifest.parent, 'HOLD', 'Required release file inventory and portable naming require review')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', nargs='?', default='.')
    parser.add_argument('--out', help='New ledger path outside project; never overwrite')
    parser.add_argument('--timeout', type=float, default=300)
    parser.add_argument('--budget', type=float, default=3600)
    parser.add_argument('--grace', type=float, default=10)
    parser.add_argument('--prepare-node', action='store_true', help='Allow npm ci in an isolated candidate')
    args = parser.parse_args()
    if min(args.timeout, args.budget, args.grace) <= 0 or not all(map(__import__('math').isfinite, (args.timeout,args.budget,args.grace))):
        parser.error('Timeout, budget, and grace must be finite and positive')
    root = Path(args.project).resolve()
    if not root.is_dir():
        parser.error('Project must be a directory')
    if args.out:
        out = Path(args.out).absolute()
        if out.exists() or out.is_relative_to(root) or out.parent.resolve().is_relative_to(root):
            parser.error('--out must be a new path outside the candidate')
        out.parent.mkdir(parents=True, exist_ok=True)
        evidence = Path(tempfile.mkdtemp(prefix=out.stem+'-evidence-', dir=out.parent))
    else:
        if Path(tempfile.gettempdir()).resolve().is_relative_to(root):
            parser.error('Default evidence path is inside candidate; use --out outside candidate')
        evidence = Path(tempfile.mkdtemp(prefix='verification-'))
        out = evidence/'ledger.json'
    os.chmod(evidence, 0o700)
    gate = Gate(root, evidence, args.timeout, args.budget, args.grace)
    gate.prepare_node = args.prepare_node
    first = {}
    def interrupted(signum, frame):
        # Defer interruption to supervisor polling so row finalization stays atomic.
        gate.interrupted = True
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        files = gate.files()
        first = gate.snapshot(files)
        gate.gates(files)
        last = gate.snapshot(gate.files())
        if first != last:
            gate.row('candidate.stability', root, 'FAIL', 'Candidate source changed during verification')
        else:
            gate.row('candidate.stability', root, 'PASS', 'Pre/post candidate manifests match')
        if (root/'waivers.toml').exists():
            gate.row('waivers.review', root, 'HOLD', 'Waivers require tracked-file, exact-candidate and authority validation; runner never auto-accepts')
        gate.row('workflow.completeness', root, 'HOLD', 'Agent must reconcile project-required scope, manual review, environment evidence, and two complete passes with the skill')
    except KeyboardInterrupt:
        gate.interrupted = True
        gate.row('workflow.interrupted', root, 'FAIL', 'Interrupted; partial ledger retained')
    except Exception as exc:
        gate.row('workflow.error', root, 'FAIL', type(exc).__name__+': '+str(exc))
    counts = {key: sum(row['status'] == key for row in gate.rows) for key in ('PASS','FAIL','HOLD','SKIP')}
    ledger = dict(schema='verification-loop-v2', project=str(root), generated_utc=utc(),
                  candidate_manifest=first, candidate_manifest_sha256=hashlib.sha256(json.dumps(first,sort_keys=True).encode()).hexdigest(),
                  environment=dict(platform=sys.platform, architecture=os.uname().machine if hasattr(os,'uname') else 'unknown',
                                   python=sys.version, CGO_ENABLED=os.environ.get('CGO_ENABLED')),
                  tool_versions=gate.versions, exclusions=gate.exclusions,
                  evidence_directory=str(evidence), counts=counts, gates=gate.rows,
                  decision='NOT READY', exception='NONE', partial=gate.interrupted)
    # Exclusive creation ensures prior evidence cannot be overwritten.
    with out.open('x') as stream:
        json.dump(ledger, stream, indent=2)
        stream.write('\n')
    print('  '.join('%s %d'%(k,v) for k,v in counts.items()))
    for row in gate.rows:
        if row['status'] != 'PASS':
            print('%s %s [%s]: %s'%(row['status'],row['check'],row['scope'],row['reason']))
    print('Ledger: '+str(out))
    return 1 if counts['FAIL'] or counts['HOLD'] else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print('FAIL: ledger/setup error: '+str(exc), file=sys.stderr)
        sys.exit(3)
