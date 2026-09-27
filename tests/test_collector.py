#!/usr/bin/env python3
"""Synthetic integration regressions. Requires Linux bwrap user namespaces.
No host /etc, /home, /var, /proc or /sys is mounted into the fixture.
FreeBSD stat/sysctl and appliance CLI are shims, not native validation.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import sysconfig
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'ns_ir_collect.sh'
RESULTS = []
SECRET = 'SYNTHETIC_SECRET_DO_NOT_EXPORT'

def put(root, name, text, mode=0o644):
    path = root / name.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)

def binary(root, name):
    src = shutil.which(name)
    if not src:
        raise RuntimeError('Missing fixture utility: ' + name)
    (root / 'bin').mkdir(exist_ok=True)
    shutil.copy2(src, root / 'bin' / name)
    deps = subprocess.run(['ldd', src], capture_output=True, text=True, check=False).stdout
    for token in deps.split():
        if token.startswith('/') and Path(token).is_file():
            dest = root / token.lstrip('/')
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists():
                shutil.copy2(token, dest)

class Fixture:
    def __init__(self, fault='', indicators=False):
        self.tmp = tempfile.TemporaryDirectory(prefix='nsir-regression-')
        self.root = root = Path(self.tmp.name)
        for d in ['sbin', 'usr/bin', 'usr/sbin', 'usr/local/bin', 'usr/local/sbin',
                  'netscaler/ns_gui', 'var/tmp', 'tmp', 'flash/nsconfig/keys/updated',
                  'var/log', 'var/vpn/theme', 'var/netscaler/gui/admin_ui', 'var/core',
                  'var/cron', 'var/nsinstall', 'var/ns_sys_backup', 'var/nslog', 'etc',
                  'dev', 'out', 'root']:
            (root / d).mkdir(parents=True, exist_ok=True)
        for n in ('sh dash id sed hostname date mkdir basename dirname realpath timeout awk sha256sum '
                  'find wc tr df du sleep mktemp cmp expr cat grep head sort xargs stat ls cut '
                  'od gzip tail mv rm tar cp uname touch chmod ln').split():
            binary(root, n)
        (root/'bin/stat').rename(root/'bin/stat-real')
        put(root, '/sbin/stat', '#!/bin/sh\nfmt=$2; shift; shift\ncase \"$fmt\" in %m) exec /bin/stat-real -c %Y \"$@\";; %d:%i) exec /bin/stat-real -c %d:%i \"$@\";; esac\nexec /bin/stat-real --printf="0|%n|%i|%A|%u|%g|%s|%X|%Y|%Z|%W\\n" -- "$@"\n', 0o755)
        put(root, '/sbin/sysctl', f'#!/bin/sh\necho "{{ sec = {int(time.time())}, usec = 0 }}"\n', 0o755)
        put(root, '/sbin/nscli', '#!/bin/sh\necho "NetScaler NS14.1 Build 73.30 synthetic fixture"\n', 0o755)
        put(root, '/sbin/ps', '#!/bin/sh\necho "USER PID PPID COMM"\necho "root 1 0 /sbin/init"\n', 0o755)
        put(root, '/sbin/procstat', '#!/bin/sh\necho "PID COMM OSREL PATH"\n', 0o755)
        put(root, '/sbin/hostname', '#!/bin/sh\necho fixture\n', 0o755)
        for tool in ['uptime', 'sockstat', 'netstat', 'arp', 'ifconfig', 'who', 'last',
                     'fstat', 'kldstat', 'mount', 'ntpq', 'crontab']:
            put(root, '/sbin/'+tool, '#!/bin/sh\nexit 0\n', 0o755)
        put(root, '/sbin/ls', '#!/bin/sh\ncase "$1" in -laT) shift; exec /bin/ls -la "$@";; -lT) shift; exec /bin/ls -l "$@";; esac\nexec /bin/ls "$@"\n', 0o755)
        put(root, '/sbin/df', '#!/bin/sh\necho "Filesystem 1024-blocks Used Available Capacity Mounted"\nshift\nfor path do echo "fixture 10000000 1 9999999 1% /"; done\n', 0o755)
        put(root, '/netscaler/ns_gui/library.php', "<?php $marker = '-----BEGIN PRIVATE KEY-----'; ?>\n")
        (root/'netscaler/ns_gui/wrong-extension.gif').write_bytes(bytes.fromhex('89504e470d0a1a0a'))
        put(root, '/etc/auth.conf', '# synthetic fixture\n')
        put(root, '/etc/crontab', '# empty fixture\n')
        put(root, '/etc/ntp.conf', '# empty fixture\n')
        put(root, '/etc/master.passwd', f'root:{SECRET}:0:0::0:0:root:/root:/bin/sh\n')
        put(root, '/flash/nsconfig/ns.conf', f'set ns hostName fixture\nadd system user fixture {SECRET}\n')
        put(root, '/flash/nsconfig/ssl/test.key', f'-----BEGIN PRIVATE KEY-----\n{SECRET}\n-----END PRIVATE KEY-----\n')
        put(root, '/flash/nsconfig/keys/test.key', SECRET+'\n')
        put(root, '/root/.sh_history', 'curl '+SECRET+'\n')
        put(root, '/var/log/ns.log', 'fixture startup '+SECRET+'\n'
            'TCPCONNSTAT Client_ip 2001:db8::1 Source 2001:db8::1 User sample SessionId: 1\n'
            'TCPCONNSTAT Client_ip 2001:db8::1 Source [2001:0DB8:0:0:0:0:0:1]:443 User sample\n'
            'TCPCONNSTAT Client_ip 192.0.2.1 Source 192.0.2.1:443 User sample\n')
        put(root, '/var/log/httpaccess.log', 'GET /saml/login?token='+SECRET+'\n')
        (root/'nsconfig').symlink_to('/flash/nsconfig')
        shutil.copy2(SOURCE, root/'collector.sh')
        if indicators:
            put(root, '/var/vpn/theme/marker.php', '<?php /* inert string: eval($_POST["sample"]) */ ?>\n')
            put(root, '/netscaler/ns_gui/leaked-key.txt', '-----BEGIN PRIVATE KEY-----\n'+SECRET+'\n')
            put(root, '/flash/nsconfig/rc.netscaler', '# inert: chmod u+s /bin/sh\n# curl '+SECRET+'\n')
            put(root, '/var/tmp/sh', 'inert file\n', 0o4644)
            put(root, '/netscaler/ns_gui/fake.png', 'not an image\n')
            with (root/'var/log/ns.log').open('ab') as f:
                f.write(b'AAA Message Authentication is rejected for user\x80\n')
        if fault in ('archive', 'evidence', 'corrupt'):
            match = '-cf' if fault == 'evidence' else '-czf'
            action = 'printf bad > "$2"; exit 0' if fault == 'corrupt' else 'exit 2'
            put(root, '/sbin/tar', f'#!/bin/sh\ncase "$1" in {match}) {action};; esac\nexec /bin/tar "$@"\n', 0o755)
        if fault == 'hash':
            put(root, '/sbin/sha256sum', '#!/bin/sh\ncase "$1" in *.partial.tgz) exit 1;; esac\nexec /bin/sha256sum "$@"\n', 0o755)
        if fault == 'python_stat':
            (root/'sbin/stat').unlink()
            binary(root, 'python3')
            (root/'bin/python3').rename(root/'usr/bin/python3')
            stdlib=Path(sysconfig.get_path('stdlib'))
            shutil.copytree(stdlib,root/str(stdlib).lstrip('/'),dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns('site-packages','dist-packages','__pycache__','test','tests'))
        if fault == 'timeline':
            p = root/'sbin/stat'; original=p.read_text()
            p.write_text(original.replace('fmt=$2; shift; shift', 'case "$3" in /collector.sh) ;; *) exit 1;; esac\nshift; shift'))
        if fault == 'cli':
            put(root, '/sbin/nscli', '#!/bin/sh\ncase "$*" in *"show ns version"*) echo "NetScaler Build 73.30";; *) echo "ERROR: injected CLI failure";; esac\n', 0o755)
        if fault == 'missing_cli':
            (root/'sbin/nscli').unlink()
        if fault in ('timeout', 'interrupt', 'size'):
            put(root, '/sbin/nscli', '#!/bin/sh\nsleep 20\n', 0o755)
        if fault == 'size':
            (root/'out/bloat').write_bytes(b'x' * 2 * 1024 * 1024)
            put(root, '/sbin/nscli', '#!/bin/sh\ncp /out/bloat "$NSIR_NOT_SET" 2>/dev/null\nfor p in /out/nsir_*; do cp /out/bloat "$p/bloat"; done\nsleep 20\n', 0o755)
        if fault == 'space':
            put(root, '/sbin/df', '#!/bin/sh\necho "Filesystem 1024-blocks Used Available Capacity Mounted"\necho "fixture 100 99 1 99% /"\n', 0o755)
        if fault == 'names':
            put(root, '/var/vpn/theme/space name.php', '<?php /* inert */ ?>\n')
            put(root, '/var/vpn/theme/bad|name.php', 'inert\n')
            put(root, '/var/vpn/theme/bad\nname.php', 'inert\n')
        if fault == 'changing':
            put(root, '/sbin/tar', '#!/bin/sh\ncase "$1" in -cf) echo changed >> /flash/nsconfig/ns.conf;; esac\nexec /bin/tar "$@"\n', 0o755)
        if fault == 'ascii_control':
            with (root/'var/log/ns.log').open('ab') as f:
                f.write(b'AAA Message Authentication is rejected for user\x01\x7f\n')
        if fault == 'sessions':
            with (root/'var/log/ns.log').open('a') as f:
                f.write('TCPCONNSTAT Client_ip 2001:db8::1 Source 2001:db8::2:443 User ambiguous\n')
                f.write('TCPCONNSTAT Client_ip 2001:db8::1 Source [2001:db8::2]:443 User ipv6\n')
                for i in range(10):
                    f.write(f'TCPCONNSTAT Client_ip 192.0.2.{i+1} Source 198.51.100.1:443 User user{i}\n')

    def run(self, *options, concurrent=False, interrupt=False):
        cmd=['bwrap', '--unshare-all', '--die-with-parent', '--uid', '0', '--gid', '0',
             '--bind', str(self.root), '/', '--dev', '/dev', '--chdir', '/', '--']
        args=['/bin/sh','/collector.sh','-o','/out','-C','SYNTHETIC',*options]
        if concurrent:
            cmd+=['/bin/sh','-c','sh /collector.sh -o /out > /one.log 2>&1 & a=$!; sh /collector.sh -o /out > /two.log 2>&1 & b=$!; wait "$a"; x=$?; wait "$b"; y=$?; test "$x" = 0 && test "$y" = 0']
        elif interrupt:
            cmd+=['/bin/sh','-c','sh /collector.sh -o /out >/run.log 2>&1 & p=$!; sleep 2; kill -TERM "$p"; wait "$p"']
        else:
            cmd+=args
        start=time.monotonic()
        result=subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        records=[]
        for path in sorted((self.root/'out').glob('*.tgz')):
            if path.name.endswith('.partial.tgz'): continue
            with tarfile.open(path) as archive:
                data={n.name.split('/',1)[1]: archive.extractfile(n).read() for n in archive.getmembers() if n.isfile()}
            digest=Path(str(path)+'.sha256').read_text().split()[0]
            records.append({'data':data, 'hash_ok':hashlib.sha256(path.read_bytes()).hexdigest()==digest})
        self.result=result
        self.records=records
        self.staging=[p for p in (self.root/'out').glob('nsir_*') if p.is_dir()]
        RESULTS.append({'test':self.label,'exit':result.returncode,'seconds':round(time.monotonic()-start,2), 'archives':len(records),'staging':len(self.staging)})
        return result.returncode

    def close(self): self.tmp.cleanup()

class CollectorTests(unittest.TestCase):
    def fixture(self, fault='', indicators=False):
        f=Fixture(fault, indicators); f.label=self.id().split('.')[-1]
        self.addCleanup(f.close); return f

    def test_default_privacy_and_archive(self):
        f=self.fixture(indicators=True); self.assertEqual(f.run(),0,f.result.stderr)
        d=f.records[0]['data']; self.assertTrue(f.records[0]['hash_ok'])
        self.assertNotIn('files/evidence_files.tar',d)
        self.assertNotIn(SECRET.encode(),b'\n'.join(d.values()))
        self.assertEqual(d['logs_analysis/session_ip_mismatch.txt'],b'')
        self.assertEqual(d['logs_analysis/cb2_nonprintable_aaa.txt'],b'matching_lines=1\n')
        self.assertEqual(d['00_TRIAGE_FLAGS.txt'].count(b'[HIGH]'),7)
        self.assertFalse(f.staging)

    def test_full_collection_explicit(self):
        f=self.fixture(); self.assertEqual(f.run('-S'),0,f.result.stderr)
        d=f.records[0]['data']; self.assertIn('files/evidence_files.tar',d)
        with tarfile.open(fileobj=io.BytesIO(d['files/evidence_files.tar'])) as t:
            self.assertIn(SECRET.encode(),t.extractfile('flash/nsconfig/ssl/test.key').read())
            for line in d['files/evidence_files.sha256'].decode().splitlines():
                h,name=line.split('  ',1); self.assertEqual(h,hashlib.sha256(t.extractfile(name).read()).hexdigest())

    def test_archive_failure_preserves(self):
        f=self.fixture('archive'); self.assertEqual(f.run(),1); self.assertTrue(f.staging); self.assertFalse(f.records)
        self.assertNotIn('Collection complete',f.result.stderr)

    def test_evidence_failure_preserves(self):
        f=self.fixture('evidence'); self.assertEqual(f.run('-S'),1); self.assertTrue(f.staging); self.assertFalse(f.records)

    def test_corrupt_archive_rejected(self):
        f=self.fixture('corrupt'); self.assertEqual(f.run(),1); self.assertTrue(f.staging)

    def test_hash_failure_preserves(self):
        f=self.fixture('hash'); self.assertEqual(f.run(),1); self.assertTrue(f.staging)

    def test_timeline_failure_partial(self):
        f=self.fixture('timeline'); self.assertEqual(f.run(),2,f.result.stderr)
        self.assertIn(b'invalid_or_empty_timeline',f.records[0]['data']['00_stage_events.tsv'])

    def test_cli_semantic_errors_partial(self):
        f=self.fixture('cli'); self.assertEqual(f.run('-S'),2,f.result.stderr)
        self.assertIn(b'cli_error:',f.records[0]['data']['00_stage_events.tsv'])

    def test_missing_cli_partial(self):
        f=self.fixture('missing_cli'); self.assertEqual(f.run(),2,f.result.stderr)

    def test_deadline_preserves(self):
        f=self.fixture('timeout'); self.assertEqual(f.run('-t','2'),124,f.result.stderr); self.assertTrue(f.staging)

    def test_interrupt_preserves(self):
        f=self.fixture('interrupt'); self.assertEqual(f.run(interrupt=True),143,f.result.stderr); self.assertTrue(f.staging)

    def test_size_limit_preserves(self):
        f=self.fixture('size'); self.assertEqual(f.run('-m','1'),1,f.result.stderr); self.assertTrue(f.staging)

    def test_free_space_limit(self):
        f=self.fixture('space'); self.assertEqual(f.run(),1); self.assertTrue(f.staging)

    def test_unusual_names_partial(self):
        f=self.fixture('names'); self.assertEqual(f.run('-S'),2,f.result.stderr)
        self.assertIn(b'unsupported_filenames_omitted',f.records[0]['data']['00_stage_events.tsv'])
        with tarfile.open(fileobj=io.BytesIO(f.records[0]['data']['files/evidence_files.tar'])) as t:
            self.assertIn('var/vpn/theme/space name.php',t.getnames())

    def test_changing_file_partial(self):
        f=self.fixture('changing'); self.assertEqual(f.run('-S'),2,f.result.stderr)
        self.assertIn(b'evidence_changed_during_capture',f.records[0]['data']['00_stage_events.tsv'])

    def test_ascii_control_not_cb2(self):
        f=self.fixture('ascii_control'); self.assertEqual(f.run(),0,f.result.stderr)
        self.assertEqual(f.records[0]['data']['logs_analysis/cb2_nonprintable_aaa.txt'],b'matching_lines=0\n')

    def test_sessions_and_source_grouping(self):
        f=self.fixture('sessions'); self.assertEqual(f.run(),2,f.result.stderr)
        d=f.records[0]['data']; self.assertIn(b'10 198.51.100.1',d['logs_analysis/ips_with_many_users.txt'])
        self.assertEqual(len(d['logs_analysis/session_ip_mismatch.txt'].splitlines()),11)
        self.assertIn(b'ambiguous_or_invalid_session_addresses',d['00_stage_events.tsv'])

    def test_concurrent_runs(self):
        f=self.fixture(); self.assertEqual(f.run(concurrent=True),0,f.result.stderr); self.assertEqual(len(f.records),2)

    def test_sensitive_options_require_opt_in(self):
        f=self.fixture(); self.assertEqual(f.run('-c'),1); self.assertFalse(f.staging)

    def test_python_stat_fallback(self):
        f=self.fixture('python_stat'); self.assertEqual(f.run(),0,f.result.stderr)
        self.assertIn(b'stat_backend=python3_lstat',f.records[0]['data']['00_metadata.txt'])
        self.assertTrue(f.records[0]['data']['timeline/bodyfile.txt'])

    def test_keep_staging(self):
        f=self.fixture(); self.assertEqual(f.run('-k'),0,f.result.stderr); self.assertTrue(f.staging)


    def support_fixture(self, behavior='success'):
        f=self.fixture()
        put(f.root, '/tmp/vendor-payload', SECRET+'\n')
        code = """#!/bin/sh
[ "$*" = '-scope NODE' ] || exit 12
mkdir -p /var/tmp/support
echo invoked > /tmp/vendor-invoked
"""
        if behavior=='timeout': code += 'sleep 20\n'
        elif behavior=='failed': code += 'exit 7\n'
        elif behavior=='stale': code += 'exit 0\n'
        elif behavior=='missing': code += 'exit 0\n'
        elif behavior=='corrupt':
            code += 'echo broken > /var/tmp/support/collector_new.tar.gz\nln -sf /var/tmp/support/collector_new.tar.gz /var/tmp/support/support.tgz\n'
        elif behavior=='outside':
            code += 'ln -sf /tmp/vendor-payload /var/tmp/support/support.tgz\n'
        elif behavior=='bloat':
            (f.root/'tmp/bloat').write_bytes(b'x'*2*1024*1024)
            code += 'cp /tmp/bloat /var/tmp/support/bloat; sleep 20\n'
        else:
            code += 'tar -czf /var/tmp/support/collector_new.tar.gz -C /tmp vendor-payload\nln -sf /var/tmp/support/collector_new.tar.gz /var/tmp/support/support.tgz\n'
        put(f.root, '/netscaler/showtechsupport.pl', code, 0o755)
        if behavior=='stale':
            put(f.root, '/var/tmp/support/collector_old.tar.gz', 'old')
            (f.root/'var/tmp/support/support.tgz').symlink_to('collector_old.tar.gz')
        return f

    def test_support_success_independent_opt_in(self):
        f=self.support_fixture(); self.assertEqual(f.run('--support-bundle'),0,f.result.stderr)
        d=f.records[0]['data']; payload=d['support_bundle/bundle.tar.gz']
        self.assertEqual(hashlib.sha256(payload).hexdigest(),d['support_bundle/bundle.tar.gz.sha256'].decode().split()[0])
        with tarfile.open(fileobj=io.BytesIO(payload)) as t:
            self.assertEqual(t.extractfile('vendor-payload').read(),(SECRET+'\n').encode())
        self.assertNotIn('files/evidence_files.tar',d)
        self.assertTrue((f.root/'var/tmp/support/collector_new.tar.gz').exists())

    def test_support_default_does_not_invoke(self):
        f=self.support_fixture(); self.assertEqual(f.run(),0,f.result.stderr)
        self.assertFalse((f.root/'tmp/vendor-invoked').exists())
        self.assertNotIn(SECRET.encode(),b'\n'.join(f.records[0]['data'].values()))

    def test_support_timeout_continues_packaging(self):
        f=self.support_fixture('timeout')
        self.assertEqual(f.run('--support-bundle','--support-timeout=1'),2,f.result.stderr)
        d=f.records[0]['data']; self.assertIn(b'support_command_failed:124',d['00_stage_events.tsv'])
        self.assertNotIn('support_bundle/bundle.tar.gz',d)
        self.assertTrue(d['timeline/bodyfile.txt'])

    def test_support_failures_are_partial(self):
        for behavior, expected in [('failed','support_command_failed:7'),('stale','support_archive_not_new'),
                                   ('missing','support_archive_missing'),('corrupt','support_archive_invalid'),
                                   ('outside','support_archive_unexpected_path')]:
            with self.subTest(behavior=behavior):
                f=self.support_fixture(behavior)
                self.assertEqual(f.run('--support-bundle'),2,f.result.stderr)
                d=f.records[0]['data']; self.assertIn(expected.encode(),d['00_stage_events.tsv'])
                self.assertNotIn('support_bundle/bundle.tar.gz',d)

    def test_support_absent_is_partial(self):
        f=self.fixture(); self.assertEqual(f.run('--support-bundle'),2,f.result.stderr)
        self.assertIn(b'support_collector_unavailable',f.records[0]['data']['00_stage_events.tsv'])

    def test_support_external_workspace_limit(self):
        f=self.support_fixture('bloat'); self.assertEqual(f.run('--support-bundle','-m','1'),1,f.result.stderr)
        self.assertTrue(f.staging); self.assertFalse(f.records)
        self.assertTrue(list((f.root/'out').glob('*.limit')))

    def test_support_invalid_timeout(self):
        f=self.fixture(); self.assertEqual(f.run('--support-bundle','--support-timeout=0'),1)
        self.assertFalse(f.staging)

if __name__=='__main__':
    try:
        unittest.main(verbosity=2)
    finally:
        target=os.environ.get('NSIR_TEST_RESULTS')
        if target:
            Path(target).write_text(json.dumps({'script_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'environment':'isolated Linux fixture with FreeBSD/CLI shims','tests':RESULTS},indent=2)+'\n')
