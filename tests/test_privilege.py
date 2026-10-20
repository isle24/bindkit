import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bindconsole'))
import bindkit_privilege as privilege

class Vault:
    def __init__(self, secret='synthetic-sudo', locked=False): self.secret=secret; self.reads=0; self.locked=locked
    def get(self, ref):
        self.reads += 1
        if self.locked: raise RuntimeError('synthetic-sudo')
        return self.secret

class FakeSSH:
    def __init__(self, script, mode): self.script=script; self.mode=mode
    def ssh_with_key(self, *args, **kwargs): return [sys.executable, self.script, self.mode]

SIMULATOR = r'''
import sys, re, time
mode, command = sys.argv[1:]
prompt = re.search(r'BINDKIT_PROMPT_[a-f0-9]+', command).group()
start = re.search(r'BINDKIT_STARTED_[a-f0-9]+', command).group()
if mode == 'tty':
    sys.stderr.write('sudo: sorry, you must have a tty to run sudo\n'); sys.exit(1)
if mode == 'unknown': sys.exit(255)
if mode == 'timeout': time.sleep(4)
if mode in ('password','wrong','disconnect_after_password'):
    sys.stderr.write(prompt); sys.stderr.flush()
    password = sys.stdin.buffer.readline()
    if mode == 'disconnect_after_password': sys.exit(255)
    if password != b'synthetic-sudo\n' or mode == 'wrong':
        sys.stderr.write(prompt); sys.stderr.flush(); sys.exit(1)
sys.stderr.write(start + '\n'); sys.stderr.flush()
if mode == 'after_start': time.sleep(4)
data=sys.stdin.buffer.read()
sys.stdout.buffer.write(data)
'''

class PlanTests(unittest.TestCase):
    def plan(self, command='id', **kw):
        return privilege.build_plan(command, 'login', uid_resolver=lambda name: {'alice':1001,'root':0,'aliasroot':0,'daemon':1}.get(name), **kw)
    def test_allowlist_requires_positive_uid(self):
        self.assertTrue(self.plan(as_user='alice', allowed_users=['alice'])['approval_exempt'])
        for target in ('root','aliasroot','missing','daemon'):
            self.assertTrue(self.plan(as_user=target, allowed_users=[target])['requires_approval'])
    def test_normalize_simple_forms(self):
        for cmd in ('sudo -u alice id', 'su alice -c id', 'runuser -u alice -- id'):
            plan=self.plan(cmd, allowed_users=['alice'])
            self.assertEqual(plan['command'], 'id')
            self.assertEqual(plan['target_user'], 'alice')
            self.assertTrue(plan['approval_exempt'])
    def test_nested_dynamic_and_complex_never_exempt(self):
        for command in ('sudo -u alice sudo id', 'sudo -u "$USER" id', 'sudo -u alice id; sudo id', 'sudo -i', 'echo ok && su root', 'env sudo id'):
            plan=self.plan(command, allowed_users=['alice'])
            self.assertTrue(plan['requires_approval'], command)
            self.assertFalse(plan['approval_exempt'], command)
        self.assertTrue(self.plan('sudo id', as_user='alice', allowed_users=['alice'])['requires_approval'])
    def test_shell_wrappers_and_obfuscation_never_exempt(self):
        for command in ('s\\u\\d\\o id', "sh -c 'id'", 'echo x; id', 'printf `id`', "'sudo' id", 'env sh -c id'):
            plan=self.plan(command, as_user='alice', allowed_users=['alice'])
            self.assertFalse(plan['approval_exempt'], command)
            self.assertTrue(plan['requires_approval'], command)
        self.assertTrue(self.plan('s\\u\\d\\o id')['requires_approval'])
    def test_dynamic_explicit_identity_rejected(self):
        with self.assertRaises(ValueError): self.plan(as_user='$(id)')
    def test_fingerprint_context_binds_original_and_resolved_identity(self):
        p=self.plan('id', as_user='alice')
        self.assertEqual(p['fingerprint_context']['target_uid'],1001)
        self.assertNotEqual(p['fingerprint'], self.plan('id', as_user='root')['fingerprint'])

class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        environ=patch.dict(os.environ, {'HOME':self.tmp.name}); environ.start(); self.addCleanup(environ.stop)
        self.script=os.path.join(self.tmp.name,'fake_ssh.py')
        Path(self.script).write_text(SIMULATOR)
        self.plan=privilege.build_plan('cat','login',as_user='root')
        self.server={'host':'synthetic.invalid','user':'login','port':22,'key':'synthetic','sudo_auth':'keyring','sudo_credential_ref':'ref'}
    def run_mode(self, mode, vault=None, **kw):
        return privilege.execute_plan(FakeSSH(self.script,mode),self.server,self.plan,vault or Vault(),stdin_data='payload\n',**kw)
    def test_password_prompt_preserves_command_stdin(self):
        r=self.run_mode('password')
        self.assertEqual(r['stdout'],'payload\n'); self.assertTrue(r['started']); self.assertTrue(r['authenticated']); self.assertIsNone(r['error'])
    def test_cached_auth_never_loads_or_forwards_password(self):
        vault=Vault(locked=True); r=self.run_mode('cached',vault)
        self.assertEqual(vault.reads,0); self.assertEqual(r['stdout'],'payload\n')
    def test_wrong_or_locked_password_precedes_execution(self):
        for mode,vault in (('wrong',Vault()),('password',Vault(locked=True)),('password',Vault(secret=None))):
            r=self.run_mode(mode,vault)
            self.assertFalse(r['started']); self.assertFalse(r['authenticated']); self.assertTrue(r['error'])
            self.assertNotIn('synthetic-sudo',json.dumps(r))
    def test_transport_loss_after_password_is_unknown_not_retriable_auth_failure(self):
        r=self.run_mode('disconnect_after_password')
        self.assertIsNone(r['started'])
        self.assertEqual(r['error']['code'],'EXECUTION_STATE_UNKNOWN')
        self.assertNotIn('synthetic-sudo',json.dumps(r))
    def test_requiretty_is_explicitly_unsupported(self):
        r=self.run_mode('tty'); self.assertEqual(r['error']['code'],'UNSUPPORTED_AUTHENTICATION'); self.assertFalse(r['started'])
    def test_timeout_and_disconnection_are_unknown_without_proof(self):
        for mode in ('timeout','unknown'):
            r=self.run_mode(mode,timeout=0.15); self.assertIsNone(r['started']); self.assertTrue(r['error'])
        r=self.run_mode('after_start',timeout=0.15); self.assertTrue(r['started']); self.assertTrue(r['error'])
    def test_unsupported_legacy_does_not_start_transport(self):
        self.plan=privilege.build_plan('sudo -i','login')
        r=self.run_mode('cached'); self.assertEqual(r['error']['code'],'UNSUPPORTED_PRIVILEGE'); self.assertFalse(r['started'])
    def test_real_shell_wrapper_preserves_quoted_command_and_large_stdin(self):
        shim = Path(self.tmp.name) / 'sudo'
        shim.write_text('#!' + sys.executable + "\nimport os,sys\na=sys.argv[1:]\ni=a.index('--')\nos.execvp(a[i+1],a[i+1:])\n")
        shim.chmod(0o700)
        class ShellSSH:
            def ssh_with_key(inner, *args):
                return ['/usr/bin/env', 'PATH=' + self.tmp.name + ':/usr/bin:/bin', '/bin/sh', '-c']
        plan=privilege.build_plan("printf '%s\\n' \"it's safe\"; cat", 'login', as_user='root')
        payload=b'x'*200000
        v=Vault(locked=True)
        result=privilege.execute_plan(ShellSSH(),self.server,plan,v,stdin_data=payload,timeout=4)
        self.assertEqual(result['exit_code'],0)
        self.assertEqual(result['stdout'],"it's safe\n"+payload.decode())
        self.assertEqual(v.reads,0)
    def test_nopasswd_prompt_never_fetches_keyring(self):
        self.server['sudo_auth']='nopasswd'; v=Vault()
        r=self.run_mode('password',v); self.assertEqual(v.reads,0); self.assertFalse(r['started'])

if __name__=='__main__': unittest.main()
