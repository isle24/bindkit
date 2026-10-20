import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bindconsole'))
import bindkit_privilege
import bindkit_connections
import bindkit_ai


def load(name,path):
    loader=importlib.machinery.SourceFileLoader(name,str(path))
    spec=importlib.util.spec_from_loader(name,loader)
    module=importlib.util.module_from_spec(spec); loader.exec_module(module)
    return module


class CLIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        environment=patch.dict(os.environ,{'HOME':self.temp.name,'BINDCONSOLE_HOME':str(Path(self.temp.name)/'.bindconsole')})
        environment.start(); self.addCleanup(environment.stop)
        self.policy=load('cli_policy',ROOT/'bindconsole/bindkit_policy.py')
        self.ssh=load('cli_ssh',ROOT/'sshbind/sshbind'); self.ssh._POLICY_MODULE=self.policy
        self.db=load('cli_db',ROOT/'dbbind/dbbind'); self.db._POLICY_MODULE=self.policy
        self.ssh.ensure_dirs()
        self.key=Path(self.ssh.KEYS_DIR)/'fake'; self.key.write_text('synthetic')
        self.server={'name':'demo','id':'fake-id','revision':1,'host':'example.invalid','user':'operator','port':22,'key':str(self.key),'sudo_auth':'none','installed':True}
        self.ssh.save_state({'servers':{'demo':self.server}})
        self.policy.write_policy('ssh',{'version':1,'defaults':{'sudo':'ask'},'servers':{'demo':{'allowed_users':['app']}}})
        self.review=patch.object(bindkit_ai,'review_and_decide',return_value={'decision':'human'}).start()
        self.addCleanup(patch.stopall)
        self.transport=patch.object(self.ssh,'run_ssh',return_value=(0,'1001\n','')).start()
    def execute(self,command='id',as_user=None):
        args=types.SimpleNamespace(name='demo',command=[command],json=True,timeout=10,as_user=as_user,stdin=False)
        output=io.StringIO()
        with contextlib.redirect_stdout(output): code=self.ssh.cmd_exec(args)
        return code,json.loads(output.getvalue())
    @contextlib.contextmanager
    def synthetic_create_transport(self, install_ok=True, verify_ok=True):
        status={'install':install_ok,'verify':verify_ok}
        def generate(name,**kwargs):
            private,public=self.ssh.key_paths(name)
            Path(private).write_text('synthetic-private'); Path(public).write_text('ssh-ed25519 synthetic-public')
            return private,public
        def transport(argv,**kwargs):
            if argv[-1] == self.ssh.REMOTE_INSTALL:
                return (0,'SSHBIND_ADDED\n','') if status['install'] else (1,'','synthetic-install-failure')
            if 'SSHBIND_OK' in argv[-1]:
                return (0,'SSHBIND_OK\nfixture\noperator\n','') if status['verify'] else (255,'','synthetic-verification-failure')
            raise AssertionError('Unexpected synthetic SSH operation')
        def run_self(argv,stdin_data=None,**kwargs):
            out=io.StringIO();err=io.StringIO()
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err),patch.object(self.ssh.sys,'stdin',io.StringIO(stdin_data or '')):
                try: rc=self.ssh.main(argv)
                except SystemExit as error: rc=error.code
            return rc,out.getvalue(),err.getvalue()
        with patch.object(self.ssh,'gen_keypair',side_effect=generate), patch.object(self.ssh,'fingerprint_of',return_value='SHA256:synthetic'), patch.object(self.ssh,'auth_ssh_opts',return_value=([],None)), patch.object(self.ssh,'run_ssh',side_effect=transport), patch.object(self.ssh,'_run_self',side_effect=run_self):
            yield status
    def test_web_password_install_failure_leaves_no_alias_and_allows_retry(self):
        body={'name':'imported','host':'example.invalid','user':'operator','password':'synthetic-secret'}
        original=set(Path(self.ssh.KEYS_DIR).iterdir())
        with self.synthetic_create_transport(install_ok=False) as status:
            with self.assertRaises(Exception): self.ssh.console_ssh_create(body)
            self.assertNotIn('imported',self.ssh.load_state()['servers'])
            self.assertEqual(set(Path(self.ssh.KEYS_DIR).iterdir()),original)
            status['install']=True
            result=self.ssh.console_ssh_create(body)
        self.assertTrue(result['ok']); self.assertTrue(self.ssh.load_state()['servers']['imported']['installed'])
    def test_web_password_post_install_verification_failure_is_not_success(self):
        body={'name':'imported','host':'example.invalid','user':'operator','password':'synthetic-secret'}
        with self.synthetic_create_transport(verify_ok=False):
            with self.assertRaises(Exception): self.ssh.console_ssh_create(body)
        self.assertNotIn('imported',self.ssh.load_state()['servers'])
        self.assertTrue(self.key.exists())
    def test_web_private_key_failure_never_prompts_or_registers(self):
        with self.synthetic_create_transport(verify_ok=False),patch.object(self.ssh,'ask_yes_no',return_value=True) as prompt:
            with self.assertRaises(Exception): self.ssh.console_ssh_create({'name':'imported','host':'example.invalid','user':'operator','private_key':'synthetic-private'})
        self.assertFalse(prompt.called); self.assertNotIn('imported',self.ssh.load_state()['servers'])
    def test_manual_add_preserves_offline_keep_key_behavior(self):
        with self.synthetic_create_transport(install_ok=False),patch.object(self.ssh.sys,'stdin',io.StringIO('synthetic-secret\n')),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            code=self.ssh.main(['add','offline','--host','example.invalid','--user','operator','--password-stdin'])
        self.assertEqual(code,1); self.assertFalse(self.ssh.load_state()['servers']['offline']['installed'])
    def test_as_user_flag_must_precede_alias(self):
        args=self.ssh.build_parser().parse_args(['exec','--as-user','app','--stdin','demo','cat'])
        self.assertEqual(args.as_user,'app'); self.assertTrue(args.stdin)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): self.execute('id --as-user root')
    def test_allowlisted_target_is_resolved_on_remote_and_runs_managed(self):
        with patch.object(bindkit_privilege,'execute_plan',return_value={'exit_code':0,'stdout':'done','stderr':'','started':True,'authenticated':True,'error':None}) as runner:
            code,result=self.execute(as_user='app')
        self.assertEqual(code,0); self.assertEqual(runner.call_args.args[2]['target_uid'],1001)
        self.assertEqual(self.transport.call_args.args[0][-1],'id -u -- app')
        self.assertTrue(result['started']); self.assertFalse(self.review.called)
    def test_managed_approval_auth_failure_releases_and_unknown_consumes(self):
        code,first=self.execute(as_user='root'); self.assertEqual(code,6)
        request=first['error']['request_id']; self.policy.approve('ssh',request)
        with patch.object(bindkit_privilege,'execute_plan',return_value={'exit_code':1,'stdout':'','stderr':'','started':False,'authenticated':False,'error':{'code':'AUTHENTICATION_FAILED','message':'failed'}}):
            code,_=self.execute(as_user='root')
        self.assertEqual(self.policy.get_approval('ssh',request)['consumes_left'],1)
        with patch.object(bindkit_privilege,'execute_plan',return_value={'exit_code':255,'stdout':'','stderr':'','started':None,'authenticated':False,'error':{'code':'EXECUTION_STATE_UNKNOWN','message':'unknown'}}):
            self.execute(as_user='root')
        self.assertEqual(self.policy.get_approval('ssh',request)['status'],'consumed')
    def test_password_then_transport_loss_consumes_approval_without_replay(self):
        import bindkit_vault
        state=self.ssh.load_state()
        state['servers']['demo'].update(sudo_auth='keyring',sudo_credential_ref='synthetic-ref')
        self.ssh.save_state(state)
        _,first=self.execute(as_user='root'); request=first['error']['request_id']
        self.policy.approve('ssh',request)
        script=Path(self.temp.name)/'disconnect_ssh.py'
        script.write_text("import re,sys\nprompt=re.search(r'BINDKIT_PROMPT_[a-f0-9]+',sys.argv[-1]).group()\nsys.stderr.write(prompt);sys.stderr.flush()\nsys.stdin.buffer.readline()\nsys.exit(255)\n")
        with patch.object(self.ssh,'ssh_with_key',return_value=[sys.executable,str(script)]), patch.object(bindkit_vault,'Vault',return_value=types.SimpleNamespace(get=lambda ref:'synthetic-sudo')):
            code,result=self.execute(as_user='root')
        self.assertEqual(code,255); self.assertIsNone(result['started'])
        self.assertEqual(result['error']['code'],'EXECUTION_STATE_UNKNOWN')
        self.assertEqual(self.policy.get_approval('ssh',request)['status'],'consumed')
    def test_changed_connection_invalidates_prior_approval(self):
        _,first=self.execute(as_user='root'); self.policy.approve('ssh',first['error']['request_id'])
        state=self.ssh.load_state(); state['servers']['demo']['revision']=2; self.ssh.save_state(state)
        code,result=self.execute(as_user='root'); self.assertEqual(code,6)
        self.assertNotEqual(first['error']['request_id'],result['error']['request_id'])
    def test_ai_approve_rechecks_gate_once_and_uses_trusted_context(self):
        def approve(tool,request_id,context,policy_module,**kw):
            self.assertEqual(context['operation'],'as_user'); self.assertTrue(context['hard_allowed']); self.assertFalse(context['protected'])
            self.assertEqual(context['resource']['alias'],'demo')
            policy_module.approve(tool,request_id,decided_by='ai'); return {'decision':'approve'}
        self.review.side_effect=approve
        with patch.object(bindkit_privilege,'execute_plan',return_value={'exit_code':0,'stdout':'ok','stderr':'','started':True,'authenticated':True,'error':None}):
            code,result=self.execute(as_user='root')
        self.assertEqual(code,0); self.assertEqual(self.review.call_count,1)
    def test_ai_rejection_never_creates_fresh_request_or_executes(self):
        def reject(tool,request_id,context,policy_module,**kw):
            policy_module.reject(tool,request_id,decided_by='ai'); return {'decision':'reject'}
        self.review.side_effect=reject
        with patch.object(bindkit_privilege,'execute_plan') as runner:
            code,result=self.execute(as_user='root')
        self.assertEqual(code,5); self.assertFalse(runner.called); self.assertEqual(len(self.policy.list_approvals('ssh')),1)
    def test_unsupported_legacy_privilege_is_rejected_without_transport(self):
        state=self.ssh.load_state(); state['servers']['demo']['sudo_auth']='nopasswd'; self.ssh.save_state(state)
        code,result=self.execute('sudo -i')
        self.assertNotEqual(code,0); self.assertEqual(result['error']['code'],'UNSUPPORTED_PRIVILEGE')
        self.assertFalse(self.transport.called); self.assertFalse(self.review.called)
    def test_disabled_managed_auth_preserves_legacy_sudo_flags_and_envelope(self):
        code,first=self.execute('sudo -n id')
        self.assertEqual(code,6)
        self.policy.approve('ssh',first['error']['request_id'])
        self.transport.return_value=(0,'legacy-sudo','')
        with patch.object(bindkit_privilege,'execute_plan') as managed:
            code,result=self.execute('sudo -n id')
        self.assertEqual(code,0); self.assertEqual(result['stdout'],'legacy-sudo')
        self.assertEqual(self.transport.call_args.args[0][-1],'sudo -n id')
        self.assertFalse(managed.called); self.assertNotIn('started',result)
    def test_plain_command_keeps_legacy_json_envelope(self):
        self.transport.return_value=(0,'legacy','noise')
        code,result=self.execute('uptime')
        self.assertEqual(code,0); self.assertEqual(result['stdout'],'legacy')
        self.assertNotIn('started',result); self.assertFalse(self.review.called)
    def test_invalid_combined_policy_never_updates_credentials(self):
        with patch.object(bindkit_connections,'update_connection') as update:
            with self.assertRaises(Exception): self.ssh.console_ssh_update('demo',{'private_key':'synthetic','sudo':'bogus'})
        self.assertFalse(update.called)
    def test_policy_persistence_failure_never_changes_credentials(self):
        with patch.object(bindkit_connections,'update_connection') as update, patch.object(self.policy,'write_policy',side_effect=OSError('disk full')):
            with self.assertRaises(Exception): self.ssh.console_ssh_update('demo',{'private_key':'synthetic','sudo':'deny'})
        self.assertFalse(update.called)
    def test_failed_credentials_restore_prior_policy(self):
        before=self.policy.read_policy('ssh')['data']
        with patch.object(bindkit_connections,'update_connection',side_effect=bindkit_connections.ConnectionError('failed')):
            with self.assertRaises(Exception): self.ssh.console_ssh_update('demo',{'private_key':'synthetic','sudo':'deny'})
        self.assertEqual(self.policy.read_policy('ssh')['data'],before)
    def test_create_backend_error_does_not_reflect_secret(self):
        with patch.object(self.ssh,'_run_self',side_effect=RuntimeError('synthetic-secret')):
            with self.assertRaises(Exception) as error:
                self.ssh.console_ssh_create({'name':'other','host':'example.invalid','password':'synthetic-secret'})
        self.assertNotIn('synthetic-secret',str(error.exception))
    def test_plain_stdin_keeps_binary_bytes(self):
        args=types.SimpleNamespace(name='demo',command=['cat'],json=True,timeout=10,as_user=None,stdin=True)
        with patch.object(self.ssh.sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(b'\xff\x00data'))), contextlib.redirect_stdout(io.StringIO()):
            self.ssh.cmd_exec(args)
        self.assertEqual(self.transport.call_args.kwargs['stdin_data'],b'\xff\x00data')
    def test_console_update_and_list_expose_only_safe_credential_status(self):
        self.ssh.console_ssh_update('demo',{'sudo_auth':'nopasswd','allowed_users':['app'],'note':'kept'})
        row=self.ssh.console_ssh_get('demo')
        self.assertEqual(row['sudo_auth'],'nopasswd'); self.assertEqual(row['allowed_users'],['app'])
        self.assertNotIn('sudo_credential_ref',row); self.assertEqual(row['note'],'kept')
    def test_discovered_users_never_include_passwd_hash_or_unbounded_fields(self):
        self.transport.return_value=(0,'app:x:1001:1001:Comment:/home/app:/bin/sh\nroot:hash:0:0:Root:/root:/bin/sh\n','')
        result=self.ssh.build_console_handlers()['users']('demo')
        self.assertEqual(result,{'users':[{'name':'app','uid':1001,'sensitive':False},{'name':'root','uid':0,'sensitive':True}]})
        self.assertEqual(self.transport.call_args.args[0][-1],'getent passwd')
    def test_security_configuration_operations_never_reach_ai(self):
        for command in ('cat /etc/sudoers', 'cat /etc/shadow', 'usermod -aG sudo alice', 'cat ~/.bindconsole/ai/config.json', 'cat ~/.ssh/authorized_keys', 'echo x > policy.json', "p''asswd lab", "printf x > /etc/sudo''ers", 'echo x > ~/.ssh/authorized_""keys', 'sh -c id', '$COMMAND id', 'tee /etc/sudo*', 'tee /etc/sudo{ers}', 'tee /etc/sudo?rs'):
            code,result=self.execute(command,as_user='root')
            self.assertEqual(code,6,command)
        self.assertFalse(self.review.called)
    def test_missing_db_write_flag_never_consumes_existing_approval(self):
        self.policy.write_policy('db',{'version':1,'defaults':{'max_level':'ddl','approval':{'write':True}}})
        rec={'name':'dbdemo','engine':'mysql','host':'db.invalid','user':'app','port':3306,'database':'target','read_only':True,'via':'local'}
        gate=self.db._policy_gate_db(rec,'UPDATE things SET value=1',True,False)
        self.policy.approve('db',gate['request_id'])
        with self.assertRaises(self.db.DbbindError): self.db._policy_gate_db(rec,'UPDATE things SET value=1',False,False)
        self.assertEqual(self.policy.get_approval('db',gate['request_id'])['consumes_left'],1)
    def test_db_connection_change_during_review_does_not_consume_approval(self):
        self.policy.write_policy('db',{'version':1,'defaults':{'max_level':'ddl','approval':{'write':True}}})
        rec={'name':'dbdemo','engine':'mysql','host':'db.invalid','user':'app','port':3306,'database':'target','read_only':True,'via':'local'}
        changed=dict(rec,host='changed.invalid')
        def approve(tool,request_id,context,policy_module,**kw):
            policy_module.approve(tool,request_id,decided_by='ai'); return {'decision':'approve'}
        self.review.side_effect=approve
        gate=self.db._policy_gate_db(rec,'UPDATE things SET value=1',True,False,refresh_record=lambda:changed)
        self.assertEqual(gate['decision'],'deny'); self.assertEqual(gate['code'],'CONNECTION_CHANGED')
        self.assertEqual(self.policy.list_approvals('db')[0]['consumes_left'],1)
    def test_db_ssh_alias_change_during_review_invalidates_approval(self):
        self.policy.write_policy('db',{'version':1,'defaults':{'max_level':'ddl','approval':{'write':True}}})
        rec={'name':'dbdemo','engine':'mysql','host':'localhost','user':'app','port':3306,'database':'target','read_only':True,'via':'ssh','via_ssh':'demo'}
        def approve(tool,request_id,context,policy_module,**kw):
            policy_module.approve(tool,request_id,decided_by='ai')
            state=self.ssh.load_state(); state['servers']['demo']['host']='changed.invalid'; self.ssh.save_state(state)
            return {'decision':'approve'}
        self.review.side_effect=approve
        gate=self.db._policy_gate_db(rec,'UPDATE things SET value=1',True,False,refresh_record=lambda:rec)
        self.assertEqual(gate['decision'],'deny'); self.assertEqual(gate['code'],'CONNECTION_CHANGED')
        self.assertEqual(self.policy.list_approvals('db')[0]['consumes_left'],1)
    def test_indirect_ssh_configuration_requires_human_review(self):
        self.policy.write_policy('db',{'version':1,'defaults':{'max_level':'ddl','approval':{'write':True}}})
        Path(self.ssh.SSH_CONFIG).write_text('Include ~/.ssh/extra-config\n')
        rec={'name':'dbdemo','engine':'mysql','host':'localhost','user':'app','port':3306,'database':'target','read_only':True,'via':'ssh','via_ssh':'demo'}
        gate=self.db._policy_gate_db(rec,'UPDATE things SET value=1',True,False)
        self.assertEqual(gate['decision'],'ask'); self.assertFalse(self.review.called)
    def test_db_ai_review_obeys_write_flags_and_binding(self):
        self.policy.write_policy('db',{'version':1,'defaults':{'max_level':'ddl','approval':{'write':True,'ddl':True}}})
        rec={'name':'dbdemo','engine':'mysql','host':'db.invalid','user':'app','port':3306,'database':'target','read_only':True,'via':'local'}
        with self.assertRaises(self.db.DbbindError):
            self.db._policy_gate_db(rec,'UPDATE things SET value=1',False,False)
        self.assertFalse(self.review.called); self.assertFalse(self.policy.list_approvals('db'))
        def approve(tool,request_id,context,policy_module,**kw):
            self.assertEqual(context['resource']['database'],'target'); self.assertEqual(context['operation'],'export'); self.assertEqual(context['effective_level'],'write')
            policy_module.approve(tool,request_id,decided_by='ai'); return {'decision':'approve'}
        self.review.side_effect=approve
        gate=self.db._policy_gate_db(rec,'UPDATE things SET value=1',True,False,operation='export')
        self.assertEqual(gate['decision'],'allow'); self.assertEqual(self.review.call_count,1)

if __name__=='__main__': unittest.main()
