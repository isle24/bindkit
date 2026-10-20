import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bindconsole'))
import bindkit_connections as connections

class Vault:
    def __init__(self): self.values={}; self.locked=False
    def status(self): return {'available':not self.locked,'backend':'fake','reason':None}
    def new_ref(self, prefix='credential'): return prefix+'-ref-'+str(len(self.values))
    def set(self, ref, value):
        if self.locked: raise RuntimeError('secret')
        self.values[ref]=value
    def get(self, ref): return self.values.get(ref)
    def delete(self, ref):
        if self.locked: raise RuntimeError("locked")
        self.values.pop(ref,None)

class SSH:
    def __init__(self, base):
        self.KEYS_DIR=base; self.STATE_FILE=os.path.join(base,'state.json')
        self.old=os.path.join(base,'old'); Path(self.old).write_text('old-key')
        self.state={'servers':{'example':{'name':'example','host':'old.invalid','port':22,'user':'alice','key':self.old,'installed':True,'policy':{'sudo':'ask'},'source':'generated'}}}
        self.valid=True; self.installs=[]; self.config=None; self.fail_save=False
    def load_state(self): return copy.deepcopy(self.state)
    def save_state(self,state):
        if self.fail_save: raise OSError('synthetic')
        self.state=copy.deepcopy(state)
    def write_ssh_config(self,servers): self.config=copy.deepcopy(servers)
    def test_connection(self,*args,**kwargs): return self.valid,['sensitive diagnostic']
    def read_pubkey_for(self,path): return 'ssh-ed25519 synthetic-public'
    def fingerprint_of(self,pub): return 'SHA256:synthetic'
    def gen_keypair(self,name):
        private=os.path.join(self.KEYS_DIR,name); Path(private).write_text('synthetic-new-key'); Path(private+'.pub').write_text('public'); return private,private+'.pub'
    def make_auth(self,mode,password=None): return {'mode':mode,'password':password}
    def install_pubkey(self,*args,**kwargs): self.installs.append((args,kwargs)); return True,'ok'

class ConnectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        environ=patch.dict(os.environ, {'HOME':self.temp.name}); environ.start(); self.addCleanup(environ.stop)
        self.ssh=SSH(self.temp.name); self.vault=Vault()
    def update(self,body): return connections.update_connection(self.ssh,'example',body,self.vault)
    def test_private_key_verified_before_update_and_old_key_retained(self):
        r=self.update({'private_key':'synthetic-private'})
        row=self.ssh.state['servers']['example']
        self.assertNotEqual(row['key'],self.ssh.old); self.assertEqual(Path(self.ssh.old).read_text(),'old-key')
        self.assertEqual(row['policy'],{'sudo':'ask'}); self.assertEqual(row['name'],'example'); self.assertEqual(row['revision'],1)
        self.assertNotIn('synthetic-private',json.dumps(r)); self.assertTrue(row['id'])
    def test_failed_replacement_preserves_state_and_cleans_candidate(self):
        before=copy.deepcopy(self.ssh.state); self.ssh.valid=False
        with self.assertRaises(connections.ConnectionError): self.update({'private_key':'bad-key','host':'new.invalid'})
        self.assertEqual(self.ssh.state,before)
        self.assertEqual(sorted(p.name for p in Path(self.temp.name).iterdir()),['.connections.lock','old'])
    def test_login_password_only_installs_key_never_changes_remote_password(self):
        self.update({'login_password':'synthetic-login'})
        self.assertEqual(len(self.ssh.installs),1)
        self.assertEqual(self.ssh.installs[0][0][3]['password'],'synthetic-login')
        self.assertNotIn('synthetic-login',json.dumps(self.ssh.state))
        self.assertTrue(Path(self.ssh.old).exists())
    def test_sudo_password_is_separate_keychain_reference(self):
        self.update({'sudo_password':'synthetic-sudo'})
        row=self.ssh.state['servers']['example']
        self.assertEqual(row['sudo_auth'],'keyring'); self.assertEqual(self.vault.values[row['sudo_credential_ref']],'synthetic-sudo')
        self.assertFalse(self.ssh.installs); self.assertNotIn('synthetic-sudo',json.dumps(self.ssh.state))
    def test_unavailable_keychain_changes_nothing(self):
        self.vault.locked=True; before=copy.deepcopy(self.ssh.state)
        with self.assertRaises(connections.ConnectionError): self.update({'sudo_password':'synthetic-sudo','login_password':'synthetic-login'})
        self.assertEqual(self.ssh.state,before); self.assertFalse(self.ssh.installs)
    def test_invalid_fields_fail_before_any_side_effect(self):
        for body in ({'port':0},{'user':'-root'},{'host':'bad host'},{'sudo_auth':'bad'},{'sudo_auth':'keyring'},{'sudo_auth':'none','sudo_password':'secret'},{'name':'renamed'}):
            with self.assertRaises(connections.ConnectionError, msg=str(body)): self.update(body)
        self.assertFalse(self.ssh.installs)
    def test_state_failure_rolls_back_config_and_staged_secret(self):
        self.ssh.fail_save=True; before=copy.deepcopy(self.ssh.state)
        with self.assertRaises(connections.ConnectionError): self.update({'sudo_password':'secret','private_key':'private'})
        self.assertEqual(self.ssh.config,before['servers']); self.assertFalse(self.vault.values)
    def test_public_status_has_no_references_or_secret_values(self):
        self.update({'sudo_password':'secret'})
        status=connections.public_credential_status(self.ssh.state['servers']['example'],self.vault)
        self.assertTrue(status['has_sudo_credential']); self.assertNotIn('sudo-ref',json.dumps(status)); self.assertNotIn('secret',json.dumps(status))
    def test_explicit_clear_deletes_current_keychain_secret(self):
        self.update({'sudo_password':'secret'})
        self.update({'clear_sudo_password':True})
        self.assertFalse(self.vault.values)
        self.assertIsNone(self.ssh.state['servers']['example']['sudo_credential_ref'])
    def test_clear_failure_keeps_reference_and_secret(self):
        self.update({'sudo_password':'secret'}); before=copy.deepcopy(self.ssh.state)
        self.vault.locked=True
        with self.assertRaises(connections.ConnectionError): self.update({'clear_sudo_password':True})
        self.assertEqual(self.ssh.state,before); self.assertTrue(self.vault.values)
    def test_clear_restores_keychain_secret_when_state_commit_fails(self):
        self.update({'sudo_password':'secret'}); before=copy.deepcopy(self.ssh.state); saved=dict(self.vault.values)
        self.ssh.fail_save=True
        with self.assertRaises(connections.ConnectionError): self.update({'clear_sudo_password':True})
        self.assertEqual(self.ssh.state,before); self.assertEqual(self.vault.values,saved)
    def test_nopasswd_clears_ref_but_keeps_old_credential(self):
        self.update({'sudo_password':'secret'}); self.update({'sudo_auth':'nopasswd'})
        row=self.ssh.state['servers']['example']; self.assertIsNone(row['sudo_credential_ref']); self.assertTrue(self.vault.values)

if __name__=='__main__': unittest.main()
