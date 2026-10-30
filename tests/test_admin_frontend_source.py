"""Synthetic frontend interaction checks; no browser, service or credential access."""
import pathlib
import shutil
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


FRONTEND_HARNESS = r'''
const assert = require('assert');
const fs = require('fs');
class N {
  constructor(tag, attrs={}, children=[]) { this.tag=tag; this.attrs=attrs; this.children=[]; this.events={}; this.value=attrs.value||''; this.checked=!!attrs.checked; this.disabled=!!attrs.disabled; this.hidden=!!attrs.hidden; this.textContent=attrs.text||''; this.id=attrs.id||''; this.append(...children); }
  append(...items) { items.filter(Boolean).forEach(x=>{ this.children.push(x); x.parentNode=this; }); }
  appendChild(x) { this.append(x); return x; }
  addEventListener(k,fn) { this.events[k]=fn; }
  setAttribute(k,v) { this.attrs[k]=v; }
  querySelector() { return null; }
  focus() {}
  removeChild(x) { this.children=this.children.filter(v=>v!==x); }
}
let nodes=[], requests=[], modals=[], cleanups=[], refresh, handler;
const make=(tag,a={},c=[])=>{const n=new N(tag,a,c);nodes.push(n);return n;};
const UI={el:make,clear:n=>n.children=[],textInput:o=>make('input',o),textareaInput:o=>make('textarea',o),
 selectInput:o=>make('select',o),field:(label,control)=>make('field',{text:label},[control]),
 button:o=>{let n=make('button',{...o,text:o.label});if(o.onClick)n.events.click=o.onClick;return n;},
 btnLink:(label,o={})=>make('button',{...o,text:label}),checkboxInput:(label,o={})=>{let input=make('input',{...o,type:'checkbox'});return{input,wrap:make('label',{text:label},[input])};},
 pageHeader:o=>({el:make('header',{},o.actions||[]),setCount:()=>{}}),
 dataTable:(cols,rows)=>{let el=make('table');rows.forEach(r=>cols.forEach(c=>el.append(c.render(r))));return{el};},
 openFormModal:o=>{modals.push(o);return{modal:{isClosed:()=>false},close:()=>{},setError:()=>{}};},
 openModal:o=>{modals.push(o);let closed=false;return{body:make('div',{},o.body||[]),footer:make('div',{},o.footer||[]),close:()=>{closed=true;if(o.onClose)o.onClose();},isClosed:()=>closed};},
 formError:()=>({el:make('error'),hide:()=>{},show:()=>{}}),
 loadingBlock:()=>make('loading'),emptyBlock:o=>make('empty',o),errorBlock:e=>make('error',{text:e.message}),
 badge:t=>make('badge',{text:t}),chip:t=>make('chip',{text:t}),flag:()=>make('flag'),
 fmtDateTime:v=>v,truncate:v=>v,successToast:()=>{},toast:()=>{},errorToast:()=>{}};
const net={};['get','post','put','del'].forEach(method=>net[method]=(url,body)=>{requests.push({method,url,body:body===undefined?undefined:JSON.parse(JSON.stringify(body))});return Promise.resolve().then(()=>handler(method,url,body));});
let tool='ssh';
global.window={BC:{ui:UI,net,app:{state:{tool:'ssh',resource:'servers'},isCurrent:()=>true,ensurePolicy:()=>Promise.resolve(),policyEntry:()=>({}),policyDefaults:()=>({}),registerSilentRefresher:fn=>refresh=fn,registerCleanup:fn=>cleanups.push(fn)}}};
global.document={createTextNode:t=>make('text',{text:t})};
const BC=window.BC;
eval(fs.readFileSync('bindconsole/web/pages.js','utf8'));
const flush=async()=>{for(let i=0;i<15;i++)await Promise.resolve();};
const find=id=>nodes.filter(n=>n.attrs.testid===id||n.attrs['data-testid']===id).at(-1);
const click=async n=>{assert(n,'missing control');await n.events.click({preventDefault(){}});await flush();};
const change=async(n,value)=>{n.value=value;await n.events.change({preventDefault(){}});await flush();};
'''


@unittest.skipUnless(shutil.which('node'), 'Node is required for frontend checks')
class AdminFrontendTests(unittest.TestCase):
    def test_password_form_selects_native_password_authentication(self):
        script = FRONTEND_HARNESS + r'''
(async()=>{
 handler=(m,url,b)=>url==='/api/servers'?{servers:[]}:{};
 BC.pages.servers(make('view'),{epoch:1});await flush();
 const add=nodes.find(n=>n.tag==='button'&&n.textContent==='添加服务器');
 await click(add);const form=modals.at(-1);
 find('f-name').value='synthetic';find('f-host').value='example.invalid';find('f-user').value='operator';find('f-port').value='22';
 find('f-password').value='synthetic%$LITERAL';
 assert.strictEqual(form.validate(),null);
 await form.onSubmit({close(){}});await flush();
 const body=requests.find(r=>r.method==='post'&&r.url==='/api/servers').body;
 assert.strictEqual(body.auth_type,'password');
 assert.strictEqual(body.password,'synthetic%$LITERAL');
 assert.strictEqual(find('f-password').value,'');
 assert(nodes.some(n=>n.textContent==='密码登录'));
 requests=[];nodes=[];
 handler=(m,url,b)=>({servers:[{name:'password-demo',host:'example.invalid',user:'operator',port:22,auth_type:'password',has_login_credential:true,installed:true,usable:true}]});
 BC.pages.servers(make('view'),{epoch:2});await flush();
 assert(nodes.some(n=>n.textContent==='密码登录'));
 console.log('Native password form checks passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', script], cwd=ROOT, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_admin_workflows_with_synthetic_api(self):
        script = FRONTEND_HARNESS + r'''
(async()=>{
  handler=(m,url,b)=>url==='/api/audit'?{entries:[{ts:'today',alias:'synthetic'}],total:101,page:b.page,page_size:b.page_size,pages:3,has_next:b.page<3,has_prev:b.page>1,snapshot:'stable-fixture'}:{};
  BC.pages.audit(make('view'),{epoch:1});await flush();
  assert.strictEqual(requests.at(-1).body.page,1);
  assert.strictEqual(requests.at(-1).body.page_size,50);
  find('audit-actor').value='not-applied-yet';
  await click(find('audit-next'));
  assert.strictEqual(requests.at(-1).body.actor,'');
  assert.strictEqual(requests.at(-1).body.page,2);
  assert.strictEqual(requests.at(-1).body.snapshot,'stable-fixture');
  await change(find('audit-decision'),'deny');
  assert.strictEqual(requests.at(-1).body.page,1);
  assert(!requests.at(-1).body.snapshot);
  const normalAudit=handler;
  let expired=false;
  handler=(m,url,b)=>{
    if(url==='/api/audit'&&b.snapshot&&!expired){expired=true;throw{status:413,message:'snapshot fixture expired'};}
    return normalAudit(m,url,b);
  };
  await click(find('audit-next'));
  assert.strictEqual(requests.at(-1).body.page,1);
  assert(!requests.at(-1).body.snapshot);

  nodes=[];requests=[];
  handler=(m,url,b)=>{
    if(url==='/api/ai/config')return{mode:m==='put'?b.mode:'auto',base_url:'https://fixture.invalid/v1',model:'fixture',scopes:{ssh:['demo'],db:['keep-db']},ttl_s:60,has_api_key:true,sdk_available:true,vault:{available:true}};
    if(url==='/api/servers')return{servers:[{name:'demo'}]};
    if(url==='/api/ai/service/status')return{running:m!=='post',pid:123};
    if(url==='/api/ai/service/stop')return{running:false};
    return{};
  };
  assert.strictEqual(typeof BC.pages.ai,'function');
  BC.pages.ai(make('view'),{epoch:2});await flush();
  const aiHandler=handler;
  handler=(m,url,b)=>url==='/api/ai/models'?{models:[],error:'fixture provider unavailable'}:aiHandler(m,url,b);
  await click(find('ai-models'));
  assert.strictEqual(find('ai-message').textContent,'');
  find('ai-ttl').value='0'; find('ai-base-url').value='invalid unsaved url';
  handler=aiHandler;
  await click(find('ai-disable'));
  const saved=requests.find(r=>r.method==='put'&&r.url==='/api/ai/config');
  assert.strictEqual(saved.body.mode,'off');
  assert.deepStrictEqual(saved.body.scopes.db,['keep-db']);
  assert(requests.some(r=>r.method==='post'&&r.url==='/api/ai/service/stop'));
  assert(!requests.some(r=>r.url.includes('api_key=')));
  nodes=[]; requests=[]; modals=[];
  const server={name:'demo',user:'deploy',host:'fixture.invalid',port:22,sudo:'ask',sudo_auth:'keyring',has_sudo_credential:true,keychain:{available:true,backend:'synthetic'},allowed_users:['app']};
  handler=(m,url,b)=>{
    if(url==='/api/servers')return{servers:[server]};
    if(url==='/api/servers/demo/users')return{users:[{name:'app',uid:1001,sensitive:false},{name:'root',uid:0,sensitive:true}]};
    if(url==='/api/servers/demo'&&m==='get')return server;
    if(url==='/api/servers/demo'&&m==='put')throw{message:'synthetic verification failed'};
    return{};
  };
  BC.pages.servers(make('view'),{epoch:3});await flush();
  await click(find('edit-demo'));
  assert.strictEqual(find('f-login-password').value,'');
  assert.strictEqual(find('f-sudo-password').value,'');
  const edit=modals.at(-1);
  find('f-approval-ttl').value='0'; find('f-login-password').value='fixture-discard';
  assert(edit.validate());
  assert.strictEqual(find('f-login-password').value,'');
  find('f-approval-ttl').value='';
  find('f-login-password').value='synthetic-login';
  find('f-sudo-password').value='synthetic-sudo';
  await edit.onSubmit({close(){}}).catch(()=>{});
  const changeRequest=requests.find(r=>r.method==='put');
  assert.strictEqual(changeRequest.body.login_password,'synthetic-login');
  assert.strictEqual(changeRequest.body.sudo_password,'synthetic-sudo');
  assert.deepStrictEqual(changeRequest.body.allowed_users,['app']);
  assert.strictEqual(find('f-login-password').value,'');
  assert.strictEqual(find('f-sudo-password').value,'');
  find('f-private-key').value='synthetic-key';edit.onClose();
  assert.strictEqual(find('f-private-key').value,'');
  await edit.onSubmit({close(){}}).catch(()=>{});
  const blankUpdate=requests.filter(r=>r.method==='put').at(-1);
  assert(!('login_password' in blankUpdate.body));
  assert(!('private_key' in blankUpdate.body));
  assert(!('sudo_password' in blankUpdate.body));
  nodes=[];requests=[];modals=[];
  global.FileReader=class{readAsDataURL(){this.result='data:text/plain;base64,c3ludGhldGlj';this.onload();}};
  handler=(m,url,b)=>{
    if(url==='/api/servers')return{servers:[server]};
    if(url==='/api/imports/preview')return{preview_id:'fixture-preview',expires_at:'tomorrow',count:2,warnings:[],items:[0,1].map(i=>({id:'i'+i,name:'import-'+i,host:'fixture.invalid',user:i===1?'':'deploy',port:22,source:'xshell',auth_type:'password',requires_credentials:true,has_imported_password:false,credential_status:'missing',warnings:[]}))};
    if(url==='/api/imports/commit')return{results:[{id:'i0',name:'import-0',ok:true},{id:'i1',name:'import-1',ok:false,error:'synthetic failed'}],imported:1,failed:1};
    return{};
  };
  BC.pages.servers(make('view'),{epoch:4});await flush();
  await click(find('btn-import'));
  find('import-files').files=[{name:'too-large.zip',size:16*1024*1024+1}];
  await click(find('import-preview'));
  assert(!requests.some(r=>r.url==='/api/imports/preview'));
  find('import-files').files=[{name:'fixture.xsh',size:42}];
  await click(find('import-preview'));
  find('import-password-0').value='fixture-pass';find('import-password-1').value='fixture-pass';
  assert.strictEqual(find('import-user-1').value,'');
  await click(find('import-commit'));
  assert(!requests.some(r=>r.url==='/api/imports/commit'));
  find('import-user-1').value='CORP\\operator';
  await click(find('import-commit'));
  assert.strictEqual(requests.find(r=>r.url==='/api/imports/commit').body.items[1].user,'CORP\\operator');
  assert.strictEqual(requests.filter(r=>r.url==='/api/imports/commit').length,1);
  assert(find('import-result-0').textContent.includes('已导入'));
  assert(find('import-result-1').textContent.includes('synthetic failed'));
  assert.strictEqual(find('import-select-0').checked,false);
  assert.strictEqual(find('import-select-1').checked,true);
  assert.strictEqual(find('import-name-1').value,'import-1');
  assert.strictEqual(find('import-password-1').value,'');
  assert.strictEqual(find('import-password-0').disabled,true);

})().catch(e=>{process.stderr.write(e.stack);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', script], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_import_batch_unlock_and_explicit_pending_confirmation(self):
        script = FRONTEND_HARNESS + r'''
const item=i=>({id:'i'+i,name:'fixture-'+i,host:'fixture.invalid',port:22,user:'deploy',source:'xshell',auth_type:'password',has_imported_password:true,credential_status:'available',requires_credentials:false,warnings:[]});
let previewItems=[item(0)], commitHandler=()=>({results:[]});
let readCount=0;
global.FileReader=class{readAsDataURL(){readCount++;this.result='data:text/plain;base64,c3ludGhldGlj';this.onload();}};
const commits=()=>requests.filter(r=>r.url==='/api/imports/commit');
const open=async()=>{
  nodes=[];requests=[];modals=[];
  handler=(m,url,b)=>{
    if(url==='/api/servers')return{servers:[{name:'fixture-pending',verification_status:'pending',usable:false,installed:false,source:'imported',host:'fixture.invalid',user:'deploy',port:22}]};
    if(url==='/api/imports/preview')return{preview_id:'synthetic-preview',items:previewItems,expires_at:1793200000,warnings:[]};
    if(url==='/api/imports/commit')return commitHandler(b);
    return{};
  };
  BC.pages.servers(make('view'),{epoch:5});await flush();
  assert(find('verification-fixture-pending').textContent.includes('待验证'));
  await click(find('btn-import'));
};
(async()=>{
  await open();
  assert.strictEqual(find('import-directory').attrs.webkitdirectory,true);
  assert.strictEqual(find('import-files').attrs.multiple,true);
  assert(find('import-files').attrs.accept.includes('.xts'));
  assert.strictEqual(find('import-master-password').attrs.type,'password');
  assert.strictEqual(find('import-master-password').value,'');
  find('import-files').files=[{name:'too-big.xts',size:16*1024*1024+1}];
  await click(find('import-preview'));
  assert.strictEqual(readCount,0);
  find('import-files').files=Array.from({length:1025},(_,i)=>({name:i+'.xsh',size:1}));
  await click(find('import-preview'));assert.strictEqual(readCount,0);
  find('import-files').files=[{name:'sessions.xts',size:1024*1024}];
  find('import-directory').files=[{name:'session.xsh',webkitRelativePath:'sessions/session.xsh',size:12}];
  find('import-master-password').value='synthetic-unlock';
  find('import-source-username').value='fixture-user';find('import-source-sid').value='S-1-5-21-123';
  await click(find('import-preview'));
  let uploaded=requests.find(r=>r.url==='/api/imports/preview').body;
  assert.strictEqual(uploaded.files.length,2);
  assert.strictEqual(uploaded.files[1].name,'sessions/session.xsh');
  assert.deepStrictEqual(uploaded.credentials,{master_password:'synthetic-unlock',source_username:'fixture-user',source_sid:'S-1-5-21-123'});
  assert.strictEqual(find('import-master-password').value,'');
  assert.strictEqual(find('import-files').files.length,1);
  assert.strictEqual(find('import-password-0').value,'');
  assert(find('import-credential-0').textContent.includes('已恢复'));
  commitHandler=b=>({results:b.items.map(x=>({id:x.id,name:x.name,ok:false,can_add_unverified:true,error:'synthetic unreachable'}))});
  await click(find('import-commit'));
  assert.strictEqual(commits().length,1);
  assert(!('allow_unverified' in commits()[0].body.items[0]));
  assert(!('login_password' in commits()[0].body.items[0]));
  assert(!find('import-deferred').hidden);
  assert.strictEqual(find('import-deferred-select-0').checked,false);
  await click(find('import-deferred-cancel'));
  assert.strictEqual(commits().length,1);
  assert(find('import-deferred').hidden);
  assert.strictEqual(find('import-select-0').checked,true);
  await click(find('import-commit'));
  assert.strictEqual(commits().length,2);
  await click(find('import-deferred-confirm'));
  assert.strictEqual(commits().length,2);
  find('import-deferred-select-0').checked=true;
  await change(find('import-deferred-select-0'),true);
  commitHandler=b=>({results:b.items.map(x=>({id:x.id,name:x.name,ok:true,pending:true,verified:false})),pending:1});
  await click(find('import-deferred-confirm'));
  assert.strictEqual(commits().length,3);
  assert.strictEqual(commits()[2].body.items[0].allow_unverified,true);
  assert(find('import-result-0').textContent.includes('待验证'));
  assert(!find('import-result-0').textContent.includes('已连接'));
  assert.strictEqual(find('import-select-0').checked,false);

  previewItems=Array.from({length:23},(_,i)=>({...item(i),has_imported_password:i!==1,credential_status:i===1?'needs_context':'available',requires_credentials:i===1}));
  await open();
  find('import-files').files=[{name:'sessions.zip',size:100}];await click(find('import-preview'));
  assert(find('import-credential-1').textContent.includes('原始文件'));
  find('import-password-0').value='synthetic-manual';
  let inFlight=0, maxInFlight=0, progress=[];
  commitHandler=async b=>{
    inFlight++;maxInFlight=Math.max(maxInFlight,inFlight);progress.push(find('import-status').textContent);
    await Promise.resolve();inFlight--;
    return{results:b.items.map(x=>({id:x.id,name:x.name,ok:x.id!=='i1'&&x.id!=='i2',verified:x.id!=='i1'&&x.id!=='i2',can_add_unverified:x.id==='i1',error:'synthetic failed'}))};
  };
  await click(find('import-commit'));
  assert.deepStrictEqual(commits().map(r=>r.body.items.length),[10,10,3]);
  assert.strictEqual(maxInFlight,1);
  assert(progress[0].includes('0 / 23')&&progress[1].includes('10 / 23')&&progress[2].includes('20 / 23'));
  assert.strictEqual(find('import-password-0').value,'');
  assert.strictEqual(find('import-select-1').checked,true);
  assert(find('import-deferred-select-1'));
  assert(!find('import-deferred-select-2'));
  find('import-deferred-select-1').checked=true;
  commitHandler=b=>({results:b.items.map(x=>({id:x.id,name:x.name,ok:true,pending:true}))});
  await click(find('import-deferred-confirm'));
  assert.deepStrictEqual(commits().at(-1).body.items,[{id:'i1',name:'fixture-1',user:'deploy',allow_unverified:true}]);
  assert.strictEqual(find('import-select-2').checked,true);

  previewItems=[{...item(0),has_imported_password:false,credential_status:'invalid',requires_credentials:true}];
  await open();find('import-files').files=[{name:'session.xsh',size:3}];await click(find('import-preview'));
  find('import-password-0').value='synthetic-discard';find('import-key-0').value='';
  commitHandler=()=>{throw{message:'synthetic HTTP failure'};};
  await click(find('import-commit'));
  assert.strictEqual(commits().length,1);
  assert.strictEqual(find('import-password-0').value,'');
  assert(find('import-deferred').hidden);
  assert.strictEqual(find('import-select-0').checked,true);
  commitHandler=b=>({results:b.items.map(x=>({id:x.id,name:x.name,ok:true,verified:true}))});
  await click(find('import-commit'));assert.strictEqual(commits().length,2);
  assert(!('login_password' in commits()[1].body.items[0]));
  assert(find('import-result-0').textContent.includes('已导入'));

  // A later HTTP failure stops following chunks, clears unsent secrets, and
  // never turns an uncertain request into an offline-add permission.
  previewItems=Array.from({length:23},(_,i)=>item(i));
  await open();find('import-files').files=[{name:'sessions.zip',size:3}];await click(find('import-preview'));
  find('import-key-11').value='synthetic-key';find('import-password-22').value='synthetic-unsent';
  let batch=0;
  commitHandler=b=>{batch++;if(batch===2)throw{message:'synthetic interrupted'};return{results:b.items.map(x=>({id:x.id,name:x.name,ok:true,verified:true}))};};
  await click(find('import-commit'));
  assert.deepStrictEqual(commits().map(r=>r.body.items.length),[10,10]);
  assert.strictEqual(find('import-key-11').value,'');assert.strictEqual(find('import-password-22').value,'');
  assert.strictEqual(find('import-select-0').checked,false);assert.strictEqual(find('import-select-11').checked,true);
  assert(find('import-result-11').textContent.includes('请求未完成'));
  assert(find('import-deferred').hidden);

  // Request failures and preview limits never retain the unlock password or
  // private keys in form fields, and never commit any connection.
  await open();
  find('import-files').files=[{name:'sessions.xts',size:3}];find('import-master-password').value='synthetic-unlock';
  const baseHandler=handler;
  handler=(m,url,b)=>{if(url==='/api/imports/preview')throw{message:'synthetic preview failure'};return baseHandler(m,url,b);};
  await click(find('import-preview'));
  assert.strictEqual(find('import-master-password').value,'');assert.strictEqual(commits().length,0);
  assert.strictEqual(find('import-files').files.length,1);
  handler=baseHandler;previewItems=Array.from({length:1025},(_,i)=>item(i));
  await click(find('import-preview'));assert(find('import-commit').disabled);
  assert(!find('import-password-0'));
  previewItems=[item(0)];await click(find('import-preview'));
  find('import-password-0').value='synthetic-close';find('import-key-0').value='synthetic-close-key';
  find('import-master-password').value='synthetic-close-unlock';find('import-bulk-password').value='synthetic-close-bulk';
  await click(find('import-close'));
  assert.strictEqual(find('import-password-0').value,'');assert.strictEqual(find('import-key-0').value,'');
  assert.strictEqual(find('import-master-password').value,'');assert.strictEqual(find('import-bulk-password').value,'');
})().catch(e=>{process.stderr.write(e.stack);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', script], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_saved_xshell_cipher_unlock_never_tests_or_exposes_credentials(self):
        script = FRONTEND_HARNESS + r'''
(async()=>{
  let fail=true, notices=[];
  UI.successToast=message=>notices.push(message);
  handler=(m,url,b)=>{
    if(url==='/api/servers')return{servers:[{name:'locked',user:'deploy',host:'fixture.invalid',port:22,verification_status:'pending',has_encrypted_login:true},{name:'plain',host:'fixture.invalid',user:'deploy',port:22}]};
    if(url==='/api/servers/locked/unlock'){if(fail==='result')return{ok:false,code:'CREDENTIAL_UNLOCK_FAILED',message:'synthetic incorrect master'};if(fail)throw{message:'synthetic incorrect context'};return{ok:true,unlocked:true};}
    return{};
  };
  BC.pages.servers(make('view'),{epoch:6});await flush();
  assert(find('unlock-locked'));assert(!find('unlock-plain'));
  await click(find('unlock-locked'));
  let form=modals.at(-1);
  assert.strictEqual(find('unlock-master-password').attrs.type,'password');
  assert.strictEqual(find('unlock-master-password').value,'');
  assert(form.validate());
  find('unlock-master-password').value='synthetic-wrong';
  find('unlock-source-username').value='fixture-user';find('unlock-source-sid').value='S-1-5-21-123';
  assert.strictEqual(form.validate(),null);
  await form.onSubmit({close(){}}).catch(()=>{});
  const failed=requests.find(r=>r.url.endsWith('/unlock'));
  assert.deepStrictEqual(failed.body,{credentials:{master_password:'synthetic-wrong',source_username:'fixture-user',source_sid:'S-1-5-21-123'}});
  assert.strictEqual(find('unlock-master-password').value,'');
  assert(!requests.some(r=>r.url.endsWith('/test')));
  assert.strictEqual(notices.length,0);
  let closed=0, rejected=null;
  const listReads=requests.filter(r=>r.url==='/api/servers').length;
  find('unlock-master-password').value='synthetic-wrong-result';fail='result';
  await form.onSubmit({close(){closed++;}}).catch(error=>{rejected=error;});await flush();
  assert(rejected,'ok:false must keep the form open and display a safe failure');
  assert(rejected.message.includes('解锁失败'));
  assert(!rejected.message.includes('synthetic-wrong-result'));
  assert.strictEqual(find('unlock-master-password').value,'');
  assert.strictEqual(closed,0);assert.strictEqual(notices.length,0);
  assert.strictEqual(requests.filter(r=>r.url==='/api/servers').length,listReads);
  find('unlock-master-password').value='synthetic-correct';fail=false;
  await form.onSubmit({close(){closed++;}});await flush();
  assert.strictEqual(closed,1);
  assert.strictEqual(find('unlock-master-password').value,'');
  assert(notices.some(x=>x.includes('已解锁，可点击测试连接')));
  assert(!requests.some(r=>r.url.endsWith('/test')));
  assert(!requests.some(r=>r.method==='put'));
  find('unlock-master-password').value='synthetic-close';form.onClose();
  assert.strictEqual(find('unlock-master-password').value,'');
})().catch(e=>{process.stderr.write(e.stack);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', script], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
