"""Synthetic frontend interaction checks; no browser, service or credential access."""
import pathlib
import shutil
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('node'), 'Node is required for frontend checks')
class AdminFrontendTests(unittest.TestCase):
    def test_admin_workflows_with_synthetic_api(self):
        script = r'''
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
 openModal:o=>{modals.push(o);return{body:make('div'),footer:make('div'),close:()=>{},isClosed:()=>false};},
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
const find=id=>nodes.find(n=>n.attrs.testid===id||n.attrs['data-testid']===id);
const click=async n=>{assert(n,'missing control');await n.events.click({preventDefault(){}});await flush();};
const change=async(n,value)=>{n.value=value;await n.events.change({preventDefault(){}});await flush();};
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
    if(url==='/api/imports/preview')return{preview_id:'fixture-preview',expires_at:'tomorrow',count:2,warnings:[],items:[0,1].map(i=>({id:'i'+i,name:'import-'+i,host:'fixture.invalid',user:i===1?'':'deploy',port:22,source:'xshell',auth_type:'password',requires_credentials:true,warnings:[]}))};
    if(url==='/api/imports/commit')return{results:[{id:'i0',name:'import-0',ok:true},{id:'i1',name:'import-1',ok:false,error:'synthetic failed'}],imported:1,failed:1};
    return{};
  };
  BC.pages.servers(make('view'),{epoch:4});await flush();
  await click(find('btn-import'));
  find('import-files').files=[{name:'too-large.zip',size:701*1024}];
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


if __name__ == '__main__':
    unittest.main()
