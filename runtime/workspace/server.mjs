import readline from 'node:readline';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { chromium } from 'playwright';

const pending = new Map();
let sequence = 0;
let active = null;
const contexts = new Map();
let browser;

function send(message) {
  process.stdout.write(JSON.stringify(message) + '\n');
}
function fail(code) {
  return { error: code };
}
async function broker(request) {
  if (!active) return fail('no_active_action');
  if (typeof request.url !== 'string' || request.url.length > 2048 ||
      typeof request.body !== 'string' || request.body.length > 32768 ||
      typeof request.method !== 'string' || !['GET','HEAD','POST','PUT','PATCH','DELETE'].includes(request.method)) return fail('invalid_request');
  const id = ++sequence;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve(fail('broker_timeout'));
    }, 45000);
    pending.set(id, (value) => { clearTimeout(timer); resolve(value); });
    send({ type: 'network_request', id, action_id: active.id, request });
  });
}
const socketServer = net.createServer((socket) => {
  let data = '';
  socket.setTimeout(45000, () => socket.destroy());
  socket.on('data', async (chunk) => {
    data += chunk.toString('utf8');
    if (data.length > 65536) return socket.destroy();
    const position = data.indexOf('\n');
    if (position < 0) return;
    const line = data.slice(0, position);
    data = '';
    try {
      const request = JSON.parse(line);
      const reply = await broker(request);
      socket.end(JSON.stringify(reply) + '\n');
    } catch {
      socket.end(JSON.stringify(fail('invalid_request')) + '\n');
    }
  });
});
socketServer.listen('/tmp/opensec-http.sock');

async function contextFor(identity) {
  const key = identity || '';
  if (contexts.has(key)) return contexts.get(key);
  const context = await browser.newContext({ serviceWorkers:'block', acceptDownloads:false });
  await context.route('**/*', async (route) => {
    const request = route.request();
    if (!active || (active.action.identity_ref || '') !== key) return route.abort();
    const body = request.postData() || '';
    const headers = {};
    for (const name of ['accept','content-type','if-match','if-none-match','x-requested-with']) {
      const value = request.headers()[name];
      if (value) headers[name] = value;
    }
    const result = await broker({url:request.url(),method:request.method(),headers,body});
    if (result.error) return route.abort();
    try {
      await route.fulfill({ status:result.status, headers:result.headers || {}, body:Buffer.from(result.body_base64 || '', 'base64') });
    } catch { await route.abort().catch(() => {}); }
  });
  if (typeof context.routeWebSocket === 'function') {
    await context.routeWebSocket('**/*', (socket) => socket.close());
  }
  const page = await context.newPage();
  const value = { context, page };
  contexts.set(key,value);
  return value;
}
async function command(script) {
  return new Promise((resolve, reject) => {
    const proc = spawn('/bin/bash',['-lc',script],{cwd:'/work',env:{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:'/work',TMPDIR:'/tmp',LANG:'C.UTF-8'},detached:true,stdio:['ignore','pipe','pipe']});
    let out='',overflow=false,timedOut=false;
    const timer=setTimeout(() => { timedOut=true;try {process.kill(-proc.pid,'SIGKILL');}catch{} },10000);
    for (const stream of [proc.stdout,proc.stderr]) stream.on('data',(chunk) => {
      if (out.length + chunk.length > 8192) { overflow=true; try {process.kill(-proc.pid,'SIGKILL');}catch{};return; }
      out += chunk.toString('utf8');
    });
    proc.on('error',() => { clearTimeout(timer);reject(new Error('command_failed')); });
    proc.on('close',(code) => {
      clearTimeout(timer);
      try {process.kill(-proc.pid,'SIGKILL');}catch{}
      if (timedOut || overflow) return reject(new Error('command_limit'));
      resolve(out.slice(0,8192) + '\nexit=' + code);
    });
  });
}
async function execute(action) {
  switch(action.kind) {
    case 'request': {
      const response=await broker({url:action.url,method:action.method || 'GET',headers:action.headers || {},body:action.body || ''});
      if(response.error) return response.error;
      return 'status=' + response.status + '\nheaders=' + JSON.stringify(response.headers || {}) + '\nbody=' + Buffer.from(response.body_base64 || '', 'base64').toString('utf8').slice(0,8192);
    }
    case 'navigate': {
      const {page}=await contextFor(action.identity_ref);
      await page.goto(action.url,{waitUntil:'domcontentloaded',timeout:30000});
      return 'url=' + page.url() + '\n' + (await page.locator('body').innerText({timeout:5000})).slice(0,8192);
    }
    case 'snapshot': {
      const {page}=await contextFor(action.identity_ref);
      return 'url=' + page.url() + '\n' + (await page.locator('body').innerText({timeout:5000})).slice(0,8192);
    }
    case 'click': {
      const {page}=await contextFor(action.identity_ref);
      await page.locator(action.selector).first().click({timeout:10000});
      return 'url=' + page.url() + '\n' + (await page.locator('body').innerText({timeout:5000})).slice(0,8192);
    }
    case 'fill': {
      const {page}=await contextFor(action.identity_ref);
      await page.locator(action.selector).first().fill(action.value,{timeout:10000});
      return 'url=' + page.url() + '\n' + (await page.locator('body').innerText({timeout:5000})).slice(0,8192);
    }
    case 'command': return command(action.script);
    default: return 'unsupported_action';
  }
}
async function action(message) {
  if (active) return send({type:'action_result',id:message.id,error:'action_busy'});
  active=message;
  try {
    const text=await execute(message.action);
    send({type:'action_result',id:message.id,text:String(text).slice(0,8192)});
  } catch {
    send({type:'action_result',id:message.id,error:'tool_failed'});
  } finally { active=null; }
}
readline.createInterface({input:process.stdin}).on('line',(line) => {
  try {
    const message=JSON.parse(line);
    if (message.type==='network_reply') {
      const done=pending.get(message.id);
      if(done) {pending.delete(message.id);done(message.response || fail('broker_missing_response'));}
    } else if (message.type==='action') void action(message);
  } catch {}
});
process.on('SIGTERM',async()=>{await browser?.close();process.exit(0)});
try {
  browser=await chromium.launch({headless:true,chromiumSandbox:true,args:['--disable-background-networking','--disable-component-update']});
  send({type:'ready',browser_version:browser.version()});
} catch (error) {
  send({type:'fatal',error:'browser_launch_failed',text:String(error?.message || '').slice(-2048)});
  process.exit(2);
}
