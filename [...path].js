'use strict';
// API única (Vercel Function) + PostgreSQL (Neon/Supabase). Defina DATABASE_URL e ADMIN_PASSWORD.
const crypto=require('node:crypto');
const {Pool}=require('pg');
const pool=global._pool||(global._pool=new Pool({connectionString:process.env.DATABASE_URL,max:1,idleTimeoutMillis:10000,ssl:process.env.DATABASE_URL&&!/localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL)?{rejectUnauthorized:false}:false}));
const q=async(s,a=[])=>(await pool.query(s,a)).rows,q1=async(s,a)=>(await q(s,a))[0];
const SCHEMA=`
CREATE TABLE IF NOT EXISTS docs(col text,id text,data jsonb NOT NULL,PRIMARY KEY(col,id));
CREATE TABLE IF NOT EXISTS users(login text PRIMARY KEY,salt text,hash text,perfil text NOT NULL,emp_id text,ativo boolean DEFAULT true,ultimo timestamptz,falhas int DEFAULT 0,bloq_ate bigint DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token text PRIMARY KEY,login text,exp bigint);
CREATE TABLE IF NOT EXISTS audit(n bigserial PRIMARY KEY,ts timestamptz DEFAULT now(),quem text,acao text,det text);
CREATE OR REPLACE FUNCTION bloqueia() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'Registro confirmado: bloqueado'; END $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS imut ON docs;
CREATE TRIGGER imut BEFORE UPDATE OR DELETE ON docs FOR EACH ROW WHEN (OLD.col IN ('launches','attendance')) EXECUTE FUNCTION bloqueia();
DROP TRIGGER IF EXISTS aud ON audit;
CREATE TRIGGER aud BEFORE UPDATE OR DELETE ON audit FOR EACH ROW EXECUTE FUNCTION bloqueia();`;
let ready;
const init=()=>ready||(ready=(async()=>{const c=await pool.connect();try{await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock(4242)');await c.query(SCHEMA);await c.query('COMMIT')}catch(e){await c.query('ROLLBACK').catch(()=>{});ready=null;throw e}finally{c.release()}})());
const log=(quem,acao,det)=>q('INSERT INTO audit(quem,acao,det) VALUES($1,$2,$3)',[quem||'-',acao,String(det||'').slice(0,500)]);
const hashPw=(pw,salt)=>crypto.scryptSync(pw,salt,64).toString('hex');
async function setPw(login,pw){const salt=crypto.randomBytes(16).toString('hex');await q('UPDATE users SET salt=$1,hash=$2 WHERE login=$3',[salt,hashPw(pw,salt),login])}
async function newUser(login,pw,perfil,emp){await q('INSERT INTO users(login,perfil,emp_id) VALUES($1,$2,$3)',[login,perfil,emp||null]);await setPw(login,pw)}
const COLS=['roles','forms','scales','emps','launches','attendance','rectifications'],PERFIS=['admin','gestor','consulta','colaborador'];
const SIT=['Presente','Ausente','Férias','Afastado','Folga'],gid=()=>crypto.randomBytes(8).toString('hex');
const send=(res,c,o,h={})=>{res.statusCode=c;res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Cache-Control','no-store');for(const k in h)res.setHeader(k,h[k]);res.end(JSON.stringify(o))};
const err=(res,c,m)=>send(res,c,{erro:m});
async function who(req){const m=/(?:^|; )sid=([a-f0-9]+)/.exec(req.headers.cookie||'');if(!m)return null;
  const u=await q1('SELECT u.login,u.perfil,u.emp_id,u.ativo FROM sessions s JOIN users u ON u.login=s.login WHERE s.token=$1 AND s.exp>$2',[m[1],Date.now()]);
  return u&&u.ativo?{login:u.login,perfil:u.perfil,empId:u.emp_id,token:m[1]}:null}
const own=(u,col,id)=>u.perfil!=='colaborador'||(col==='emps'?id===u.empId:id.startsWith(u.empId+'_'));
async function eff(id){const l=await q1("SELECT data FROM docs WHERE col='launches' AND id=$1",[id]);if(!l)return null;
  const r=await q1("SELECT data FROM docs WHERE col='rectifications' AND id=$1",[id]);return r?r.data.novo:l.data.status}
const UP='INSERT INTO docs VALUES($1,$2,$3) ON CONFLICT (col,id) DO UPDATE SET data=EXCLUDED.data';
async function api(req,res,u,url,b){
  const p=url.pathname.split('/').slice(2),m=req.method;
  if(p[0]==='me')return send(res,200,{login:u.login,perfil:u.perfil,empId:u.empId});
  if(p[0]==='backup'&&u.perfil==='admin'){const o={gerado:new Date().toISOString(),docs:await q('SELECT col,id,data FROM docs'),audit:await q('SELECT * FROM audit ORDER BY n'),users:await q('SELECT login,perfil,emp_id,ativo FROM users')};
    await log(u.login,'backup','');res.statusCode=200;res.setHeader('Content-Type','application/json');res.setHeader('Content-Disposition','attachment; filename="backup-controle.json"');return res.end(JSON.stringify(o))}
  if(p[0]==='users'){if(u.perfil!=='admin'){await log(u.login,'acesso_negado','users');return err(res,403,'Somente administrador.')}
    if(m==='GET')return send(res,200,{users:(await q('SELECT login,perfil,emp_id,ativo,ultimo FROM users ORDER BY login')).map(x=>({login:x.login,perfil:x.perfil,empId:x.emp_id,ativo:x.ativo,ultimo:x.ultimo}))});
    if(m==='POST'){if(!/^[\w.@-]{3,60}$/.test(b.login||'')||(b.senha||'').length<8||!PERFIS.includes(b.perfil))return err(res,400,'Login (3+), senha (8+) e perfil válidos são obrigatórios.');
      if(await q1('SELECT 1 x FROM users WHERE login=$1',[b.login]))return err(res,409,'Login já existe.');
      await newUser(b.login,b.senha,b.perfil,b.empId);await log(u.login,'usuario criado',b.login+' '+b.perfil);return send(res,200,{ok:1})}
    if(m==='PATCH'&&p[1]){const t=await q1('SELECT * FROM users WHERE login=$1',[p[1]]);if(!t)return err(res,404,'Usuário não encontrado.');
      if(b.ativo===false&&t.login===u.login)return err(res,400,'Você não pode bloquear a si mesmo.');
      if(typeof b.ativo==='boolean')await q('UPDATE users SET ativo=$1,falhas=0,bloq_ate=0 WHERE login=$2',[b.ativo,t.login]);
      if(b.senha){if(b.senha.length<8)return err(res,400,'Senha com 8+ caracteres.');await setPw(t.login,b.senha)}
      if(b.perfil&&PERFIS.includes(b.perfil))await q('UPDATE users SET perfil=$1 WHERE login=$2',[b.perfil,t.login]);
      if('empId'in b)await q('UPDATE users SET emp_id=$1 WHERE login=$2',[b.empId||null,t.login]);
      await log(u.login,'usuario alterado',t.login+' '+Object.keys(b).filter(k=>k!=='senha').join(',')+(b.senha?' senha-redefinida':''));return send(res,200,{ok:1})}}
  if(p[0]==='audit'&&m==='GET'&&u.perfil==='admin')return send(res,200,{audit:await q('SELECT * FROM audit ORDER BY n DESC LIMIT 500')});
  if(p[0]==='c'&&p[1]==='audit')return send(res,200,{ok:1});
  if(p[0]==='c'&&COLS.includes(p[1])){const col=p[1],id=p[2];
    if(m==='GET'&&!id){const docs={};for(const r of await q('SELECT id,data FROM docs WHERE col=$1',[col]))if(own(u,col,r.id))docs[r.id]=r.data;return send(res,200,{docs})}
    const deny=async()=>{await log(u.login,'acesso_negado',m+' '+url.pathname);return err(res,403,'Sem permissão.')},adm=u.perfil==='admin';
    if(['roles','forms','scales','emps'].includes(col)){if(!adm)return deny();
      if(m==='POST'){const i=gid();await q('INSERT INTO docs VALUES($1,$2,$3)',[col,i,JSON.stringify(b)]);await log(u.login,'cadastro '+col,JSON.stringify(b));return send(res,200,{id:i})}
      if(m==='PUT'&&id){await q(UP,[col,id,JSON.stringify(b)]);await log(u.login,'edição '+col,id);return send(res,200,{ok:1})}
      if(m==='PATCH'&&id){const r=await q1('SELECT data FROM docs WHERE col=$1 AND id=$2',[col,id]);if(!r)return err(res,404,'Não encontrado.');
        await q('UPDATE docs SET data=$1 WHERE col=$2 AND id=$3',[JSON.stringify({...r.data,...b}),col,id]);await log(u.login,'edição '+col,id+' '+JSON.stringify(b));return send(res,200,{ok:1})}}
    if(col==='rectifications'&&m==='PUT'&&id){if(!adm)return deny();
      const ant=await eff(id);if(!ant)return err(res,404,'Lançamento inexistente.');
      if(!['F','N'].includes(b.novo)||(b.just||'').trim().length<5)return err(res,400,'Justificativa (5+ caracteres) e novo valor são obrigatórios.');
      await q(UP,[col,id,JSON.stringify({id,anterior:ant,novo:b.novo,just:b.just.trim(),por:u.login,ts:new Date().toISOString()})]);
      await log(u.login,'retificação',`${id} ${ant}→${b.novo} | ${b.just}`);return send(res,200,{ok:1})}
  }
  if(p[0]==='claim'&&m==='POST'&&COLS.includes(p[1])&&p[2]){const col=p[1],id=p[2];
    if(!['launches','attendance'].includes(col)||!['admin','gestor'].includes(u.perfil)){await log(u.login,'acesso_negado','claim '+url.pathname);return err(res,403,'Sem permissão para lançar.')}
    const emp=await q1("SELECT data FROM docs WHERE col='emps' AND id=$1",[b.emp]);
    if(!emp||emp.data.ativo===false||!/^\d{4}-\d\d-\d\d$/.test(b.ds||''))return err(res,400,'Dados inválidos.');
    let d;if(col==='launches'){const fm=await q1("SELECT data FROM docs WHERE col='forms' AND id=$1",[b.form]);
      if(id!==`${b.emp}_${b.form}_${b.ds}`||!['F','N'].includes(b.status)||!fm)return err(res,400,'Dados inválidos.');
      d={id,emp:b.emp,form:b.form,ds:b.ds,status:b.status,obs:String(b.obs||'').slice(0,500),roleNome:String(b.roleNome||'').slice(0,100)};
      if(fm.data.usaBal){const sc=await q1("SELECT data FROM docs WHERE col='scales' AND id=$1",[String(b.balId||'')]),pw=Number(b.pesoPadrao);
        if(!sc||sc.data.ativo===false)return err(res,400,'Selecione uma balança válida.');
        if(!(pw>0&&pw<1e9))return err(res,400,'Informe o peso padrão (maior que zero).');
        d.balId=b.balId;d.bal=sc.data.nome+(sc.data.cod?' ('+sc.data.cod+')':'');d.pesoPadrao=pw}}
    else{if(id!==`${b.emp}_${b.ds}`||!SIT.includes(b.sit))return err(res,400,'Dados inválidos.');d={emp:b.emp,ds:b.ds,sit:b.sit}}
    d.por=u.login;d.ts=new Date().toISOString();
    try{await q('INSERT INTO docs VALUES($1,$2,$3)',[col,id,JSON.stringify(d)])}catch(e){
      if(e.code==='23505'){await log(u.login,'duplicidade_bloqueada',col+' '+id);return err(res,409,'Este formulário já possui um lançamento confirmado para este colaborador nesta data. Registro bloqueado.')}throw e}
    await log(u.login,'lançamento '+col,id+' '+(d.status||d.sit));return send(res,200,{ok:1})}
  err(res,404,'Rota inexistente.')}
module.exports=async(req,res)=>{try{
  if(!process.env.DATABASE_URL)return err(res,500,'DATABASE_URL não configurada no Vercel.');
  await init();
  const url=new URL(req.url,'http://x');let b=req.body;if(typeof b==='string'){try{b=JSON.parse(b||'{}')}catch(e){b={}}}b=b||{};
  if(!(await q1('SELECT 1 x FROM users'))){const pw=process.env.ADMIN_PASSWORD;if(!pw||pw.length<8)return err(res,500,'Defina ADMIN_PASSWORD (8+ caracteres) no Vercel.');await newUser('admin',pw,'admin');await log('sistema','admin criado','')}
  if(url.pathname==='/api/login'&&req.method==='POST'){const t=await q1('SELECT * FROM users WHERE login=$1',[String(b.login||'')]);
    if(t&&Number(t.bloq_ate)>Date.now())return err(res,429,'Muitas tentativas. Aguarde 5 minutos.');
    const ok=t&&t.ativo&&crypto.timingSafeEqual(Buffer.from(hashPw(String(b.senha||''),t.salt),'hex'),Buffer.from(t.hash,'hex'));
    if(!ok){if(t){const f=t.falhas+1;await q('UPDATE users SET falhas=$1,bloq_ate=$2 WHERE login=$3',[f%5,f%5?0:Date.now()+3e5,t.login])}await log(t?t.login:String(b.login||'?').slice(0,40),'login_negado',t&&!t.ativo?'usuário bloqueado':'');return err(res,401,'Usuário ou senha inválidos.')}
    const tk=crypto.randomBytes(32).toString('hex');await q('INSERT INTO sessions VALUES($1,$2,$3)',[tk,t.login,Date.now()+8*36e5]);await q('DELETE FROM sessions WHERE exp<$1',[Date.now()]);
    await q('UPDATE users SET falhas=0,ultimo=now() WHERE login=$1',[t.login]);await log(t.login,'login','');
    return send(res,200,{ok:1},{'Set-Cookie':`sid=${tk}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`})}
  const u=await who(req);if(!u)return err(res,401,'Não autenticado.');
  if(url.pathname==='/api/logout'){await q('DELETE FROM sessions WHERE token=$1',[u.token]);return send(res,200,{ok:1})}
  return await api(req,res,u,url,b)
}catch(e){console.error(e);if(!res.headersSent)err(res,500,'Erro interno.')}};
