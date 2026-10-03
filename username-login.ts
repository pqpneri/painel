// Deploy as Edge Function "username-login", verify_jwt=false.
import {createClient} from 'npm:@supabase/supabase-js@2';
const headers={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'apikey, content-type, authorization','Access-Control-Allow-Methods':'POST, OPTIONS'};
const attempts=new Map<string,{n:number,t:number}>();
Deno.serve(async(req)=>{
 if(req.method==='OPTIONS')return new Response('ok',{headers});
 const reply=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers:{...headers,'Content-Type':'application/json'}});
 if(req.method!=='POST')return reply({message:'Método inválido'},405);
 const ip=req.headers.get('x-forwarded-for')?.split(',')[0]||'unknown',now=Date.now(),prior=attempts.get(ip);
 if(prior&&now-prior.t<60000&&prior.n>=10)return reply({message:'Aguarde antes de tentar novamente'},429);
 attempts.set(ip,{t:prior&&now-prior.t<60000?prior.t:now,n:prior&&now-prior.t<60000?prior.n+1:1});
 if(attempts.size>10000)for(const [k,v]of attempts)if(now-v.t>60000)attempts.delete(k);
 try{
  const {username,password}=await req.json();
  if(typeof username!=='string'||typeof password!=='string'||!username.match(/^[a-zA-Z0-9_.]{3,32}$/)||password.length>512)return reply({message:'Usuário ou senha inválidos'},400);
  const url=Deno.env.get('SUPABASE_URL')!,secret=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,anon=Deno.env.get('SUPABASE_ANON_KEY')!;
  const admin=createClient(url,secret,{auth:{persistSession:false}}),client=createClient(url,anon,{auth:{persistSession:false}});
  const {data:profile}=await admin.from('crm_accounts').select('email,active').eq('username',username.toLowerCase()).maybeSingle();
  const {data,error}=await client.auth.signInWithPassword({email:profile?.email||'unknown-login@invalid.example',password});
  if(error||!profile?.active||!data.session)return reply({message:'Usuário ou senha inválidos'},401);
  return reply({...data.session,user:data.user});
 }catch(e){return reply({message:'Não foi possível realizar o login'},500)}
});
