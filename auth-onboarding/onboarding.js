/* LOCAL ONLY. Dedicated ephemeral onboarding session; never carries app authorization. */
(function(root){
'use strict';
const messages={blocked:'この画面では認証を開始できません。案内リンクを通常のブラウザで開いてください。',link:'リンクが無効、使用済み、または期限切れです。管理者に確認してください。',session:'本人確認ができません。新しい案内リンクでやり直してください。',password:'パスワードは12文字以上128文字以内で、確認欄と同じ内容にしてください。',failed:'処理を完了できませんでした。管理者に確認してください。',cancelled:'操作を終了しました。',pkce:'この画面では認証コード形式のリンクを利用できません。管理者に専用の案内リンクを確認してください。'};
class OnboardingError extends Error {constructor(code){super(messages[code]||messages.failed);this.code=code;}}
const fail=code=>{throw new OnboardingError(code);};
function parseLink(href){
 let u;try{u=new URL(href);}catch{fail('link');}
 // Fragment TokenHash avoids sending the email credential in the Pages HTTP URL.
 // Retain query-form compatibility for isolated tests; never combine both forms.
 if(!u.hash||u.search)fail('link');
 const q=u.hash?new URLSearchParams(u.hash.slice(1)):u.searchParams;if(q.has('code'))fail('pkce');
 if([...q.keys()].some(k=>!['token_hash','type'].includes(k))||q.getAll('type').length!==1||q.getAll('token_hash').length!==1)fail('link');
 const type=q.get('type'),token_hash=q.get('token_hash');
 if(!['invite','recovery'].includes(type)||!token_hash||token_hash.length>2048||!/^[a-zA-Z0-9_-]+$/.test(token_hash))fail('link');
 return {type,token_hash};
}
function create(options={}){
 const cfg=options.config||{};let client, busy=false, generation=0, readyId=null, readyToken=null, terminal=false;
 const memory=new Map();
 function check(){let u;try{u=new URL(cfg.supabaseUrl);}catch{fail('blocked');}
 if(cfg.enabled!==true||cfg.environment!=='hosted-pilot'||u.href!=="https://nxaepscqkxpldvunbhri.supabase.co/"||root.location?.href.split(/[?#]/)[0]!=="https://tanakapray-web.github.io/-/auth-onboarding/index.html"||root.top!==root.self||!/^sb_publishable_[A-Za-z0-9_-]+$/.test(cfg.publishableKey||''))fail('blocked');return u.origin;}
 function sdk(){const origin=check();if(!client){const factory=options.supabaseFactory||root.supabase?.createClient;if(typeof factory!=='function')fail('blocked');
 client=factory(origin,cfg.publishableKey,{auth:{persistSession:false,autoRefreshToken:false,detectSessionInUrl:false,flowType:'pkce',storageKey:'pray-onboarding-ephemeral',storage:{getItem:k=>memory.get(k)||null,setItem:(k,v)=>memory.set(k,v),removeItem:k=>memory.delete(k)}},global:{fetch:async(input,init)=>{const u=new URL(typeof input==='string'?input:input.url);if(u.origin!==origin||!u.pathname.startsWith('/auth/v1/'))fail('blocked');return (options.fetch||root.fetch.bind(root))(input,{...init,redirect:'error'});}}});
 client.auth.onAuthStateChange((event,session)=>{if(event==='SIGNED_OUT'||(readyId&&session?.user?.id!==readyId)){readyId=null;readyToken=null;generation++;options.onState?.('signed-out');}});
 }return client;}
 async function logout(){readyId=null;readyToken=null;generation++;memory.clear();if(client){const r=await client.auth.signOut({scope:'local'});if(r?.error)fail('failed');}}
 async function verified(c){const r=await c.auth.getSession();const s=r.data?.session;if(r.error||!s?.access_token||!s.user?.id)fail('session');const v=await c.auth.getUser(s.access_token);const u=v.data?.user;if(v.error||!u?.id||u.id!==s.user.id||u.is_anonymous===true||!u.email)fail('session');return {id:u.id,token:s.access_token};}
 async function exclusive(fn){if(busy||terminal)fail('cancelled');busy=true;try{return await fn();}catch(e){readyId=null;if(client)try{await logout();}catch{};throw e instanceof OnboardingError?e:new OnboardingError('failed');}finally{busy=false;}}
 async function acceptLink(href){return exclusive(async()=>{if(readyId)fail('link');const link=parseLink(href),c=sdk(),g=generation;const r=await c.auth.verifyOtp(link);if(r.error||!r.data?.session)fail('link');const identity=await verified(c);if(identity.id!==r.data.session.user?.id||identity.token!==r.data.session.access_token)fail('session');if(g!==generation||terminal)fail('cancelled');readyId=identity.id;readyToken=identity.token;return {type:link.type};});}
 async function updatePassword(password,confirmation){return exclusive(async()=>{if(typeof password!=='string'||password.length<12||password.length>128||password!==confirmation)fail('password');if(!readyId)fail('session');const c=sdk(),g=generation,identity=await verified(c);if(identity.id!==readyId||identity.token!==readyToken||g!==generation||terminal)fail('session');
 // Bind the mutation to the exact verified bearer, never SDK mutable current-session state.
 const response=await (options.fetch||root.fetch.bind(root))(check()+'/auth/v1/user',{method:'PUT',redirect:'error',headers:{apikey:cfg.publishableKey,Authorization:'Bearer '+identity.token,'Content-Type':'application/json'},body:JSON.stringify({password})});password=confirmation='';if(!response.ok)fail('failed');let updated;try{updated=await response.json();}catch{fail('failed');}if(updated?.id!==identity.id)fail('session');if(g!==generation||terminal)fail('cancelled');terminal=true;await logout();return true;});}
 async function cancel(){terminal=true;await logout();}
 function mockRecovery(){check();if(cfg.environment!=='test'||cfg.mockMail!==true)fail('blocked');return 'テスト受付のみです。メールは送信していません。';}
 return {acceptLink,updatePassword,cancel,mockRecovery,isReady:()=>!!readyId&&!terminal};
}
root.SafeOnboarding={create,parseLink,OnboardingError};if(typeof module!=='undefined')module.exports=root.SafeOnboarding;
})(typeof window!=='undefined'?window:globalThis);
