(function(){'use strict';const $=id=>document.getElementById(id),status=$('status'),form=$('password-form');let link=location.href;
// Remove all callback material before interacting with the SDK. Never render it.
history.replaceState(null,'',location.pathname);
// A second mail link may reuse this document via a fragment-only navigation.
window.addEventListener('hashchange',()=>{if(location.hash)location.reload();});const clear=()=>{$('password').value='';$('confirmation').value='';};
const api=SafeOnboarding.create({config:window.ONBOARDING_CONFIG,onState:()=>{form.hidden=true;clear();}});
const report=e=>{status.textContent=e instanceof SafeOnboarding.OnboardingError?e.message:'処理を完了できませんでした。管理者に確認してください。';};
try{SafeOnboarding.parseLink(link);$('verify').disabled=false;status.textContent='メールの案内をご自身で開いたことを確認して、下のボタンを押してください。';}catch(e){link=null;report(e);}
$('verify').onclick=async()=>{$('verify').disabled=true;const pending=link;link=null;try{await api.acceptLink(pending);form.hidden=false;status.textContent='本人確認ができました。新しいパスワードを設定してください。';$('password').focus();}catch(e){report(e);}};
form.onsubmit=async e=>{e.preventDefault();if($('save').disabled)return;$('save').disabled=true;const p=$('password').value,c=$('confirmation').value;clear();try{await api.updatePassword(p,c);form.hidden=true;status.textContent='パスワードを設定しました。利用するアプリでログインしてください。';}catch(e){form.hidden=true;report(e);}finally{$('save').disabled=false;}};
$('cancel').onclick=async()=>{link=null;clear();form.hidden=true;$('verify').disabled=true;try{await api.cancel();status.textContent='操作を終了しました。';}catch(e){report(e);}};
window.addEventListener('pagehide',()=>{link=null;clear();void api.cancel().catch(()=>{});});
})();
