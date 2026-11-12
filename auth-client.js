/* Shared authenticated transport. Local restoration preparation, not a deployment approval. */
(function (root) {
  'use strict';
  class AccessError extends Error {
    constructor(message, status = 403) { super(message); this.name = 'AccessError'; this.status = status; }
  }
  const ids = value => Array.isArray(value) ? [...new Set(value.filter(v => typeof v === 'string' && v.length))] : [];
  function normalizeContext(raw, user) {
    if (!raw || !raw.profile || raw.profile.auth_user_id !== user.id || !raw.profile.id) {
      throw new AccessError('利用者の登録・利用許可を管理者に確認してください。');
    }
    const p = raw.profile, s = raw.schedule || {}, sales = raw.sales || {};
    const feature_scopes = Object.create(null);
    for (const [key, value] of Object.entries(sales.feature_scopes || {})) {
      if(!['daily','monthly','cleaning','sales_overrides','schedule_lookup','routes','budgets'].includes(key))continue;
      feature_scopes[key] = { view_store_ids: ids(value?.view_store_ids), edit_store_ids: ids(value?.edit_store_ids) };
    }
    return Object.freeze({
      access_admin: Object.freeze({can_manage_access: raw.access_admin?.can_manage_access === true}),
      profile: Object.freeze({ id: p.id, auth_user_id: user.id, email: user.email || '', name: String(p.name || ''),
        role: ['admin', 'manager', 'general'].includes(p.role) ? p.role : 'general', store_id: p.store_id || null,
        store_ids: ids(p.store_ids), divisions: ids(p.divisions) }),
      schedule: Object.freeze({ view_store_ids: ids(s.view_store_ids), edit_store_ids: ids(s.edit_store_ids),
        view_dept_ids: ids(s.view_dept_ids), edit_dept_ids: ids(s.edit_dept_ids) }),
      sales: Object.freeze({ view_store_ids: ids(sales.view_store_ids), edit_store_ids: ids(sales.edit_store_ids),
        can_manage_settings: sales.can_manage_settings === true, feature_scopes })
    });
  }
  function create(options = {}) {
    const config = options.config || {}, app = options.app;
    const fetchImpl = options.fetch || root.fetch?.bind(root);
    let client = null, access = null, generation = 0, busySignIn = null, busySignOut = null, explicitlySignedOut = false;
    let cleanupFailures=0, logoutHttpFailures=0;
    const storage = options.storage || root.sessionStorage;
    const storageKey = `pray-auth-${app}-v2`, logoutKey = `pray-auth-${app}-signed-out`;
    function isSignedOut(){try{return explicitlySignedOut || storage?.getItem(logoutKey)==='1';}catch{return explicitlySignedOut;}}
    function markSignedOut(){explicitlySignedOut=true;try{storage?.setItem(logoutKey,'1');}catch{cleanupFailures++;}}
    function removeStoredSession(){try{storage?.removeItem(storageKey);}catch{cleanupFailures++;}}
    function permitFreshSignIn(){explicitlySignedOut=false;try{storage?.removeItem(logoutKey);}catch{}}
    function clear(reason) { access = null; generation++; try{options.onSignedOut?.(reason);}catch{cleanupFailures++;} }
    function checkConfig() {
      if (config.enabled !== true) throw new AccessError('安全な復旧準備中です。本番への接続は停止しています。', 503);
      let url; try { url = new URL(config.supabaseUrl); } catch { throw new AccessError('接続先が未設定です。', 503); }
      if(config.environment!=='hosted-pilot'||url.href!=="https://nxaepscqkxpldvunbhri.supabase.co/"||!(root.location?.origin==="https://tanakapray-web.github.io" && root.location?.pathname.startsWith("/schedule-app/") && root.top===root.self)||!/^sb_publishable_[A-Za-z0-9_-]+$/.test(config.publishableKey||''))throw new AccessError('公開設定が未確認です。',503);
      return url.origin;
    }
    async function safeFetch(input, init) {
      const origin = checkConfig(), url = new URL(typeof input === 'string' ? input : input.url, origin);
      if (url.origin !== origin || !/^\/(auth|rest)\/v1\//.test(url.pathname)) throw new AccessError('許可されていない接続先です。');
      const response=await fetchImpl(input, {...init,redirect:'error'});
      if(url.pathname==='/auth/v1/logout' && !response.ok)logoutHttpFailures++;
      return response;
    }
    function ensureClient() {
      const origin = checkConfig();
      if (!client) {
        const factory = options.supabaseFactory || root.supabase?.createClient;
        if (typeof factory !== 'function') throw new AccessError('認証ライブラリが未準備です。', 503);
        client = factory(origin, config.publishableKey, { auth: { persistSession: true, autoRefreshToken: true,
          detectSessionInUrl: false, storage: options.storage || root.sessionStorage, storageKey: `pray-auth-${app}-v2` },
          global: { fetch: safeFetch } });
        client.auth.onAuthStateChange((event) => {
          if (event === 'SIGNED_OUT') clear('アプリの利用を停止しました。');
          // Do not await Supabase calls from the auth callback (SDK lock/deadlock avoidance).
        });
      }
      return client;
    }
    async function verifiedSession() {
      const sessionGeneration=generation;
      if(isSignedOut())throw new AccessError('ログインしてください。',401);
      const c = ensureClient();
      const { data, error } = await c.auth.getSession();
      const session = data?.session;
      if (error || !session?.access_token) { clear('ログインしてください。'); throw new AccessError('ログインしてください。', 401); }
      const checked = await c.auth.getUser(session.access_token);
      if (checked.error || !checked.data?.user || checked.data.user.is_anonymous === true) {
        clear('ログインの有効期限が切れました。もう一度ログインしてください。');
        throw new AccessError('ログインの有効期限が切れました。', 401);
      }
      if (sessionGeneration!==generation || isSignedOut()) throw new AccessError('ログイン状態が変わりました。',401);
      return { session, user: checked.data.user };
    }
    async function refreshContext() {
      const start = generation, { session, user } = await verifiedSession();
      const response = await safeFetch(checkConfig() + '/rest/v1/rpc/app_access_context', {
        method: 'POST', headers: { apikey: config.publishableKey, Authorization: `Bearer ${session.access_token}`, 'Content-Type': 'application/json' }, body: '{}'
      });
      if (!response.ok) { clear('利用許可を確認できません。'); throw new AccessError('利用許可を確認できません。', response.status); }
      const raw = await response.json();
      if (start !== generation) throw new AccessError('ログイン状態が変わりました。', 401);
      access = normalizeContext(raw, user);
      return access;
    }
    async function signIn(email, password) {
      if (busySignOut) throw new AccessError('ログアウト処理中です。完了後にログインしてください。',409);
      if (busySignIn) return busySignIn;
      busySignIn = (async () => {
        const cleanupBeforeSignIn=cleanupFailures;clear();
        if(cleanupFailures!==cleanupBeforeSignIn){markSignedOut();throw new AccessError('前の利用者の表示を消去できません。画面を閉じてください。',503);}
        permitFreshSignIn();
        const signInGeneration = generation;
        const { error } = await ensureClient().auth.signInWithPassword({ email: email.trim(), password });
        if (signInGeneration !== generation) { await ensureClient().auth.signOut({ scope: 'local' }); clear('ログイン処理を取り消しました。'); throw new AccessError('ログイン処理を取り消しました。', 401); }
        if (error) throw new AccessError('メールアドレスまたはパスワードを確認してください。', 401);
        try { return await refreshContext(); }
        catch (e) { await ensureClient().auth.signOut({ scope: 'local' }); throw e; }
      })();
      try { return await busySignIn; } finally { busySignIn = null; }
    }
    async function restore() {
      try {
        if (!config.enabled || isSignedOut()) return null;
        const c = ensureClient(), state = await c.auth.getSession();
        if (state.error || !state.data?.session) return null;
        return await refreshContext();
      } catch (e) { clear(e.message); return null; }
    }
    async function signOut() {
      if (busySignOut) return busySignOut;
      // Deny app access immediately, but leave the SDK session available until it
      // captures its bearer for revocation. Removing its storage first skips POST /logout.
      const initialCleanupFailures=cleanupFailures, initialHttpFailures=logoutHttpFailures;
      markSignedOut();clear('アプリの利用を停止しました。');
      busySignOut = (async () => {
        try {
          if (client) {const result=await client.auth.signOut({scope:'local'});if(result.error)throw new AccessError('ログアウトの完了を確認できません。画面を閉じてください。',503);}
        } finally {
          removeStoredSession();markSignedOut();
          if(cleanupFailures!==initialCleanupFailures || logoutHttpFailures!==initialHttpFailures)throw new AccessError('ログアウトの完了を確認できません。画面を閉じてください。',503);
        }
      })();
      try {return await busySignOut;} finally {busySignOut=null;}
    }
    function canSchedule({ storeId, deptId }, write = false) {
      if (!access || !deptId) return false;
      const s = access.schedule;
      if (storeId) return s.view_dept_ids.includes(deptId) && (write ? s.edit_store_ids : s.view_store_ids).includes(storeId);
      return (write ? s.edit_dept_ids : s.view_dept_ids).includes(deptId);
    }
    function canSales(storeId, feature, write = false) {
      if (!access || !storeId) return false;
      const scopes = access.sales.feature_scopes;
      if (!Object.prototype.hasOwnProperty.call(scopes, feature)) return false;
      const s = scopes[feature];
      return (write ? s.edit_store_ids : s.view_store_ids).includes(storeId);
    }
    function assertSchedule(scope, write = false) { if (!canSchedule(scope, write)) throw new AccessError(write ? 'この店舗・部署は編集できません。' : 'この店舗・部署は閲覧できません。'); }
    function assertSales(storeId, feature, write = false) { if (!canSales(storeId, feature, write)) throw new AccessError(write ? 'この店舗の編集権限がありません。' : 'この店舗の閲覧権限がありません。'); }
    function assertSettings() {
      if (!access?.sales.can_manage_settings) throw new AccessError('管理設定の権限がありません。');
    }
    function assertWriteRecord(table, row) {
      if (app === 'schedule') {
        if (table === 'schedules') return assertSchedule({ storeId: row.store_id, deptId: row.schedule_dept_id }, true);
        if (table === 'schedule_attendance' || table === 'schedule_staff') {
          if (table === 'schedule_staff') assertSettings();
          const s = access.schedule;
          if (!row.store_id || (!s.edit_store_ids.includes(row.store_id) && !s.edit_dept_ids.includes(row.store_id))) throw new AccessError('この店舗・部署は編集できません。');
          return;
        }
        if (table === 'schedule_depts') { assertSettings(); return assertSchedule({ storeId: row.store_id, deptId: row.id }, true); }
        throw new AccessError('スケジュールからはこの設定を変更できません。');
      }
      const features = { daily: 'daily', monthly: 'monthly', cleaning_masters: 'cleaning', cleaning_monthly: 'cleaning', sales_overrides: 'sales_overrides' };
      if (features[table]) return assertSales(row.store_id, features[table], true);
      if (table === 'cats') { assertSettings(); return; }
      if (table === 'stores') {
        const keys = Object.keys(row).filter(k => k !== 'id');
        if (!keys.length || keys.some(k => !['routes', 'budgets'].includes(k))) throw new AccessError('部署マスタ変更は安全な管理手順で行ってください。');
        for (const key of keys) assertSales(row.id, key, true);
        return;
      }
      throw new AccessError('この操作は安全な管理手順で行ってください。');
    }
    async function preflightWrite(table, path, opts) {
      await refreshContext();
      const method = (opts.method || 'POST').toUpperCase();
      let body = null;
      if (opts.body) { try { body = typeof opts.body === 'string' ? JSON.parse(opts.body) : opts.body; } catch { throw new AccessError('保存データを確認してください。'); } }
      if (method === 'POST') {
        const rows = Array.isArray(body) ? body : [body];
        if (!rows.length || rows.some(r => !r || typeof r !== 'object')) throw new AccessError('保存データがありません。');
        for (const row of rows) assertWriteRecord(table, row);
        return;
      }
      const query = new URLSearchParams(path.split('?')[1] || '');
      if (![...query].some(([k,v]) => ['id','master_id','store_id'].includes(k) && v.startsWith('eq.'))) throw new AccessError('変更対象を一意に指定してください。');
      const current = await request(path, { method: 'GET' });
      const rows = await current.json();
      if (!Array.isArray(rows) || !rows.length) throw new AccessError('変更対象が見つかりません。', 409);
      for (const row of rows) {
        if (table === 'stores') {
          if (method !== 'PATCH' || Array.isArray(body)) throw new AccessError('部署マスタ変更は安全な管理手順で行ってください。');
          assertWriteRecord(table, { ...body, id: row.id });
        } else {
          assertWriteRecord(table, row);
          if (method === 'PATCH') assertWriteRecord(table, { ...row, ...body });
        }
      }
    }
    async function request(path, opts = {}) {
      const allowed = new Set(['stores', 'daily', 'monthly', 'cats', 'cleaning_masters', 'cleaning_monthly', 'sales_overrides', 'schedules', 'schedule_depts', 'schedule_attendance', 'schedule_staff']);
      const table = path.split('?')[0];
      if (!allowed.has(table) || /[\\#]/.test(path)) throw new AccessError('この操作は利用できません。');
      const method = (opts.method || 'GET').toUpperCase();
      if (!['GET', 'POST', 'PATCH', 'DELETE'].includes(method)) throw new AccessError('許可されていない操作です。');
      if (table==='stores') {const query=new URLSearchParams(path.split('?')[1]||'');query.set('select',method==='GET'?'id,name,dept,division,sort_order,created_at':'id');path='stores?'+query.toString();}
      if (method !== 'GET') await preflightWrite(table, path, opts);
      const start = generation, { session, user } = await verifiedSession();
      if (!access || access.profile.auth_user_id !== user.id) throw new AccessError('利用許可を確認してください。', 401);
      const headers = { ...opts.headers, apikey: config.publishableKey, Authorization: `Bearer ${session.access_token}`, 'Content-Type': 'application/json', Prefer: opts.headers?.Prefer || 'return=representation' };
      const response = await safeFetch(checkConfig() + '/rest/v1/' + path, { ...opts, method, headers });
      if (generation !== start) throw new AccessError('ログイン状態が変わりました。', 401);
      if (!response.ok) {
        if (response.status === 401) clear('ログインの有効期限が切れました。');
        let detail;try{detail=await response.clone().json();}catch{}
        const error=new AccessError(detail?.code==='PT409'?'他の人が変更しました。入力内容を控え、再読み込みしてから開き直してください。保存・削除はされていません。':detail?.code==='23505'?'同じ対象の記録が既に保存されています。再読み込みして確認してください。':response.status === 403 ? '権限がないため操作できません。保存されていません。' : '通信に失敗しました。最新の状態を確認してください。', response.status);error.code=detail?.code;throw error;
      }
      // RLS may turn an unauthorized PATCH/DELETE into a successful zero-row response.
      if (method !== 'GET') {
        let rows; try { rows = await response.clone().json(); } catch { throw new AccessError('保存結果を確認できません。再読み込みしてください。', 409); }
        if (!Array.isArray(rows) || rows.length === 0) throw new AccessError('対象が更新されませんでした。権限または最新データを確認してください。', 409);
      }
      if (generation !== start || isSignedOut()) throw new AccessError('ログイン状態が変わりました。',401);
      return response;
    }
    async function setAttendanceCell(params) {
      const keys=['p_dept_id','p_scope_id','p_date','p_staff_id','p_staff_index','p_expected_value','p_value'];
      if(app!=='schedule'||!params||Object.keys(params).length!==keys.length||keys.some(key=>!Object.hasOwn(params,key)))throw new AccessError('出勤変更の入力項目を確認してください。');
      for(const key of ['p_dept_id','p_scope_id','p_staff_id'])if(typeof params[key]!=='string'||!params[key])throw new AccessError('出勤変更の対象を確認してください。');
      if(typeof params.p_date!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(params.p_date)||!Number.isFinite(Date.parse(params.p_date))||new Date(params.p_date).toISOString().slice(0,10)!==params.p_date||!Number.isSafeInteger(params.p_staff_index)||params.p_staff_index<0)throw new AccessError('日付・スタッフを確認してください。');
      if(!['','出勤','休日'].includes(params.p_expected_value)||!['','出勤','休日'].includes(params.p_value))throw new AccessError('出勤状態を確認してください。');
      await refreshContext();const start=generation;
      if(access.schedule.edit_store_ids.includes(params.p_scope_id))assertSchedule({storeId:params.p_scope_id,deptId:params.p_dept_id},true);
      else if(params.p_scope_id===params.p_dept_id)assertSchedule({deptId:params.p_dept_id},true);
      else throw new AccessError('この店舗・部署の出勤情報は編集できません。');
      const {session}=await verifiedSession();
      if(start!==generation)throw new AccessError('ログイン状態が変わりました。',401);
      const response=await safeFetch(checkConfig()+'/rest/v1/rpc/app_attendance_cell_set',{method:'POST',headers:{apikey:config.publishableKey,Authorization:`Bearer ${session.access_token}`,'Content-Type':'application/json'},body:JSON.stringify(params)});
      const result=await response.json();
      if(start!==generation)throw new AccessError('ログイン状態が変わりました。',401);
      if(!response.ok){if(response.status===401)clear('ログインの有効期限が切れました。');const error=new AccessError((result?.code==='PT409'&&response.status===409)?'出勤情報またはスタッフ一覧が変更されています。最新表示を確認してから入力してください。':'出勤情報の処理結果を確認できません。最新表示を確認してください。',response.status);error.code=result?.code;throw error;}
      const expected={store_id:params.p_scope_id,month:params.p_date.slice(0,7),key:params.p_date+'__'+params.p_staff_index,staff_id:params.p_staff_id,staff_index:params.p_staff_index,value:params.p_value};
      if(!result||Object.entries(expected).some(([key,value])=>result[key]!==value))throw new AccessError('出勤情報の保存結果を確認できません。再読み込みして確認してください。',502);
      return result;
    }
    async function readStoreDetails(feature, storeIds) {
      const methods={routes:'app_store_routes',budgets:'app_store_budgets'};
      if(!Object.hasOwn(methods,feature)||!Array.isArray(storeIds)||storeIds.some(id=>typeof id!=='string'||!id))throw new AccessError('取得対象を確認してください。');
      if(!storeIds.length)return [];
      await refreshContext();const start=generation;
      for(const id of storeIds)assertSales(id,feature,false);
      const {session}=await verifiedSession();
      if(start!==generation)throw new AccessError('ログイン状態が変わりました。',401);
      const response=await safeFetch(checkConfig()+'/rest/v1/rpc/'+methods[feature],{method:'POST',headers:{apikey:config.publishableKey,Authorization:`Bearer ${session.access_token}`,'Content-Type':'application/json'},body:JSON.stringify({p_store_ids:storeIds})});
      const result=await response.json();
      if(start!==generation)throw new AccessError('ログイン状態が変わりました。',401);
      if(!response.ok||!Array.isArray(result))throw new AccessError('店舗情報の閲覧が許可されていません。',response.status||403);
      return result;
    }
    async function deleteCleaningMaster(masterId) {
      if(app!=='sales'||typeof masterId!=='string'||!masterId)throw new AccessError('削除対象を確認してください。');
      await refreshContext();
      const start=generation;
      const read=await request('cleaning_masters?id=eq.'+encodeURIComponent(masterId));
      const masters=await read.json();
      if(masters.length!==1)throw new AccessError('対象が見つかりません。',404);
      assertSales(masters[0].store_id,'cleaning',true);
      const {session}=await verifiedSession();
      if(start!==generation)throw new AccessError('ログイン状態が変わりました。',401);
      const response=await safeFetch(checkConfig()+'/rest/v1/rpc/app_cleaning_master_delete',{method:'POST',headers:{apikey:config.publishableKey,Authorization:`Bearer ${session.access_token}`,'Content-Type':'application/json'},body:JSON.stringify({p_master_id:masterId})});
      const result=await response.json();
      if(start!==generation)throw new AccessError('ログイン状態が変わりました。',401);
      if(!response.ok){const error=new AccessError(result?.code==='23503'?'子契約があるため削除できません。':(result?.code==='PT409'&&response.status===409)?'対象が変更されています。再読み込みして確認してください。':'削除結果を確認できません。再読み込みして確認してください。',response.status);error.code=result?.code;throw error;}
      if(result?.deleted_master_id!==masterId||!Number.isInteger(result.deleted_monthly_count)||result.deleted_monthly_count<0)throw new AccessError('削除結果を確認できません。再読み込みしてください。',502);
      return result;
    }
    async function dailyCloseSnapshot(month,storeIds) {
      if(app!=='sales'||!/^\d{4}-(0[1-9]|1[0-2])$/.test(month)||!Array.isArray(storeIds)||!storeIds.length||storeIds.length>100||new Set(storeIds).size!==storeIds.length)throw new AccessError('年月と店舗を選択してください。');
      const start=generation;await refreshContext();
      for(const id of storeIds)assertSales(id,'daily',false);
      const {session}=await verifiedSession();
      if(start!==generation)throw new AccessError('ログイン状態が変わりました。',401);
      const response=await safeFetch(checkConfig()+'/rest/v1/rpc/app_daily_close_snapshot',{method:'POST',headers:{apikey:config.publishableKey,Authorization:`Bearer ${session.access_token}`,'Content-Type':'application/json'},body:JSON.stringify({p_month:month,p_store_ids:storeIds})});
      const result=await response.json();
      if(start!==generation||isSignedOut())throw new AccessError('ログイン状態が変わりました。',401);
      if(!response.ok)throw new AccessError(response.status===403?'集計対象の閲覧権限を確認してください。':'締め集計を作成できません。日報の金額形式と最新の権限を確認してください。',response.status);
      if(result?.month!==month||result.basis!=='daily.service_rows'||!Number.isFinite(Date.parse(result.as_of))||!Array.isArray(result.stores)||result.stores.length!==storeIds.length||new Set(result.stores.map(s=>s.store_id)).size!==storeIds.length||result.stores.some(s=>!storeIds.includes(s.store_id)||!/^[-]?\d+(?:\.\d+)?$/.test(s.total))||!/^[-]?\d+(?:\.\d+)?$/.test(result.total))throw new AccessError('締め集計の結果を確認できません。',502);
      return result;
    }
    async function adminRequest(method, params = {}) {
      const methods = {
        app_access_admin_list: [],
        app_access_admin_update: ['p_target_auth_user_id','p_expected_revision','p_assigned_store_ids','p_assigned_dept_ids','p_view_store_ids','p_edit_store_ids','p_view_dept_ids','p_edit_dept_ids']
      };
      if (!Object.hasOwn(methods, method)) throw new AccessError('許可されていない管理操作です。');
      const keys=methods[method];
      if (!params || Array.isArray(params) || Object.keys(params).length !== keys.length || keys.some(k=>!Object.hasOwn(params,k))) throw new AccessError('管理操作の入力項目を確認してください。');
      const start=generation;
      await refreshContext();
      if (!access?.access_admin.can_manage_access) throw new AccessError('利用権限の管理が許可されていません。');
      if (method==='app_access_admin_update') {
        if (typeof params.p_target_auth_user_id !== 'string' || !params.p_target_auth_user_id || params.p_target_auth_user_id===access.profile.auth_user_id) throw new AccessError('自分自身の権限は変更できません。');
        if (!Number.isSafeInteger(params.p_expected_revision) || params.p_expected_revision<0) throw new AccessError('更新版番号を確認してください。');
        for (const key of keys.slice(2)) if(!Array.isArray(params[key]) || params[key].some(id=>typeof id!=='string'||!id)) throw new AccessError('権限の選択内容を確認してください。');
      }
      const {session,user}=await verifiedSession();
      if(start!==generation || access?.profile.auth_user_id!==user.id) throw new AccessError('ログイン状態が変わりました。',401);
      const response=await safeFetch(checkConfig()+'/rest/v1/rpc/'+method,{method:'POST',headers:{apikey:config.publishableKey,Authorization:`Bearer ${session.access_token}`,'Content-Type':'application/json'},body:JSON.stringify(params)});
      let result;try{result=await response.json();}catch{throw new AccessError('管理操作の結果を確認できません。',502);}
      if(start!==generation)throw new AccessError('ログイン状態が変わりました。',401);
      if(!response.ok){
        if(response.status===401)clear('ログインの有効期限が切れました。');
        const error=new AccessError((result?.code==='PT409'&&response.status===409)?'他の管理者が変更しました。再読み込みしてください。':'管理操作の結果を確認できません。一覧を読み直してください。',response.status);
        error.code=typeof result?.code==='string'?result.code:null;throw error;
      }
      return result;
    }
    return { dailyCloseSnapshot, signIn, restore, signOut, refreshContext, request, adminRequest, setAttendanceCell, readStoreDetails, deleteCleaningMaster, canSchedule, canSales, assertSchedule, assertSales,
      context: () => access, clear, isConfigured: () => config.enabled === true };
  }
  function revisionHeaders(value){if(!Number.isSafeInteger(value)||value<0)throw new AccessError('記録の版を確認できません。入力内容を控え、再読み込みして開き直してください。',409);return {'X-Pray-Expected-Revision':String(value)};}
  root.SafeAuth = { create, AccessError, normalizeContext, revisionHeaders };
  if (typeof module !== 'undefined') module.exports = root.SafeAuth;
})(typeof window !== 'undefined' ? window : globalThis);
