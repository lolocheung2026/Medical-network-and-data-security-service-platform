let currentSid = null;
let state = null;
let canvas, ctx;
let nodePositions = {};
let animFrame = 0;
let animRunning = false;
let currentTarget = null;

const NODE_COLORS = {
  // 2026-09-06 乐叔定稿：场景画布已完全由 STATE_* 状态色驱动（safe 全绿），
  // NODE_COLORS 仅剩资产清单色点使用；external 取绿色与"初始安全"心智一致。
  external: '#3fb950',
  firewall: '#d29922',
  switch: '#8b949e',
  server: '#58a6ff',
  database: '#bc8cff',
  workstation: '#39d2c0',
  iot: '#3fb950',
};

const STATE_FILLS = {
  // 2026-09-06 乐叔定稿口径：初始状态（safe）由 CATEGORY_COLORS 按
  // 「网络/设备/系统」三大类分色（safe 此处不再全局消费，置 null）。
  safe: null,
  target: 'rgba(210,153,34,0.15)',
  compromised: 'rgba(248,81,73,0.35)',
  defended: 'rgba(230,237,243,0.12)',
  exfiltrated: 'rgba(188,140,255,0.35)',
  encrypted: 'rgba(121,31,31,0.5)',
  isolated: 'rgba(110,118,129,0.3)',
};

const STATE_STROKES = {
  safe: null,
  target: '#d29922',
  compromised: '#f85149',
  defended: '#e6edf3',  // 2026-09-06 v4：防御点亮改白（原蓝 #58a6ff 与设备蓝冲突）
  exfiltrated: '#bc8cff',
  encrypted: '#791f1f',
  isolated: '#6e7681',
};

// 2026-09-06 乐叔定稿 v4：初始状态按三大类分色（攻击者恒红优先判断）
// 设备改蓝 #4f8ef5（华为交换机惯例），与攻击目标土黄 #d29922 色相距离 176.7°；
// 已防御改白 #e6edf3（防护点亮语义），避开设备蓝冲突。
const CATEGORY_COLORS = {
  attacker: { stroke: '#f85149', fill: 'rgba(248,81,73,0.28)' },  // 攻击源恒红
  network:  { stroke: '#39d2c0', fill: 'rgba(57,210,192,0.15)' },  // 网络：外部网络域（互联网/专线/平台）
  device:   { stroke: '#4f8ef5', fill: 'rgba(79,142,245,0.15)' },  // 设备：物理硬件（交换机/防火墙/网闸/无线）
  system:   { stroke: '#3fb950', fill: 'rgba(63,185,80,0.15)' },   // 系统：业务系统（服务器/数据库/终端/云）
};

function nodeCategory(n) {
  var lbl = n.label || '', id = n.id || '';
  if (/攻击者/.test(lbl) || /attacker/i.test(id)) return 'attacker';
  var t = n.type;
  // 2026-09-06 乐叔纠正：三分法 = 资产语义
  // 网络 = 外部网络域（互联网/专线/政务外网/平台，云状域节点）
  // 设备 = 物理硬件（交换机含核心、防火墙、网闸、行为管理、无线设备）
  // 系统 = 业务系统（服务器/数据库/终端/云资源/IoT）
  if (t === 'external') return 'network';
  if (t === 'switch' || t === 'network' || t === 'firewall' || t === 'gap'
      || t === 'isolator' || t === 'behavior') return 'device';
  return 'system';
}

const STEP_LABELS = { pending: '待执行', completed: '已完成', blocked: '已拦截' };
const EVENT_LABELS = { attack: '攻击', defense: '防御', system: '系统' };

function initApp(sid) {
  currentSid = sid;
  canvas = document.getElementById('topoCanvas');
  ctx = canvas.getContext('2d');
  resizeCanvas();
  window.addEventListener('resize', () => { resizeCanvas(); drawTopology(); });
  startAnimLoop();
  fetchState();
  // 六步工作流入口（dashboard 跳转带参）：自动启动动画推演
  var params = new URLSearchParams(window.location.search);
  if (params.get('workflow') === '1') {
    var tid = params.get('topology');
    setTimeout(function() { startWorkflowAnim(tid); }, 600);
  } else if (params.get('round2') === '1') {
    // 整改后拓扑已导入：直接进行第二次推演（防御全开动画）→ 最终报告
    setTimeout(function() { startRound2Anim(); }, 600);
  }
}

// ===== 六步推演工作流动画（2026-09-03 修订流程）=====
// 1.导入拓扑 → 2.首次推演(轮1动画) → 3.整改方案(勾选) → 4.整改落地拓扑图并导入
// → 5.第二次推演(整改后拓扑上动画) → 6.最终推演报告
async function startWorkflowAnim(topologyId) {
  if (remediateRunning || autoPlaying) return;
  remediateRunning = true;
  var btn = document.getElementById('btnRemediate');
  if (btn) btn.textContent = '停止攻防推演';
  try {
    // 步骤1：导入拓扑图（若有）
    if (topologyId) {
      showStageBar('步骤1：导入拓扑图「' + topologyId + '」…', 'r1', 1);
      var imp = await fetch('/api/topology/' + topologyId + '/import', { method: 'POST' });
      var ir = await imp.json();
      if (!ir.ok) { flashError('拓扑导入失败: ' + (ir.error || '')); return; }
      await fetchState();
      await sleep(800);
    }
    // 步骤2：首次推演（轮1 动画）
    await remediateRound1();
    if (!remediateRunning) return;
    // 步骤3：整改方案弹窗（勾选，人在环）
    await showPlanModal();
    if (!remediateRunning) return;
    // 步骤4：整改落地拓扑图 → 导入整改后拓扑（跳转新场景）
    // 由 showPlanModal 内的 applyRemediationAndGoRound2 触发跳转
  } finally {
    remediateRunning = false;
    hideStageBar();
    if (btn) btn.textContent = '启动网络安全攻防推演';
  }
}

// 第二次推演（整改后拓扑场景，round2=1 跳转触发）
async function startRound2Anim() {
  if (remediateRunning || autoPlaying) return;
  remediateRunning = true;
  var btn = document.getElementById('btnRemediate');
  if (btn) btn.textContent = '停止攻防推演';
  try {
    showStageBar('整改后拓扑已导入，准备第二次推演…', 'r2', 3);
    await sleep(800);
    flashError('已进入整改后拓扑：拓扑图中含整改防护设备（[整改] 前缀节点）');
    // 防御全开，在整改后拓扑上推演（注意：start 会重置防御，须先 start 再开防御）
    remediateRound = 2;
    showStageBar('第二次推演（整改后拓扑 · 防御全开）准备中…', 'r2', 4);
    await api('/reset', 'POST');
    await api('/start', 'POST');
    await api('/defense_all', 'POST', { enable: true });
    await fetchState();
    flashError('第二次推演开始：整改后拓扑上，观察防御拦截');
    await runRoundSteps();
    if (!remediateRunning) return;
    showConclusionModal();
  } finally {
    remediateRunning = false;
    hideStageBar();
    if (btn) btn.textContent = '启动网络安全攻防推演';
  }
}

// workflow 负载（2026-09-06 修复）：结论/报告必须以「轮1 原始对象」为基准——
// 整改落地跳转后当前页面是整改后场景，若直接用它跑六步，轮1 现状=整改后（全拦），
// 报告会错误显示「第一轮未被攻破」。orig_topology/orig_scenario 记录轮1 原始对象；
// remediations 透传勾选措施集合（结论与落盘口径 = 用户在弹窗的勾选）。
function payloadWorkflow() {
  var params = new URLSearchParams(window.location.search);
  var origTopo = params.get('orig_topology');
  var origScenario = params.get('orig_scenario');
  var topoParam = params.get('topology');
  var remParam = params.get('remediations');
  var payload;
  if (origTopo) {
    payload = { topology_id: origTopo };
  } else if (origScenario) {
    payload = { scenario_id: origScenario };
  } else if (topoParam) {
    payload = { topology_id: topoParam };
  } else {
    payload = { scenario_id: currentSid };
  }
  if (remParam && remParam.trim()) {
    payload.defense_ids = remParam.split(',').filter(function(x) { return x; });
  }
  return payload;
}

async function finalizeWorkflowReport() {
  // 生成最终推演报告并落盘（复用后端六步工作流接口，确定性复算，毫秒级）
  var content = document.getElementById('graphContent');
  var note = document.getElementById('wfFinalizeNote');
  if (note) note.innerHTML = '<span style="color:var(--text-secondary);">正在生成最终报告并落盘...</span>';
  var res = await fetch('/api/workflow/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // topology_id 优先：动态导入场景在服务重启后会丢失，拓扑库磁盘持久化可重新导入
    body: JSON.stringify(payloadWorkflow())
  });
  var r = await res.json();
  if (!r.ok) {
    if (note) note.innerHTML = '<span style="color:var(--red);">落盘失败：' + (r.error || '') + '</span>';
    return;
  }
  if (note) {
    note.innerHTML = '<span style="color:var(--green);">✓ 最终推演报告已落盘：' + r.report_path + '</span>';
  }
  // 落盘成功后自动展示报告内容（2026-09-06 乐叔要求：点击后自动展示）
  var view = document.getElementById('wfReportView');
  try {
    var vres = await fetch('/api/report/view?path=' + encodeURIComponent(r.report_path));
    var vd = await vres.json();
    if (view) {
      if (vd.ok) {
        view.innerHTML = '<div style="font-weight:600;font-size:13px;margin-bottom:8px;">最终推演报告全文（' +
          escHtml(vd.name) + '）</div>' + mdToHtml(vd.content);
        view.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      } else {
        view.innerHTML = '<div style="color:var(--red);">报告读取失败：' + escHtml(vd.error || '') + '</div>';
      }
    }
  } catch (e) {
    if (view) view.innerHTML = '<div style="color:var(--red);">报告读取异常，请检查服务状态</div>';
  }
}

// 轻量 markdown 渲染（零外部依赖）：标题/列表/加粗
function mdToHtml(md) {
  var lines = String(md || '').split('\n');
  var html = '<div style="text-align:left;max-height:55vh;overflow:auto;background:var(--bg-card);' +
    'border:1px solid var(--border);border-radius:8px;padding:14px;">';
  var inList = false;
  lines.forEach(function (line) {
    var t = line;
    if (/^###\s+/.test(t)) {
      if (inList) { html += '</ul>'; inList = false; }
      html += '<div style="font-weight:600;font-size:13px;margin:10px 0 4px;">' + inlineMd(escHtml(t.slice(4))) + '</div>';
      return;
    }
    if (/^##\s+/.test(t)) {
      if (inList) { html += '</ul>'; inList = false; }
      html += '<div style="font-weight:700;font-size:14px;margin:12px 0 4px;color:#58a6ff;' +
        'border-left:3px solid #58a6ff;padding-left:8px;">' + inlineMd(escHtml(t.slice(3))) + '</div>';
      return;
    }
    if (/^#\s+/.test(t)) {
      if (inList) { html += '</ul>'; inList = false; }
      html += '<div style="font-weight:700;font-size:16px;margin:4px 0 8px;">' + inlineMd(escHtml(t.slice(2))) + '</div>';
      return;
    }
    if (/^\s*[-*]\s+/.test(t)) {
      if (!inList) { html += '<ul style="margin:4px 0;padding-left:18px;">'; inList = true; }
      var indent = (t.match(/^\s*/) || [''])[0].length;
      html += '<li style="font-size:12px;line-height:1.7;margin-left:' + Math.min(indent * 6, 36) + 'px;">' +
        inlineMd(escHtml(t.replace(/^\s*[-*]\s+/, ''))) + '</li>';
      return;
    }
    if (/^\s*\d+\.\s+/.test(t)) {
      if (!inList) { html += '<ul style="margin:4px 0;padding-left:18px;list-style:none;">'; inList = true; }
      html += '<li style="font-size:12px;line-height:1.7;">' +
        inlineMd(escHtml(t.replace(/^\s*(\d+\.)\s+/, '<b>$1</b> '))) + '</li>';
      return;
    }
    if (inList) { html += '</ul>'; inList = false; }
    if (t.trim() === '') return;
    html += '<div style="font-size:12px;line-height:1.7;margin:2px 0;">' + inlineMd(escHtml(t)) + '</div>';
  });
  if (inList) html += '</ul>';
  html += '</div>';
  return html;
}

function inlineMd(s) {
  return s.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
}

function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function resizeCanvas() {
  const rect = canvas.parentElement.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  canvas.style.width = rect.width + 'px';
  canvas.style.height = rect.height + 'px';
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}

async function api(path, method, body) {
  const opts = { method: method || 'GET', headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch('/api/scenario/' + currentSid + path, opts);
  return res.json();
}

async function fetchState() {
  state = await api('');
  renderAll();
}

async function startScenario() {
  await api('/start', 'POST');
  await fetchState();
}

async function resetScenario() {
  // 2026-09-06 修复（乐叔报告"重置无法恢复启动前画面"）：
  // 根因 = 旧版只调 /reset 清后端，前端推演 async 链（remediateRunning）、
  // 一键推演循环（autoPlaying）、stageBar、弹窗全部存活，重置后链条继续
  // 执行攻击并污染画布。必须"先停链、再复位"。
  if (typeof remediateRunning !== 'undefined' && remediateRunning) stopRemediateSim();
  autoPlaying = false;
  currentTarget = null;
  // 关闭所有弹窗（决策/整改方案/报告/攻击图/行为模拟/校准）。
  // 2026-09-14 补 #graphOverlay：整改勾选/决策/攻击图弹窗挂在 graphOverlay 上，
  // 旧版只关 .report-overlay，重置后弹窗残留旧内容（乐叔 16:41 报告"日志/面板没清空"）。
  document.querySelectorAll('.report-overlay, #graphOverlay').forEach(function(el) {
    el.classList.remove('show');
  });
  // 释放可能挂起的决策弹窗 Promise（否则推演链成孤儿挂起）
  if (window._decisionResolve) { window._decisionResolve(null, false); window._decisionResolve = null; }
  if (typeof hideStageBar === 'function') hideStageBar();
  await sleep(450);  // 给推演链一个循环检查点退出，收窄与 /attack 的竞态窗口
  await api('/reset', 'POST');
  await fetchState();
  // 2026-09-06：重置完成反馈——乐叔报告"重置无反应"实为无任何视觉反馈
  // （红色 external 类型色不随重置变化 + 无提示），此处加日志回执。
  // 2026-09-14：回执同步画像复位与整改标记隐藏（乐叔口径"重置=恢复初始状态全绿"）。
  flashDefense('场景已重置：攻陷状态、日志、时间线已清空，攻击者画像已复位默认，整改标记已隐藏（画布恢复全绿初始状态）');
}

async function executeAttack(stepId) {
  // 2026-09-06：删除「启动推演」按钮后，手动点击攻击步骤时自动启动场景
  if (!state.started) {
    await api('/start', 'POST');
    await fetchState();
  }
  const result = await api('/attack', 'POST', { step_id: stepId });
  if (!result.ok && result.error) {
    flashError(result.error);
  }
  await fetchState();
}

async function toggleDefense(defenseId) {
  await api('/defense', 'POST', { defense_id: defenseId });
  await fetchState();
}

async function toggleAllDefenses() {
  var allOn = state.defenses.every(function(d) { return d.active; });
  var res = await fetch('/api/scenario/' + currentSid + '/defense_all', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enable: !allOn })
  }).then(function(r) { return r.json(); });
  await fetchState();
  var btn = document.getElementById('btnAllDef');
  if (btn) btn.textContent = allOn ? '全开' : '全关';
  flashDefense(allOn ? '已关闭全部防护措施' : '已开启全部防护措施（' + (res.active || 0) + '/' + (res.total || 0) + '）');
}

async function toggleProbMode() {
  await api('/prob_mode', 'POST', { enable: !state.prob_mode });
  await fetchState();
}

let autoPlaying = false;
let autoBtnOriginal = '';
let autoMode = 'consequence';      // 一键推演参数面板选择（2026-09-06）
let autoProfile = 'professional';

async function showAutoPlayPanel() {
  // 一键推演参数面板（2026-09-06，借鉴 SafeBreach 新建演练向导）
  var content = document.getElementById('graphContent');
  var modal = document.getElementById('graphOverlay');
  var html = '<div style="font-size:15px;font-weight:600;margin-bottom:10px;">一键推演 · 参数选择</div>';
  html += '<div style="font-size:12px;color:var(--text-secondary);margin-bottom:12px;">选择推演模式与攻击者画像，确认后自动执行（可随时停止）</div>';
  html += '<div style="margin-bottom:12px;"><div style="font-weight:600;font-size:13px;margin-bottom:6px;">推演模式</div>';
  html += '<label style="display:block;padding:8px 12px;margin-bottom:6px;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;cursor:pointer;">';
  html += '<input type="radio" name="autoMode" value="consequence" checked style="margin-right:8px;" onchange="onAutoModeChange()"><b>后果推演</b>';
  html += '<div style="font-size:11px;color:var(--text-secondary);margin:2px 0 0 24px;">按剧本顺序执行全部攻击步骤，观察攻击链与防御拦截过程（线性确定性）</div></label>';
  html += '<label style="display:block;padding:8px 12px;margin-bottom:6px;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;cursor:pointer;">';
  html += '<input type="radio" name="autoMode" value="behavior" style="margin-right:8px;" onchange="onAutoModeChange()"><b>行为模拟</b>';
  html += '<div style="font-size:11px;color:var(--text-secondary);margin:2px 0 0 24px;">攻击者智能体自主决策（目标选择/效用计算/对抗适应），逐步攻陷并输出决策日志</div></label></div>';
  html += '<div id="autoProfileBox" style="display:none;margin-bottom:12px;"><div style="font-weight:600;font-size:13px;margin-bottom:6px;">攻击者画像</div>';
  html += '<select id="autoProfileSel" class="mode-select" style="width:100%;">';
  html += '<option value="script_kiddie">脚本小子（技术弱、随机尝试）</option>';
  html += '<option value="professional" selected>职业黑客（技术熟练、目标导向）</option>';
  html += '<option value="apt">APT（高级持续威胁、隐蔽渗透）</option>';
  html += '</select></div>';
  html += '<button class="btn btn-primary" onclick="runAutoPlayFromPanel()">开始推演</button>';
  html += '<button class="btn" onclick="closeAutoPanel()" style="margin-left:8px;">取消</button>';
  content.innerHTML = html;
  modal.classList.add('show');
}

function onAutoModeChange() {
  var v = document.querySelector('input[name="autoMode"]:checked').value;
  document.getElementById('autoProfileBox').style.display = (v === 'behavior') ? '' : 'none';
}

function closeAutoPanel() {
  document.getElementById('graphOverlay').classList.remove('show');
}

async function runAutoPlayFromPanel() {
  autoMode = (document.querySelector('input[name="autoMode"]:checked') || {}).value || 'consequence';
  var sel = document.getElementById('autoProfileSel');
  if (sel) autoProfile = sel.value;
  closeAutoPanel();
  if (autoMode === 'behavior') {
    await autoPlayBehavior();
  } else {
    await autoPlayConsequence();
  }
}

var anonEnabled = false;
async function toggleAnonymize() {
  anonEnabled = !anonEnabled;
  await fetch('/api/scenario/' + currentSid + '/anonymize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enable: anonEnabled })
  });
  var btn = document.getElementById('btnAnon');
  if (btn) btn.textContent = '脱敏:' + (anonEnabled ? '开' : '关');
  flashError(anonEnabled ? '已开启脱敏，报告与拓扑将隐藏真实资产名' : '已关闭脱敏');
}

async function autoPlayConsequence() {
  const btn = document.getElementById('btnAuto');
  if (autoPlaying) {
    autoPlaying = false;
    if (btn) btn.textContent = autoBtnOriginal;
    return;
  }
  autoPlaying = true;
  autoBtnOriginal = btn ? btn.textContent : '一键推演';
  if (btn) btn.textContent = '停止推演';

  try {
    if (!state.started) {
      await api('/start', 'POST');
      await fetchState();
    }
    // 一次遍历当前 pending 步骤，按序执行，播放攻击叙事
    const pendingSteps = state.attack_steps.filter(function(s) { return s.state === 'pending'; });
    for (let i = 0; i < pendingSteps.length; i++) {
      if (!autoPlaying) break;
      const st = pendingSteps[i];
      // P1-5 决策点：执行到决策步骤前暂停，人在环选择
      var dp = findPendingDecision(st.id);
      if (dp) {
        var resolved = await showDecisionModal(dp);
        if (!autoPlaying || !resolved) break;
        await fetchState();
        var cur = state.attack_steps.find(function(x) { return x.id === st.id; });
        if (cur && cur.state !== 'pending') continue;
      }
      currentTarget = (st.effects && st.effects[0]) ? st.effects[0].target : null;
      const r = await api('/attack', 'POST', { step_id: st.id });
      if (!r.ok && r.error) {
        flashError('一键推演跳过: ' + st.name + ' - ' + r.error);
        currentTarget = null;
        continue;
      }
      // 播放攻击叙事（分阶段技术动作，慢节奏）
      await playNarrative(r.narrative || [], st.name);
      if (r.blocked) {
        flashDefense('被防御拦截: ' + r.defense);
      } else {
        flashAttack('✓ 攻击得手');
      }
      await fetchState();
      currentTarget = null;
      await sleep(600);
    }
  } finally {
    autoPlaying = false;
    if (btn) btn.textContent = autoBtnOriginal;
    if (state && state.started) flashError('一键推演结束，可查看推演报告');
  }
}

async function playNarrative(narrative, stepName) {
  if (narrative.length) {
    flashAttack('► ' + stepName + '（' + narrative.length + ' 个动作）');
    await sleep(400);
  }
  for (let i = 0; i < narrative.length; i++) {
    if (!autoPlaying && !remediateRunning) break;
    flashAttack('　' + narrative[i].action);
    await sleep(1600);
  }
}

async function autoPlayBehavior() {
  const btn = document.getElementById('btnAuto');
  if (autoPlaying) {
    autoPlaying = false;
    if (btn) btn.textContent = autoBtnOriginal;
    return;
  }
  autoPlaying = true;
  autoBtnOriginal = btn ? btn.textContent : '一键推演';
  if (btn) btn.textContent = '停止推演';

  try {
    var profile = autoProfile || 'professional';
    var start = await api('/behavior_start', 'POST', { profile: profile });
    if (!start.ok) {
      flashError('行为推演启动失败: ' + (start.error || ''));
      return;
    }
    await fetchState();
    flashAttack('攻击者智能体已启动（' + profile + '），目标清单 ' + (start.goal_count || 0) + ' 个: ' + (start.goals_labels || []).join('、'));

    // 逐步自主决策，最多 30 步
    for (let i = 0; i < 30; i++) {
      if (!autoPlaying) break;
      var r = await api('/behavior_step', 'POST');
      if (!r.ok) break;
      if (!r.decision) {
        flashError('攻击者无路可走，推演结束');
        break;
      }
      var d = r.decision;
      var u = d.utility || {};
      currentTarget = d.target;
      // 播放攻击叙事（攻击者视角，技术动作）
      await playNarrative(d.narrative || [], '攻击 ' + d.target_label);
      var msg = (d.success ? '攻陷 ' : '攻击失败 ') + d.target_label +
                (d.detected ? ' · 被检测' : '') +
                ' · 效用=' + (u.total !== undefined ? u.total : '-') +
                '（成功率 ' + (u.success !== undefined ? Math.round(u.success * 100) : '-') + '%）';
      if (d.success) flashAttack(msg); else flashDefense(msg);
      await fetchState();  // 更新 canvas 节点状态
      currentTarget = null;
      if (r.done) {
        var doneMsg = (r.achieved_count >= r.goal_count)
          ? '⚠ 攻击者攻陷全部 ' + r.goal_count + ' 个目标'
          : '攻击者推演结束（已攻陷 ' + (r.achieved_count || 0) + '/' + (r.goal_count || 0) + ' 目标）';
        flashAttack(doneMsg);
        break;
      }
      await sleep(700);
    }
  } finally {
    autoPlaying = false;
    if (btn) btn.textContent = autoBtnOriginal;
  }
}

// 返回未满足的前置条件文案列表（空数组=满足）
function preconditionsUnmet(s) {
  if (!s.preconditions || s.preconditions.length === 0) return [];
  var nodeStates = {};
  state.nodes.forEach(function(n) { nodeStates[n.id] = n.state; });
  var unmet = [];
  s.preconditions.forEach(function(pre) {
    if (pre.type === 'step_completed') {
      var st = null;
      for (var i = 0; i < state.attack_steps.length; i++) {
        if (state.attack_steps[i].id === pre.step) { st = state.attack_steps[i]; break; }
      }
      if (!st || st.state !== 'completed') unmet.push('需先完成步骤 ' + pre.step);
    } else if (pre.type === 'node_compromised') {
      var ns = nodeStates[pre.node];
      var breached = ['compromised', 'exfiltrated', 'encrypted'];
      if (breached.indexOf(ns) < 0) unmet.push('需先攻陷节点 ' + pre.node);
    }
  });
  return unmet;
}

function flashError(msg) {
  const body = document.getElementById('logBody');
  const entry = document.createElement('div');
  entry.className = 'log-entry warning';
  const now = new Date();
  const t = String(now.getHours()).padStart(2,'0') + ':' + String(now.getMinutes()).padStart(2,'0') + ':' + String(now.getSeconds()).padStart(2,'0');
  entry.innerHTML = '<span class="log-time">' + t + '</span><span class="log-type system">系统</span><span class="log-msg">' + msg + '</span>';
  body.insertBefore(entry, body.firstChild);
}

function sleep(ms) { return new Promise(function(res) { setTimeout(res, ms); }); }

function flashAttack(msg) {
  var body = document.getElementById('logBody');
  if (!body) return;
  var entry = document.createElement('div');
  entry.className = 'log-entry danger';
  var now = new Date();
  var t = String(now.getHours()).padStart(2,'0') + ':' + String(now.getMinutes()).padStart(2,'0') + ':' + String(now.getSeconds()).padStart(2,'0');
  entry.innerHTML = '<span class="log-time">' + t + '</span><span class="log-type attack">攻击者</span><span class="log-msg">' + msg + '</span>';
  body.insertBefore(entry, body.firstChild);
}

function flashDefense(msg) {
  var body = document.getElementById('logBody');
  if (!body) return;
  var entry = document.createElement('div');
  entry.className = 'log-entry';
  var now = new Date();
  var t = String(now.getHours()).padStart(2,'0') + ':' + String(now.getMinutes()).padStart(2,'0') + ':' + String(now.getSeconds()).padStart(2,'0');
  entry.innerHTML = '<span class="log-time">' + t + '</span><span class="log-type defense">防御方</span><span class="log-msg">' + msg + '</span>';
  body.insertBefore(entry, body.firstChild);
}

function renderAll() {
  if (!state) return;
  var sidEl = document.getElementById('sessionId');
  if (sidEl) sidEl.textContent = state.session_id ? '#' + state.session_id : '';

  var dot = document.getElementById('statusDot');
  var text = document.getElementById('statusText');
  if (!state.started) {
    dot.className = 'status-dot idle';
    text.textContent = '未启动';
  } else {
    var completed = state.attack_steps.filter(function(s) { return s.state === 'completed'; }).length;
    var total = state.attack_steps.length;
    if (completed === total && total > 0) {
      dot.className = 'status-dot complete';
      text.textContent = '推演完成 (' + completed + '/' + total + ')';
    } else {
      dot.className = 'status-dot running';
      text.textContent = '推演中 (' + completed + '/' + total + ')';
    }
  }

  renderAttackSteps();
  renderDefenses();
  renderRemediations();
  renderAssets();
  renderEventLog();
  renderTimeline();
  renderProbToggle();
}

function renderProbToggle() {
  var sw = document.getElementById('probSwitch');
  var hint = document.getElementById('probHint');
  if (!sw) return;
  if (state.prob_mode) {
    sw.className = 'toggle on';
    if (hint) hint.textContent = state.bypassed !== undefined ? ('已绕过 ' + state.bypassed + ' 次') : '已开启';
  } else {
    sw.className = 'toggle';
    if (hint) hint.textContent = '确定性拦截';
  }
}

function startAnimLoop() {
  if (animRunning) return;
  animRunning = true;
  function loop() {
    animFrame++;
    drawTopology();
    requestAnimationFrame(loop);
  }
  requestAnimationFrame(loop);
}

function drawTopology() {
  if (!state || !state.nodes) return;
  var w = canvas.clientWidth;
  var h = canvas.clientHeight;
  ctx.clearRect(0, 0, w, h);

  // 2026-09-14 乐叔口径（17:32 三度强调）：未启动（打开场景/重置后）画布必须
  // 回到原始拓扑画面——轮2 整改新增设备节点（rem_ 前缀）一律不渲染；
  // 推演进行中（started）才显示整改设备（品红+「改」角标，可视化为拦截方）。
  var visibleNodes = state.started
    ? state.nodes
    : state.nodes.filter(function(n) {
        return !String(n.id).startsWith('rem_') && !n.remediation;
      });

  var padding = 50;
  var xs = visibleNodes.map(function(n) { return n.x; });
  var ys = visibleNodes.map(function(n) { return n.y; });
  var minX = Math.min.apply(null, xs), maxX = Math.max.apply(null, xs);
  var minY = Math.min.apply(null, ys), maxY = Math.max.apply(null, ys);
  var spanX = Math.max(maxX - minX, 1), spanY = Math.max(maxY - minY, 1);
  var availW = w - padding * 2;
  var availH = h - padding * 2;
  // 2026-09-09 空白区根治（乐叔报告）：改用 span 口径——按内容跨度缩放并
  // 补偿最小坐标偏移。旧 maxX/maxY 口径在坐标非零起点时 scale 被低估、
  // 内容挤在画布角落，四周大片空白（实测内容仅占画布 24%-47%）。
  // scale 上限提至 2.0（原 1.3 限制小场景放大），配合 effR/label/type 纯随
  // scale 缩放保持比例恒定，稀疏场景也能铺满画布。
  var scale = Math.min(availW / spanX, availH / spanY, 2.0);
  var offsetX = (w - spanX * scale) / 2 - minX * scale;
  var offsetY = (h - spanY * scale) / 2 - minY * scale;
  // 2026-09-06 遮挡根治：节点半径/标签/字号全部随 scale 缩放，
  // 视觉比例恒定——任何画布尺寸下节点间距与圆径/标签比例不变，永不相压。
  // 2026-09-09 上限随 scale 上限同步放宽（scale≤2.0 时 clamp 不触发，恒定为真）。
  var effR = Math.max(15, Math.min(48, 26 * scale));
  var labelFont = Math.max(9.5, Math.min(17, 11 * scale));
  var typeFont = Math.max(8, Math.min(14, 10 * scale));

  nodePositions = {};
  visibleNodes.forEach(function(n) {
    nodePositions[n.id] = { x: n.x * scale + offsetX, y: n.y * scale + offsetY };
  });

  // Draw edges。2026-09-14：未启动时隐藏整改接入边，被重定向的原边
  // （原拓扑边在整改落地时改指 rem_ 设备）按整改接入边还原到锚点，
  // 保证未启动画面 = 原始拓扑连线完整。
  var remAnchor = {};
  if (!state.started) {
    state.edges.forEach(function(e) {
      if (String(e.from).startsWith('rem_')) remAnchor[e.from] = e.to;
    });
  }
  // 2026-09-18 绘图规范整改（与 topology.js 同一算法）：边从直线改 90° 正交
  // 折线（竖→横→竖三段），水平段自动落入节点间空隙带避盒。圆形节点按
  // 外接正方形（半径 effR+4）避障；JSON 无 waypoints 概念，纯实时路由。
  var obstacleBoxes = visibleNodes.map(function(n) {
    var p = nodePositions[n.id], r = effR + 4;
    return { id: n.id, x1: p.x - r, y1: p.y - r, x2: p.x + r, y2: p.y + r };
  });
  function pickClearYC(y1, y2, xA, xB, ym0, excl) {
    var lo = Math.min(y1, y2) + 1, hi = Math.max(y1, y2) - 1;
    if (hi <= lo) return ym0;
    var xLo = Math.min(xA, xB), xHi = Math.max(xA, xB);
    var spans = [];
    obstacleBoxes.forEach(function(b) {
      if (excl[b.id]) return;
      if (b.x2 <= xLo || b.x1 >= xHi) return;
      if (b.y2 <= lo || b.y1 >= hi) return;
      spans.push([Math.max(b.y1, lo), Math.min(b.y2, hi)]);
    });
    if (!spans.length) return ym0;
    spans.sort(function(a, b) { return a[0] - b[0]; });
    var gaps = [], cur = lo;
    spans.forEach(function(sp) {
      if (sp[0] > cur) gaps.push([cur, sp[0]]);
      cur = Math.max(cur, sp[1]);
    });
    if (cur < hi) gaps.push([cur, hi]);
    var pool = gaps.filter(function(g) { return g[1] - g[0] >= 6; });
    var use = pool.length ? pool : gaps;
    if (!use.length) return ym0;
    var best = use[0], bd = Infinity;
    use.forEach(function(g) {
      var mid = (g[0] + g[1]) / 2, d = Math.abs(mid - ym0);
      if (d < bd) { bd = d; best = g; }
    });
    return (best[0] + best[1]) / 2;
  }
  function vSegHitsBoxC(xC, yA, yB, excl) {
    var lo = Math.min(yA, yB), hi = Math.max(yA, yB);
    for (var i = 0; i < obstacleBoxes.length; i++) {
      var b = obstacleBoxes[i];
      if (excl[b.id]) continue;
      if (xC > b.x1 && xC < b.x2 && hi > b.y1 && lo < b.y2) return true;
    }
    return false;
  }
  var edgeIdxC = 0;
  state.edges.forEach(function(e) {
    var fromId = e.from, toId = e.to;
    if (!state.started) {
      if (String(fromId).startsWith('rem_')) return;              // 整改接入边隐藏
      if (String(toId).startsWith('rem_')) toId = remAnchor[toId] || toId;  // 还原原边
    }
    var from = nodePositions[fromId];
    var to = nodePositions[toId];
    if (!from || !to) return;
    var myIdx = edgeIdxC++;
    ctx.strokeStyle = '#30363d';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    var x1 = from.x, y1 = from.y + effR;  // 圆底出
    var x2 = to.x, y2 = to.y - effR;      // 圆顶入
    if (Math.abs(y2 - y1) < 2 || Math.abs(x2 - x1) < 2) {
      ctx.moveTo(x1, y1); ctx.lineTo(x2, y2);
    } else {
      var excl = {}; excl[fromId] = 1; excl[toId] = 1;
      var ym = pickClearYC(y1, y2, x1, x2, (y1 + y2) / 2, excl);
      var pts = [[x1, y1], [x1, ym], [x2, ym], [x2, y2]];
      if (vSegHitsBoxC(x1, y1, ym, excl) || vSegHitsBoxC(x2, ym, y2, excl)) {
        var ySide = y2 < y1 ? y1 - 2 * effR : y1 + 2;
        if (!vSegHitsBoxC(x2, ySide, y2, excl))
          pts = [[x1, y1], [x1, ySide], [x2, ySide], [x2, y2]];
      }
      // 2026-09-18 水平段分道（±3px 多车道，与 topology.js 同步）
      var lane = (myIdx % 3 - 1) * 3;
      if (lane !== 0 && pts.length === 4) {
        pts = pts.map(function(p, i) { return (i === 1 || i === 2) ? [p[0], p[1] + lane] : p; });
      }
      ctx.moveTo(pts[0][0], pts[0][1]);
      for (var pi = 1; pi < pts.length; pi++) ctx.lineTo(pts[pi][0], pts[pi][1]);
    }
    ctx.stroke();
  });

  // Draw nodes
  var radius = effR;
  visibleNodes.forEach(function(n) {
    var pos = nodePositions[n.id];
    var baseColor = NODE_COLORS[n.type] || '#8b949e';
    // 2026-09-06 乐叔定稿：初始态（safe）按类别分色——攻击者恒红、网络青、
    // 设备橙、系统绿；推演状态色（target/compromised/...）显式覆盖类别色。
    var cat = nodeCategory(n);
    var isAttacker = cat === 'attacker';
    var fillOverride = (n.state === 'safe' || isAttacker)
      ? CATEGORY_COLORS[cat].fill : STATE_FILLS[n.state];
    var strokeOverride = (n.state === 'safe' || isAttacker)
      ? CATEGORY_COLORS[cat].stroke : STATE_STROKES[n.state];
    // 2026-09-14 乐叔三修（A）：品红整改标记仅推演进行中（started）显示。
    // 重置后 started=False → 品红隐藏，画布恢复"全绿初始状态"（乐叔口径）。
    // 整改标记是推演可视化层，不是拓扑静态色；重新推演时自动恢复显示。
    var isRemediation = !!n.remediation && state.started;

    // Pulse glow for attacker（攻击者恒红脉冲，警示威胁源）
    if (isAttacker) {
      var apulse = Math.sin(animFrame * 0.06) * 0.25 + 0.75;
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, radius + 10, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(248,81,73,' + (apulse * 0.18) + ')';
      ctx.fill();
    }

    // Pulse glow for target（整改设备用品红光晕，与现状节点的土黄光晕区分）
    if (n.state === 'target') {
      var pulse = Math.sin(animFrame * 0.06) * 0.3 + 0.7;
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, radius + 10, 0, Math.PI * 2);
      ctx.fillStyle = isRemediation
        ? 'rgba(255,123,206,' + (pulse * 0.2) + ')'
        : 'rgba(210,153,34,' + (pulse * 0.15) + ')';
      ctx.fill();
    }

    // Pulse ring for "under attack"（攻击进行中）
    if (n.id === currentTarget) {
      var ap = Math.sin(animFrame * 0.12) * 0.4 + 0.6;
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, radius + 14 + ap * 4, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(248,81,73,' + ap + ')';
      ctx.lineWidth = 2.5;
      ctx.stroke();
    }

    // Ring for defended
    if (n.state === 'defended') {
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, radius + 6, 0, Math.PI * 2);
      ctx.strokeStyle = '#58a6ff';
      ctx.lineWidth = 2;
      ctx.setLineDash([4, 3]);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Main circle（整改设备节点：品红渐变 + 亮品红边，与现状防护/数据泄露紫明确区分）
    ctx.beginPath();
    ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2);
    if (isRemediation) {
      var grad = ctx.createRadialGradient(pos.x, pos.y, 2, pos.x, pos.y, radius);
      grad.addColorStop(0, 'rgba(255,123,206,0.5)');
      grad.addColorStop(1, 'rgba(255,123,206,0.16)');
      ctx.fillStyle = fillOverride || grad;
    } else {
      ctx.fillStyle = fillOverride || (baseColor + '22');
    }
    ctx.fill();
    ctx.strokeStyle = isRemediation ? '#ff7bce' : (strokeOverride || baseColor);
    ctx.lineWidth = isRemediation ? 3 : 2.5;
    ctx.stroke();

    // 整改设备角标（右上等腰三角形，「改」字置于内心居中显示）
    if (isRemediation) {
      var tax = pos.x + radius + 9,  tay = pos.y - radius - 16;  // 顶角
      var tbx = pos.x + radius - 2,  tby = pos.y - radius + 3;   // 左下
      var tcx = pos.x + radius + 20, tcy = pos.y - radius + 3;   // 右下
      ctx.beginPath();
      ctx.moveTo(tax, tay);
      ctx.lineTo(tbx, tby);
      ctx.lineTo(tcx, tcy);
      ctx.closePath();
      ctx.fillStyle = '#ff7bce';
      ctx.fill();
      ctx.strokeStyle = 'rgba(13,17,23,0.6)';
      ctx.lineWidth = 1;
      ctx.stroke();
      // 内心（等腰三角形对称轴上，距底边 1/3 高）：字居中于此
      ctx.fillStyle = '#0d1117';
      ctx.font = 'bold 9px -apple-system, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('改', pos.x + radius + 9, pos.y - radius - 3.4);
    }

    // Label（2026-09-06 乐叔报告遮挡：原标签绘于圆内 y-2，中文标签超 4 字
    // （宽 > 圆直径 52px）即溢出切边——"应用服务器"等 5 字标签被圆框截断。
    // 修复：主标签移到节点下方 + 半透明背景条（防压线/压邻节点不可读），
    // type 短文字保留圆内。全场景渲染层统一生效，新拓扑天然免疫。
    var lw = ctx.measureText(n.label).width;
    var ly = pos.y + radius + 10;
    ctx.fillStyle = 'rgba(13,17,23,0.82)';
    var bx = pos.x - lw / 2 - 5, by = ly - 8, bw = lw + 10, bh = 15;
    ctx.beginPath();
    if (ctx.roundRect) { ctx.roundRect(bx, by, bw, bh, 3); }
    else { ctx.rect(bx, by, bw, bh); }
    ctx.fill();
    ctx.fillStyle = '#e6edf3';
    ctx.font = '500 ' + labelFont + 'px -apple-system, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(n.label, pos.x, ly);

    // Type label（圆内短文字）
    ctx.fillStyle = '#6e7681';
    ctx.font = typeFont + 'px -apple-system, sans-serif';
    ctx.fillText(n.type, pos.x, pos.y + 12);
  });
}

function renderAttackSteps() {
  var list = document.getElementById('attackList');
  var completed = state.attack_steps.filter(function(s) { return s.state === 'completed'; }).length;
  document.getElementById('attackCount').textContent = completed + '/' + state.attack_steps.length;

  var html = '';
  state.attack_steps.forEach(function(s, i) {
    var unmet = preconditionsUnmet(s);
    // 2026-09-06：删除「启动推演」按钮后，未启动时步骤可点击（点击自动启动）
    var disabled = s.state !== 'pending' || unmet.length > 0;
    var classes = ['attack-step'];
    if (s.state === 'completed') classes.push('completed');
    if (s.state === 'blocked') classes.push('blocked');
    if (disabled) classes.push('disabled');

    html += '<div class="' + classes.join(' ') + '"';
    if (!disabled) html += ' onclick="executeAttack(\'' + s.id + '\')"';
    html += '>';
    html += '<div class="step-header">';
    html += '<span class="step-num">' + String(i+1).padStart(2,'0') + '</span>';
    html += '<span class="step-name">' + s.name + '</span>';
    html += '<span class="step-status ' + s.state + '">' + STEP_LABELS[s.state] + '</span>';
    html += '</div>';
    html += '<div class="step-desc">' + s.desc + '</div>';
    // 前置条件提示：已执行/被拦截时给原因，pending 但前置未满足时给出具体缺口
    if (s.state === 'pending' && unmet.length > 0) {
      html += '<div class="step-pre">⚠ ' + unmet.join('；') + '</div>';
    } else if (s.state === 'pending') {
      html += '<div class="step-pre ok">✓ 前置条件已满足，可执行</div>';
    }
    html += '<div class="step-meta">';
    if (s.mitre_tactic_zh) html += '<span class="tag tag-tactic">' + s.mitre_tactic_zh + '</span>';
    if (s.mitre) html += '<span class="tag tag-mitre" title="' + (s.technique || '') + '">' + s.mitre + '</span>';
    if (s.cwe) html += '<span class="tag tag-cwe" title="' + s.cwe + '">' + s.cwe.split(' ')[0] + '</span>';
    if (s.cve && s.cve.length) html += '<span class="tag tag-cve" title="' + s.cve_note + '">' + s.cve[0].id + '</span>';
    if (s.exploitability !== undefined) html += '<span class="tag tag-cvss">CVSS可利用性 ' + Math.round(s.exploitability * 100) + '%</span>';
    if (s.detection) html += '<span>检测: ' + s.detection + '</span>';
    html += '</div></div>';
  });
  list.innerHTML = html;
}

function renderDefenses() {
  var list = document.getElementById('defenseList');
  var active = state.defenses.filter(function(d) { return d.active; }).length;
  document.getElementById('defenseCount').textContent = active + '/' + state.defenses.length;

  var html = '';
  state.defenses.forEach(function(d) {
    html += '<div class="defense-item' + (d.active ? ' active' : '') + '">';
    html += '<div class="def-header">';
    html += '<span class="def-name">' + d.name + '</span>';
    var toggleOn = state.started ? ' onclick="toggleDefense(\'' + d.id + '\')"' : '';
    html += '<div class="toggle' + (d.active ? ' on' : '') + '"' + toggleOn + '></div>';
    html += '</div>';
    html += '<div class="def-desc">' + d.desc + '</div>';
    html += '<div class="def-meta"><span>成本: ' + d.cost + '</span><span>' + d.category + '</span>';
    if (d.bypass_rate !== undefined && d.bypass_rate > 0) {
      html += '<span title="概率模式下攻击绕过此防御的概率">绕过率: ' + Math.round(d.bypass_rate * 100) + '%</span>';
    }
    html += '</div></div>';
  });
  list.innerHTML = html;
}

function renderEventLog() {
  var body = document.getElementById('logBody');
  // 2026-09-06 修复：事件为空（如重置后）必须清空旧日志 DOM，
  // 否则重置前的事件残留（旧版直接 return 导致）
  if (!state.events || state.events.length === 0) {
    body.innerHTML = '<div class="log-entry"><span class="log-msg" style="color:var(--text-muted);">暂无事件（启动推演后此处滚动显示攻防事件）</span></div>';
    return;
  }

  var html = '';
  state.events.slice().reverse().forEach(function(e) {
    html += '<div class="log-entry ' + (e.severity || '') + '">';
    html += '<span class="log-time">' + e.time + '</span>';
    html += '<span class="log-type ' + e.type + '">' + (EVENT_LABELS[e.type] || e.type) + '</span>';
    html += '<span class="log-msg">' + e.message + '</span>';
    html += '</div>';
  });
  body.innerHTML = html;
}

async function showReport() {
  var report = await api('/report');
  var content = document.getElementById('reportContent');
  var s = report.summary;

  var stepsHtml = '';
  report.attack_steps.forEach(function(step, i) {
    stepsHtml += '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:6px;">';
    stepsHtml += '<div style="display:flex;justify-content:space-between;align-items:center;">';
    stepsHtml += '<span style="font-weight:500;">' + (i+1) + '. ' + step.name + '</span>';
    var color = step.state === 'completed' ? 'var(--red)' : (step.state === 'blocked' ? 'var(--green)' : 'var(--text-secondary)');
    stepsHtml += '<span style="font-size:10px;padding:1px 8px;border-radius:10px;background:rgba(139,148,158,0.15);color:' + color + ';">' + STEP_LABELS[step.state] + '</span>';
    stepsHtml += '</div>';
    stepsHtml += '<div style="font-size:11px;color:var(--text-secondary);margin-top:4px;">' + step.desc + '</div>';
    var metaHtml = '';
    if (step.mitre_tactic_zh) metaHtml += '<span class="tag tag-tactic">' + step.mitre_tactic_zh + '</span>';
    if (step.mitre) metaHtml += '<span class="tag tag-mitre">' + step.mitre + ' ' + (step.technique || '') + '</span>';
    if (step.cwe) metaHtml += '<span class="tag tag-cwe">' + step.cwe + '</span>';
    if (step.cve && step.cve.length) {
      step.cve.forEach(function(cv) {
        metaHtml += '<span class="tag tag-cve" title="' + step.cve_note + '">' + cv.id + ' ' + cv.name + '</span>';
      });
    }
    if (step.cvss) metaHtml += '<span class="tag tag-cvss" title="' + step.cvss + '">' + step.cvss + '</span>';
    if (metaHtml) stepsHtml += '<div style="margin-top:6px;">' + metaHtml + '</div>';
    stepsHtml += '</div>';
  });

  var nodesHtml = '';
  report.nodes.forEach(function(n) {
    var color = STATE_STROKES[n.state] || '#8b949e';
    nodesHtml += '<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);">';
    nodesHtml += '<span>' + n.label + ' <span style="color:var(--text-muted);font-size:11px;">(' + n.type + ')</span></span>';
    nodesHtml += '<span style="font-family:var(--font-mono);font-size:12px;color:' + color + ';">' + n.state + '</span>';
    nodesHtml += '</div>';
  });

  // D 档：检测-响应时间线
  var tlHtml = '';
  if (report.timeline && report.timeline.length) {
    var tlLabels = { attack: '攻击', bypass: '绕过防御', block: '拦截', detect: '检测', respond: '响应' };
    var tlColors = { attack: 'var(--red)', bypass: 'var(--red)', block: 'var(--green)', detect: 'var(--orange)', respond: 'var(--accent)' };
    report.timeline.forEach(function(ev) {
      tlHtml += '<div style="display:flex;align-items:baseline;gap:10px;padding:4px 0;border-bottom:1px dashed var(--border);">';
      tlHtml += '<span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);white-space:nowrap;">T+' + ev.t + 'min</span>';
      tlHtml += '<span style="font-size:10px;padding:0 6px;border-radius:8px;color:' + (tlColors[ev.type] || 'var(--text-secondary)') + ';background:rgba(139,148,158,0.12);">' + (tlLabels[ev.type] || ev.type) + '</span>';
      tlHtml += '<span style="font-size:11px;color:var(--text-secondary);">' + ev.message + '</span>';
      tlHtml += '</div>';
    });
  }

  // 整改建议单
  var remedHtml = '';
  if (report.remediation && report.remediation.length) {
    report.remediation.forEach(function(r) {
      var pillColor = r.cost === '低' ? 'rgba(63,185,80,0.3)' : (r.cost === '中' ? 'rgba(210,153,34,0.3)' : 'rgba(248,81,73,0.3)');
      remedHtml += '<div class="remed-item">';
      remedHtml += '<div class="remed-head">';
      remedHtml += '<span class="remed-name">' + r.item + '</span>';
      remedHtml += '<span class="remed-pill" style="background:' + pillColor + ';color:var(--text);">' + r.priority_hint + '</span>';
      remedHtml += '</div>';
      remedHtml += '<div class="remed-detail">' + r.detail + '</div>';
      remedHtml += '<div class="remed-meta">责任部门（建议）: ' + r.dept + ' | 成本: ' + r.cost + (r.bypass_rate > 0 ? ' | 绕过率: ' + Math.round(r.bypass_rate*100) + '%' : '') + '</div>';
      remedHtml += '</div>';
    });
  }

  // P1-3/P3：业务后果 + 合规
  var bcHtml = '';
  var bc = report.business_consequences;
  if (bc && bc.breached_assets && bc.breached_assets.length) {
    bc.breached_assets.forEach(function(a) {
      var safeColor = a.patient_safety === '高' ? 'var(--red)' : (a.patient_safety === '中' ? 'var(--orange)' : 'var(--green)');
      bcHtml += '<div style="padding:8px 0;border-bottom:1px solid var(--border);">';
      bcHtml += '<div style="display:flex;justify-content:space-between;"><span style="font-weight:500;">' + a.node + '</span>';
      bcHtml += '<span style="font-size:11px;color:var(--text-muted);">敏感级 ' + a.sensitivity.level + '（' + a.sensitivity.grade + '）</span></div>';
      bcHtml += '<div style="font-size:12px;color:var(--text-secondary);margin-top:3px;">' + a.business + '</div>';
      bcHtml += '<div style="font-size:11px;margin-top:3px;">患者安全: <span style="color:' + safeColor + ';">' + a.patient_safety + '</span></div>';
      bcHtml += '<div style="font-size:11px;color:var(--text-muted);margin-top:3px;">涉合规: ' + (a.compliance || []).join('、') + '</div>';
      bcHtml += '</div>';
    });
  } else {
    bcHtml = '<p style="color:var(--text-muted);font-size:12px;">无资产被攻陷</p>';
  }

  // P1-6：影响传播链（兵棋多域复合影响）
  var chainHtml = '';
  var impactChain = bc && bc.impact_chain;
  if (impactChain && impactChain.chains && impactChain.chains.length) {
    impactChain.chains.forEach(function(ch) {
      var items = ch.chain.map(function(c) {
        var dc = c.domain === '组织域' ? 'var(--red)' : (c.domain === '业务域' ? 'var(--orange)' : 'var(--accent)');
        return '<span style="padding:1px 8px;border-radius:8px;background:rgba(139,148,158,0.12);color:' + dc + ';font-size:10px;margin-right:4px;">' + c.node + '</span>';
      }).join('<span style="color:var(--text-muted);"> → </span>');
      chainHtml += '<div style="padding:6px 0;border-bottom:1px solid var(--border);">';
      chainHtml += '<div style="font-size:11px;color:var(--text-muted);margin-bottom:4px;">源：' + ch.source + '</div>';
      chainHtml += '<div>' + items + '</div></div>';
    });
  } else {
    chainHtml = '<p style="color:var(--text-muted);font-size:12px;">无资产被攻陷，无影响传播</p>';
  }

  // P0-3：ATT&CK 覆盖度（异步获取）
  var cov = null;
  try {
    var covRes = await fetch('/api/scenario/' + currentSid + '/attck_coverage');
    cov = await covRes.json();
  } catch (e) {}
  var covHtml = '';
  if (cov && cov.matrix) {
    var bars = cov.matrix.map(function(t) {
      var pct = Math.min(100, Math.round(t.step_count * 100 / Math.max(cov.total_steps, 1)));
      return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">' +
        '<span style="font-size:11px;width:56px;flex-shrink:0;color:var(--text-secondary);">' + t.tactic + '</span>' +
        '<div style="flex:1;height:10px;background:var(--border);border-radius:5px;overflow:hidden;">' +
        '<div style="height:100%;width:' + pct + '%;background:linear-gradient(90deg,#58a6ff,#bc8cff);"></div></div>' +
        '<span style="font-size:10px;color:var(--text-muted);width:34px;text-align:right;">' + t.step_count + '步</span></div>';
    }).join('');
    covHtml = '<p style="font-size:12px;color:var(--text-secondary);margin-bottom:6px;">' +
      '覆盖 ' + cov.total_techniques + ' 个 ATT&CK 技术 / ' + cov.covered_tactics + ' 个战术（共 ' + cov.tactic_order_total + ' 战术）</p>' + bars;
  } else {
    covHtml = '<p style="color:var(--text-muted);font-size:12px;">无覆盖数据</p>';
  }

  // P3：AAR 复盘
  var aarHtml = '';
  var aar = report.aar;
  if (aar) {
    var chain = (aar.attack_chain || []).map(function(c) { return c.name + (c.tactic ? '(' + c.tactic + ')' : ''); }).join(' → ');
    aarHtml += '<p style="font-size:12px;color:var(--text-secondary);">攻击链: ' + (chain || '无') + '</p>';
    aarHtml += '<p style="font-size:12px;color:var(--text-secondary);margin-top:4px;">已拦截 ' + (aar.blocked_count || 0) + ' 步 | 防御缺口 ' + (aar.defense_gaps ? aar.defense_gaps.length : 0) + ' 处</p>';
    if (aar.improvements && aar.improvements.length) {
      aarHtml += '<p style="font-size:12px;font-weight:500;margin-top:6px;">改进项：</p>';
      aar.improvements.forEach(function(im) {
        aarHtml += '<div style="font-size:11px;color:var(--text-secondary);padding:3px 0;">· ' + im.item + '（' + (im.dept || '') + '）</div>';
      });
    }
  }

  // 演练评估评分卡（2026-09-23 丈八「人才培养 PDCA」思想）
  var scHtml = '';
  var sc = report.scorecard;
  if (sc && sc.dimensions && sc.dimensions.length) {
    scHtml = '<div style="display:flex;align-items:center;gap:14px;margin-bottom:8px;">' +
      '<div style="font-size:28px;font-weight:700;color:var(--accent);">' + sc.total +
      '<span style="font-size:11px;color:var(--text-muted);font-weight:400;"> 分</span></div>' +
      '<div style="font-size:14px;font-weight:600;">' + sc.grade + '</div></div>';
    sc.dimensions.forEach(function(d) {
      var pct = Math.round(d.score * 100 / d.max);
      scHtml += '<div style="margin-bottom:5px;">' +
        '<div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-secondary);">' +
        '<span>' + d.name + '</span><span>' + d.score + '/' + d.max + '</span></div>' +
        '<div style="height:6px;background:var(--bg-hover);border-radius:3px;margin-top:2px;">' +
        '<div style="width:' + pct + '%;height:6px;background:var(--accent);border-radius:3px;"></div></div>' +
        '<div style="font-size:10px;color:var(--text-muted);margin-top:2px;">' + d.detail + '</div></div>';
    });
    if (sc.note) scHtml += '<div style="font-size:10px;color:var(--text-muted);">' + sc.note + '</div>';
    scHtml += '<div style="font-size:10px;color:var(--text-muted);margin-top:4px;">' + (sc.disclaimer || '') + '</div>';
  } else {
    scHtml = '<p style="color:var(--text-muted);font-size:12px;">推演后生成</p>';
  }

  var modeNote = report.prob_mode
    ? '<p style="color:var(--orange);font-size:12px;">概率仿真模式：防御存在预设绕过率，结果含随机性，仅供参考。</p>'
    : '<p style="color:var(--text-secondary);font-size:12px;">确定性模式：防御拦截为二元判定。</p>';

  content.innerHTML =
    '<h2>推演报告 - ' + report.scenario + '</h2>' +
    '<p style="color:var(--text-secondary);margin-bottom:8px;font-size:12px;">会话: ' + report.session_id + ' | 启动时间: ' + (report.start_time || 'N/A') + '</p>' +
    '<p style="margin-bottom:16px;font-size:11px;"><span style="padding:2px 10px;border-radius:10px;background:rgba(210,153,34,0.15);color:var(--orange);">密级：' + (report.classification || '内部') + '</span></p>' +
    modeNote +
    '<div class="report-stats">' +
      '<div class="report-stat"><div class="val" style="color:var(--red)">' + s.completed + '</div><div class="label">已完成攻击</div></div>' +
      '<div class="report-stat"><div class="val" style="color:var(--green)">' + s.blocked + '</div><div class="label">已拦截攻击</div></div>' +
      '<div class="report-stat"><div class="val" style="color:var(--orange)">' + s.nodes_compromised + '</div><div class="label">被攻陷节点</div></div>' +
      '<div class="report-stat"><div class="val" style="color:var(--accent)">' + (s.bypassed || 0) + '</div><div class="label">防御被绕过</div></div>' +
    '</div>' +
    '<div class="report-section"><h3>攻击步骤详情</h3>' + stepsHtml + '</div>' +
    '<div class="report-section"><h3>业务后果与合规</h3>' + bcHtml + '</div>' +
    '<div class="report-section"><h3>影响传播链</h3>' + chainHtml + '</div>' +
    '<div class="report-section"><h3>ATT&CK 覆盖度</h3>' + covHtml + '</div>' +
    '<div class="report-section"><h3>整改建议单</h3>' + (remedHtml || '<p style="color:var(--text-muted);font-size:12px;">无</p>') + '</div>' +
    '<div class="report-section"><h3>演练评估评分卡</h3>' + scHtml + '</div>' +
    '<div class="report-section"><h3>检测-响应时间线</h3>' + (tlHtml || '<p style="color:var(--text-muted);font-size:12px;">推演后生成</p>') + '</div>' +
    '<div class="report-section"><h3>AAR 复盘</h3>' + (aarHtml || '<p style="color:var(--text-muted);font-size:12px;">无</p>') + '</div>' +
    '<div class="report-section"><h3>节点状态</h3>' + nodesHtml + '</div>' +
    '<div class="disclaimer-box">' + (report.disclaimer || '') + '</div>';

  document.getElementById('reportOverlay').classList.add('show');
}

function renderTimeline() {
  var body = document.getElementById('timelineBody');
  var hint = document.getElementById('tlHint');
  if (!body) return;
  if (!state.timeline || state.timeline.length === 0) {
    body.innerHTML = '<div class="log-entry"><span class="log-msg">推演开始后展示 MTTD/MTTR 检测响应时间线</span></div>';
    return;
  }
  var labels = { attack: '攻击', bypass: '绕过防御', block: '拦截', detect: '检测', respond: '响应' };
  var colors = { attack: 'var(--red)', bypass: 'var(--red)', block: 'var(--green)', detect: 'var(--orange)', respond: 'var(--accent)' };
  var html = '';
  state.timeline.forEach(function(ev) {
    html += '<div class="log-entry ' + (ev.severity || '') + '">';
    html += '<span class="log-time">T+' + ev.t + 'm</span>';
    html += '<span class="log-type ' + ev.type + '" style="color:' + (colors[ev.type] || 'var(--text-secondary)') + '">' + (labels[ev.type] || ev.type) + '</span>';
    html += '<span class="log-msg">' + ev.message + '</span>';
    html += '</div>';
  });
  body.innerHTML = html;
  if (hint) {
    var detectTimes = state.timeline.filter(function(e) { return e.type === 'detect'; });
    if (detectTimes.length) hint.textContent = '最近检测 T+' + detectTimes[detectTimes.length - 1].t + 'min';
  }
}

async function showAttackGraph() {
  var res = await fetch('/api/scenario/' + currentSid + '/attack_graph');
  var g = await res.json();
  var content = document.getElementById('graphContent');
  if (!g || g.total_paths === undefined) {
    content.innerHTML = '<h2>攻击图</h2><p style="color:var(--text-muted);">暂无数据</p>';
    document.getElementById('graphOverlay').classList.add('show');
    return;
  }

  var html = '<h2>攻击图 - 多路径可达分析</h2>';
  html += '<p style="color:var(--text-secondary);font-size:12px;margin-bottom:12px;">外部入口 ' + g.entry_points.length + ' 个 | 关键资产目标 ' + g.target_count + ' 个 | 总攻击路径 ' + g.total_paths + ' 条</p>';

  if (g.bottlenecks && g.bottlenecks.length) {
    html += '<div class="report-section"><h3>必经节点（单点瓶颈）</h3>';
    g.bottlenecks.forEach(function(b) {
      html += '<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border);">';
      html += '<span>' + b.label + ' <span style="color:var(--text-muted);font-size:11px;font-family:var(--font-mono);">' + b.node + ' · ' + b.type + '</span></span>';
      html += '<span style="font-size:11px;color:var(--orange);">' + b.on_paths + ' 条路径经过（' + Math.round(b.ratio * 100) + '%）</span>';
      html += '</div>';
    });
    html += '</div>';
  }

  g.targets.forEach(function(t) {
    html += '<div class="report-section"><h3>' + t.target_label + ' <span style="color:var(--text-muted);font-size:11px;">(' + t.target_type + ' · ' + t.path_count + ' 条路径)</span></h3>';
    if (!t.paths.length) {
      html += '<p style="color:var(--text-muted);font-size:12px;">无可达路径</p>';
    }
    t.paths.slice(0, 6).forEach(function(p, i) {
      var segs = p.nodes.map(function(nid) { return nid; });
      var via = p.via_defenses.length ? ' <span style="color:var(--accent);">[经过防御点: ' + p.via_defenses.join(', ') + ']</span>' : ' <span style="color:var(--red);">[无防御点]</span>';
      html += '<div style="font-size:11px;color:var(--text-secondary);padding:4px 0;border-bottom:1px dashed var(--border);font-family:var(--font-mono);">';
      html += '路径' + (i + 1) + '（' + p.length + '跳）: ' + segs.join(' → ') + via;
      html += '</div>';
    });
    if (t.path_count > 6) html += '<p style="font-size:11px;color:var(--text-muted);">… 仅展示前 6 条，共 ' + t.path_count + ' 条</p>';
    html += '</div>';
  });

  content.innerHTML = html;
  document.getElementById('graphOverlay').classList.add('show');
}

async function showBehaviorSim() {
  var content = document.getElementById('graphContent');
  var modal = document.getElementById('graphOverlay');
  // 复用 graphOverlay 容器展示行为模拟配置面板
  // 2026-09-06 乐叔四点要求：行为模拟 = 推演参数配置（画像+目标导向），
  // 点「确定」保存后影响「启动网络安全攻防推演」结果；不显示蒙特卡洛指标参数；
  // 不配置直接推演 = 默认最低档（低阶攻击者+无偏好）。
  var profiles = [
    { id: 'script_kiddie', name: '低阶攻击者', desc: 'Script Kiddie：现成工具/钓鱼模板，无提权能力，核心库不可达' },
    { id: 'professional', name: '网络犯罪组织', desc: 'RaaS 勒索团伙（LockBit 类）：完整攻击链/横向/提权' },
    { id: 'apt', name: '高级持续性威胁', desc: 'APT（APT41 类）：0day/供应链/隐蔽驻留，高穿透防御' },
    { id: 'insider', name: '内部威胁', desc: 'Insider：内鬼/厂商滥用权限，内网入口、免外部边界突破、熟知防御盲区' }
  ];
  var curP = (state && state.behavior_profile) || 'script_kiddie';
  var curO = (state && state.behavior_objective) || '';
  var html = '<h2>行为模拟 - 推演参数配置</h2>';
  html += '<p style="color:var(--text-secondary);font-size:12px;margin-bottom:12px;">选择的画像与目标导向将影响「启动网络安全攻防推演」的两轮推演结果；不选择直接推演时，一律按最低档（低阶攻击者 + 无偏好）执行。内部威胁画像：初始访问（外部边界突破）步骤自动达成，且推演报告附蒙特卡洛风险快照。</p>';
  html += '<div style="margin-bottom:12px;"><span style="font-size:12px;color:var(--text-secondary);">攻击者画像：</span></div>';
  html += '<div id="simProfiles" style="display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap;">';
  profiles.forEach(function(p) {
    html += '<div class="sim-profile' + (p.id === curP ? ' sel' : '') + '" data-p="' + p.id + '" onclick="selectSimProfile(this)">';
    html += '<div style="font-weight:500;">' + p.name + '</div>';
    html += '<div style="font-size:11px;color:var(--text-secondary);">' + p.desc + '</div>';
    html += '</div>';
  });
  html += '</div>';
  html += '<div id="simIntel" style="margin-bottom:12px;background:rgba(88,166,255,0.06);border:1px solid var(--border);border-radius:6px;padding:8px;">';
  html += '<div style="font-size:11px;color:var(--text-muted);">选择攻击者画像后显示匹配威胁情报</div></div>';
  // 攻击目标导向（窃密/勒索/破坏改变攻击目标集与价值权重）
  html += '<div style="margin-bottom:12px;"><span style="font-size:12px;color:var(--text-secondary);">攻击目标导向：</span>';
  html += '<select id="simObjective" style="background:var(--bg-card);color:var(--text-primary);border:1px solid var(--border);border-radius:6px;padding:4px 8px;margin-left:8px;">';
  html += '<option value=""' + (curO === '' ? ' selected' : '') + '>无偏好（默认高价值资产）</option>';
  html += '<option value="exfil"' + (curO === 'exfil' ? ' selected' : '') + '>数据窃取（人口/病历/核心库）</option>';
  html += '<option value="ransom"' + (curO === 'ransom' ? ' selected' : '') + '>勒索加密（先断备份再锁生产）</option>';
  html += '<option value="destroy"' + (curO === 'destroy' ? ' selected' : '') + '>破坏瘫痪（HIS/EMR 可用性）</option>';
  html += '</select></div>';
  html += '<div style="margin-bottom:12px;display:flex;gap:10px;">';
  html += '<button class="btn btn-primary" onclick="applyBehaviorConfig()">确定</button>';
  html += '</div>';
  content.innerHTML = html;
  modal.classList.add('show');
  // 回显当前画像的威胁情报
  var cur = document.querySelector('.sim-profile.sel');
  if (cur) selectSimProfile(cur);
}

async function applyBehaviorConfig() {
  // 「确定」：保存行为模拟配置，作用于后续推演（不跑蒙特卡洛统计、不显示指标）
  var sel = document.querySelector('.sim-profile.sel');
  var profile = sel ? sel.getAttribute('data-p') : 'script_kiddie';
  var objSel = document.getElementById('simObjective');
  var objective = objSel ? objSel.value : '';
  var res = await fetch('/api/scenario/' + currentSid + '/behavior_config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ profile: profile, objective: objective || null })
  });
  var r = await res.json();
  if (!r.ok) { flashError('配置失败：' + (r.error || '')); return; }
  document.getElementById('graphOverlay').classList.remove('show');
  await fetchState();  // 同步 behavior_profile/objective 到全局 state
  var names = { script_kiddie: '低阶攻击者', professional: '网络犯罪组织', apt: '高级持续性威胁', insider: '内部威胁' };
  var objNames = { '': '无偏好', exfil: '数据窃取', ransom: '勒索加密', destroy: '破坏瘫痪' };
  flashDefense('行为模拟配置已生效：' + (names[profile] || profile) + ' · 目标导向「' + (objNames[objective] || '无偏好') + '」——下次推演按此执行');
}

function selectSimProfile(el) {
  document.querySelectorAll('.sim-profile').forEach(function(x) { x.classList.remove('sel'); });
  el.classList.add('sel');
  // P0-4 情报开场升级：按画像加载匹配威胁情报
  var profile = el.getAttribute('data-p');
  fetch('/api/scenario/' + currentSid + '/briefing', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ profile: profile })
  }).then(function(res) { return res.json(); }).then(function(r) {
    var box = document.getElementById('simIntel');
    if (!box || !r.briefing || !r.briefing.length) return;
    var html = '<div style="font-weight:500;font-size:12px;margin-bottom:4px;">匹配威胁情报（该画像关联态势）</div>';
    r.briefing.forEach(function(b) {
      html += '<div style="font-size:11px;color:var(--text-secondary);padding:2px 0;">• ' +
        b.metric + '：<b>' + b.value + '</b>（' + b.source_report + '）</div>';
    });
    box.innerHTML = html;
  });
}

async function showCalibration() {
  var content = document.getElementById('graphContent');
  var modal = document.getElementById('graphOverlay');
  var cvesRes = await fetch('/api/cves');
  var cvesData = await cvesRes.json();
  var calRes = await fetch('/api/scenario/' + currentSid + '/calibration');
  var cal = await calRes.json();
  var snap = await fetch('/api/scenario/' + currentSid);
  var state = await snap.json();

  var html = '<h2>漏洞校准 - 真实 CVE 绑定</h2>';
  html += '<p style="color:var(--text-secondary);font-size:12px;margin-bottom:12px;">将真实 CVE（NVD 分数）绑定到节点，覆盖默认 CVSS 可利用性。' + (cvesData.source || '') + '</p>';
  html += '<div id="calResult" style="margin-bottom:12px;"></div>';

  // 全部节点均可绑定（2026-09-06 乐叔指示：删除设备类型过滤，
  // 原仅 server/database/workstation 三类可绑）；攻击者节点排在末尾
  var nodes = state.nodes || [];
  var targets = nodes.slice().sort(function(a, b) {
    return (a.type === 'external' ? 1 : 0) - (b.type === 'external' ? 1 : 0);
  });
  html += '<div class="report-section"><h3>绑定节点</h3>';
  html += '<div style="max-height:240px;overflow-y:auto;">';
  targets.forEach(function(n) {
    var cur = cal[n.id];
    html += '<div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid var(--border);">';
    html += '<span style="flex:1;font-size:12px;">' + n.label + ' <span style="color:var(--text-muted);font-size:10px;font-family:var(--font-mono);">' + n.id + '</span></span>';
    html += '<select class="cal-select" data-node="' + n.id + '" style="background:var(--bg-card);color:var(--text-primary);border:1px solid var(--border);border-radius:6px;padding:3px 6px;font-size:11px;">';
    html += '<option value="">未绑定（默认 CVSS）</option>';
    cvesData.cves.forEach(function(cv) {
      var sel = cur && cur.cve_id === cv.id ? ' selected' : '';
      html += '<option value="' + cv.id + '"' + sel + '>' + cv.id + ' ' + cv.name.split('（')[0] + ' (' + cv.cvss + ')</option>';
    });
    html += '</select>';
    html += '</div>';
  });
  html += '</div></div>';
  html += '<button class="btn btn-primary" onclick="applyCalibration()">应用校准</button>';

  content.innerHTML = html;
  modal.classList.add('show');
}

async function applyCalibration() {
  var selects = document.querySelectorAll('.cal-select');
  var mappings = [];
  selects.forEach(function(sel) {
    mappings.push({ node_id: sel.getAttribute('data-node'), cve_id: sel.value || null });
  });
  var res = await fetch('/api/scenario/' + currentSid + '/calibrate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mappings: mappings })
  });
  var r = await res.json();
  var box = document.getElementById('calResult');
  if (r.ok) {
    var n = (r.applied || []).filter(function(a) { return a.cve_id; }).length;
    box.innerHTML = '<p style="color:var(--green);font-size:12px;">已应用 ' + n + ' 条 CVE 校准。返回行为模拟重新运行即可生效。</p>';
  } else {
    box.innerHTML = '<p style="color:var(--red);font-size:12px;">校准失败：' + (r.error || '') + '</p>';
  }
}

// ===== 整改闭环两轮推演（2026-09-02 v2：场景页动画推演，非静态弹窗）=====
// 流程：拓扑图上轮1（无防御）逐步攻陷动画 → 整改方案弹窗（人确认）→
//       拓扑图上轮2（防御全开）逐步拦截动画 → 两轮对比结论弹窗
let remediateRunning = false;
let remediateRound = 1;
let remediateR1Report = null;

function stopRemediateSim() {
  remediateRunning = false;
  hideStageBar();
  var btn = document.getElementById('btnRemediate');
  if (btn) btn.textContent = '启动网络安全攻防推演';
  if (window._planConfirmed) { window._planConfirmed(); window._planConfirmed = null; }
}

function showStageBar(text, dot, step) {
  var bar = document.getElementById('stageBar');
  if (bar) bar.style.display = '';
  var t = document.getElementById('stageText');
  if (t) t.textContent = text;
  // 五步向导高亮（2026-09-06：1现状→2勾选→3落地→4验证→5报告）
  if (step) setStageStep(step);
  // 阶段条占位挤压 main-content，重算 canvas 防拓扑图底部被遮挡（2026-09-06 修复）
  setTimeout(function() { resizeCanvas(); drawTopology(); }, 50);
}

function setStageStep(n) {
  document.querySelectorAll('.stage-step').forEach(function(el) {
    var s = parseInt(el.getAttribute('data-step'), 10);
    el.classList.toggle('done', s < n);
    el.classList.toggle('active', s === n);
  });
}

function hideStageBar() {
  var bar = document.getElementById('stageBar');
  if (bar) bar.style.display = 'none';
  setTimeout(function() { resizeCanvas(); drawTopology(); }, 50);
}

async function showRemediateSim() {
  if (remediateRunning) { stopRemediateSim(); return; }
  if (autoPlaying) { flashError('请先停止「一键推演」再运行整改推演'); return; }
  // 2026-09-20 修复（乐叔报告）：完成两次推演后页面停留在整改后场景
  // （URL 带 orig_scenario/round2）。重置后在此页点「启动网络安全攻防推演」，
  // 轮1 会在整改后拓扑上推演——画布出现整改防护设备（品红三角标）且攻击被
  // 整改设备拦截，「现状推演」失真。整改后场景的启动必须回到轮1 原始场景，
  // 在初始画面上重新开始整个推演。
  var urlParams = new URLSearchParams(window.location.search);
  var origScenario = urlParams.get('orig_scenario');
  var origTopo = urlParams.get('orig_topology');
  if (origScenario) {
    var target = '/scenario/' + encodeURIComponent(origScenario) + '?workflow=1';
    if (origTopo) target += '&topology=' + encodeURIComponent(origTopo);
    location.href = target;
    return;
  }
  remediateRunning = true;
  remediateRound = 1;
  var btn = document.getElementById('btnRemediate');
  if (btn) btn.textContent = '停止攻防推演';
  try {
    // 阶段1：首次推演（现状，拓扑图动画）
    await remediateRound1();
    if (!remediateRunning) return;
    // 阶段2：整改方案（弹窗勾选，应用后跳转整改后拓扑）
    await showPlanModal();
    if (!remediateRunning) return;
    // 后续在整改后拓扑场景（round2=1）继续：第二次推演 → 最终报告
  } finally {
    remediateRunning = false;
    hideStageBar();
    if (btn) btn.textContent = '启动网络安全攻防推演';
  }
}

async function runRoundSteps() {
  // 逐步执行 pending 步骤（带叙事动画），返回 {completed, blocked}
  // P1-5：执行到决策点步骤前暂停，人在环选择后继续
  var completed = [], blocked = [];
  var steps = state.attack_steps.filter(function(s) { return s.state === 'pending'; });
  for (let i = 0; i < steps.length; i++) {
    if (!remediateRunning) break;
    const st = steps[i];
    // 决策点检测：该步前有未解决的决策
    var dp = findPendingDecision(st.id);
    if (dp) {
      var resolved = await showDecisionModal(dp);
      if (!remediateRunning || !resolved) break;  // 链已停或用户取消决策 → 中断本轮（2026-09-06 修 typo remediatedRunning）
      // resolve 后该步可能已被决策阻断（state != pending）
      await fetchState();
      var cur = state.attack_steps.find(function(x) { return x.id === st.id; });
      if (cur && cur.state !== 'pending') {
        if (cur.state === 'blocked') blocked.push(st.id);
        continue;
      }
    }
    currentTarget = (st.effects && st.effects[0]) ? st.effects[0].target : null;
    showStageBar('第 ' + remediateRound + ' 轮推演 · 第 ' + (i + 1) + '/' + steps.length +
      ' 步「' + st.name + '」', remediateRound === 1 ? 'r1' : 'r2');
    const r = await api('/attack', 'POST', { step_id: st.id });
    if (!r.ok && r.error) {
      flashError('步骤跳过: ' + st.name + ' - ' + r.error);
      currentTarget = null;
      continue;
    }
    await playNarrative(r.narrative || [], st.name);
    if (r.blocked) {
      blocked.push(st.id);
      flashDefense('被防御拦截: ' + r.defense);
    } else {
      completed.push(st.id);
      flashAttack('✓ 攻击得手');
    }
    await fetchState();
    currentTarget = null;
    await sleep(700);
  }
  return { completed: completed, blocked: blocked };
}

function findPendingDecision(stepId) {
  // 该步对应的决策点（未解决：该步仍在 pending，且无已应用决策记录）
  if (!state.decision_points || !state.decision_points.length) return null;
  return state.decision_points.find(function(d) {
    return d.step_id === stepId && !d.resolved;
  }) || null;
}

function showDecisionModal(dp) {
  return new Promise(async function(resolve) {
    var content = document.getElementById('graphContent');
    var modal = document.getElementById('graphOverlay');
    var html = '<div style="font-size:15px;font-weight:600;margin-bottom:8px;">推演决策点（人在环）</div>';
    html += '<div style="font-size:13px;margin-bottom:12px;padding:10px;background:rgba(210,153,34,0.12);border-radius:6px;">' + dp.question + '</div>';
    dp.options.forEach(function(o) {
      html += '<div class="decision-opt" style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:8px;cursor:pointer;" ' +
        'onclick="resolveDecisionAndClose(\'' + dp.id + '\', \'' + o.id + '\')">';
      html += '<div style="font-weight:500;margin-bottom:4px;">' + o.label + '</div>';
      html += '<div style="font-size:12px;color:var(--text-secondary);">' + o.description + '</div></div>';
    });
    content.innerHTML = html;
    modal.classList.add('show');
    window._decisionResolve = function(optionId, ok) {
      dp.resolved = true;
      modal.classList.remove('show');
      resolve(ok);
    };
  });
}

async function resolveDecisionAndClose(decisionId, optionId) {
  var res = await fetch('/api/scenario/' + currentSid + '/decision', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ decision_id: decisionId, option_id: optionId })
  });
  var r = await res.json();
  if (r.ok) {
    flashError('决策已应用：' + r.log);
  } else {
    flashError('决策应用失败：' + (r.error || ''));
  }
  if (window._decisionResolve) { window._decisionResolve(optionId, r.ok); window._decisionResolve = null; }
}

async function remediateRound1() {
  remediateRound = 1;
  showStageBar('首次推演（现状 · 现有防护全部启用）准备中…', 'r1', 1);
  await api('/reset', 'POST');
  await api('/defense_all', 'POST', { enable: true });
  await api('/start', 'POST');
  await fetchState();
  flashError('首次推演开始：现状（现有防护全部启用），观察仍有防护仍被突破的薄弱环节');
  await runRoundSteps();
  remediateR1Report = await getReportData();
  // 跨页面传递轮1 报告（整改落地后跳转新场景使用）
  try { sessionStorage.setItem('remediateR1Report', JSON.stringify(remediateR1Report)); } catch (e) {}
}

async function remediateRound2() {
  remediateRound = 2;
  showStageBar('轮2：整改后推演（防御全开）准备中…', 'r2', 4);
  await api('/reset', 'POST');
  await api('/defense_all', 'POST', { enable: true });
  await api('/start', 'POST');
  await fetchState();
  flashError('轮2 开始：整改后推演（防御全开），观察防御拦截');
  await runRoundSteps();
}

async function getReportData() {
  var res = await fetch('/api/scenario/' + currentSid + '/report');
  return await res.json();
}

async function showPlanModal() {
  setStageStep(2);
  var report = remediateR1Report || await getReportData();
  var content = document.getElementById('graphContent');
  var modal = document.getElementById('graphOverlay');
  var html = '<div style="font-size:15px;font-weight:600;margin-bottom:8px;">现状推演结束 · 增量整改方案</div>';
  html += '<div style="font-size:12px;color:var(--text-secondary);margin-bottom:10px;">' +
    '现状推演（现有防护全部启用）：完成攻击步 ' + report.summary.completed + '/' + report.summary.total_steps +
    '，攻陷节点 ' + report.summary.nodes_compromised + ' 个。以下为本轮新增整改措施（针对现状薄弱环节），勾选后落地到拓扑图：</div>';
  report.remediation.forEach(function(p, i) {
    var trapTag = p.trap ? '<span style="font-size:10px;background:rgba(188,140,255,0.15);color:#bc8cff;border-radius:3px;padding:1px 5px;margin-left:6px;">诱捕/监测</span>' : '';
    html += '<label style="display:block;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:8px;margin-bottom:6px;cursor:pointer;">';
    html += '<div style="display:flex;justify-content:space-between;align-items:flex-start;">';
    html += '<span style="font-weight:500;"><input type="checkbox" class="rem-check" data-did="' + p.defense_id + '" checked style="margin-right:8px;vertical-align:middle;">' + p.item + trapTag + '</span>';
    html += '<span style="font-size:11px;color:var(--text-secondary);flex-shrink:0;margin-left:8px;">成本:' + p.cost + ' | ' + p.category + '</span></div>';
    html += '<div style="font-size:11px;color:var(--text-secondary);margin-top:3px;margin-left:24px;">' + p.detail + '</div>';
    if (p.root_cause) html += '<div style="font-size:11px;color:var(--yellow,#d29922);margin-top:2px;margin-left:24px;">针对薄弱环节：' + p.root_cause + '</div>';
    html += '<div style="font-size:11px;color:var(--text-muted);margin-top:2px;margin-left:24px;">责任部门：' + p.dept + '</div></label>';
  });
  html += '<div style="font-size:10px;color:var(--text-muted);margin:6px 0 10px;">' + (report.disclaimer || '') + '</div>';
  html += '<button class="btn btn-primary" onclick="applyRemediationAndGoRound2()">将整改措施体现到拓扑图并进入第二次推演</button>';
  content.innerHTML = html;
  modal.classList.add('show');
  // 等待用户在弹窗确认（点按钮继续 / 点停止或手动关闭则终止）
  await new Promise(function(resolve) {
    window._planConfirmed = resolve;
    var poll = setInterval(function() {
      if (!modal.classList.contains('show')) {
        clearInterval(poll);
        if (window._planConfirmed) {
          // 手动关闭弹窗 = 终止整改推演
          window._planConfirmed = null;
          remediateRunning = false;
        }
        resolve();
      }
    }, 300);
  });
  modal.classList.remove('show');
}

async function applyRemediationAndGoRound2() {
  var modal = document.getElementById('graphOverlay');
  var defenseIds = [];
  document.querySelectorAll('.rem-check:checked').forEach(function(c) {
    defenseIds.push(c.getAttribute('data-did'));
  });
  if (!defenseIds.length) {
    flashError('请至少勾选一项整改措施');
    return;
  }
  // 步骤4：整改建议体现到拓扑图 → 生成并导入整改后拓扑
  var content = document.getElementById('graphContent');
  content.innerHTML = '<p style="color:var(--text-secondary);">正在将 ' + defenseIds.length + ' 项整改措施落地到拓扑图并导入…</p>';
  var res = await fetch('/api/scenario/' + currentSid + '/apply_remediation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ defense_ids: defenseIds })
  });
  var r = await res.json();
  if (!r.ok) {
    content.innerHTML = '<p style="color:var(--red);">整改落地失败：' + (r.error || '') + '</p>';
    return;
  }
  modal.classList.remove('show');
  if (window._planConfirmed) { window._planConfirmed(); window._planConfirmed = null; }
  // 跳转到整改后拓扑场景，执行第二次推演。
  // topology = 整改后拓扑（轮2 动画用）；orig_topology/orig_scenario = 轮1 原始对象
  // （结论与最终报告必须以原始对象为基准，2026-09-06 修复「第一轮未被攻破」bug）；
  // remediations = 勾选措施集合（结论口径与勾选一致）
  var origTopo = '';
  if (currentSid.indexOf('topo_') === 0) origTopo = currentSid.slice(5);
  location.href = '/scenario/' + r.scenario_id + '?round2=1&topology=' +
    encodeURIComponent(r.topology_id || '') +
    '&orig_topology=' + encodeURIComponent(origTopo) +
    '&orig_scenario=' + encodeURIComponent(currentSid) +
    '&remediations=' + encodeURIComponent(defenseIds.join(','));
}

async function showConclusionModal() {
  // 2026-09-06 口径：结论以六步工作流权威计算为准（轮1 现状防护全开
  // → 整改新增措施 → 轮2 对比 + 拦截来源 + 概率突破率）
  setStageStep(5);
  var content = document.getElementById('graphContent');
  var modal = document.getElementById('graphOverlay');
  content.innerHTML = '<p style="color:var(--text-secondary);">正在生成整改闭环两轮对比结论…</p>';
  modal.classList.add('show');
  var res = await fetch('/api/workflow/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payloadWorkflow())
  });
  var r = await res.json();
  if (!r.ok) {
    content.innerHTML = '<p style="color:var(--red);">结论生成失败：' + (r.error || '') + '</p>';
    return;
  }
  var s = r.steps;
  var r1 = s['2_sim_round1'];
  var r2 = s['5_sim_round2'];
  var plan = s['3_remediation'].plan || [];
  var prob = s.prob_comparison || {};
  var names = r.step_names || {};
  var topoNames = r.topo_step_names || {};
  function nm(id) { return names[id] || topoNames[id] || id; }
  var weak = r1.weak_steps || [];
  var nb = r2.newly_blocked_steps || [];
  var residual = r2.residual_risks || [];

  var html = '<div style="font-size:15px;font-weight:600;margin-bottom:10px;">整改闭环两轮推演 · 结论</div>';
  html += '<div style="font-size:11px;color:var(--text-secondary);margin-bottom:10px;">' +
    '口径：轮1 现状（现有防护全部启用）→ ' + plan.length + ' 项新增整改措施 → 轮2 整改后验证</div>';
  html += '<div style="display:flex;gap:10px;margin-bottom:12px;">';
  html += roundCard('首次推演 · 现状（防护全开）',
    { completed_steps: r1.completed_steps || [], blocked_steps: r1.blocked_steps || [],
      compromised_nodes: r1.compromised_nodes || [] }, 'rgba(248,81,73,0.12)');
  html += roundCard('第二次推演 · 整改后',
    { completed_steps: r2.completed_steps || [], blocked_steps: r2.blocked_steps || [],
      compromised_nodes: r2.compromised_nodes || [] }, 'rgba(63,185,80,0.12)');
  html += '</div>';
  // 整改效果
  html += '<div style="background:rgba(88,166,255,0.1);border:1px solid rgba(88,166,255,0.35);border-radius:8px;padding:12px;margin-bottom:12px;">';
  html += '<div style="font-weight:600;margin-bottom:6px;">整改效果</div>';
  html += '<div style="font-size:12px;line-height:1.9;">';
  html += '攻陷节点：<b style="color:var(--red);">' + (r1.compromised_nodes || []).length +
    '</b> → <b style="color:var(--green);">' + (r2.compromised_nodes || []).length + '</b> 个<br>';
  html += '整改新增拦截：<b>' + nb.length + '</b> 步';
  if (nb.length) { html += '（' + nb.map(nm).join('、') + '）'; }
  html += '<br>';
  if (prob.samples) {
    html += '概率模式整体突破率：<b style="color:var(--red);">' + Math.round(prob.round1_rate * 100) +
      '%</b> → <b style="color:var(--green);">' + Math.round(prob.round2_rate * 100) +
      '%</b>（降 ' + Math.round(prob.reduction * 100) + '%，' + prob.samples + ' 轮采样）';
  }
  html += '</div></div>';
  // 薄弱环节
  if (weak.length) {
    html += '<div style="font-weight:600;margin-bottom:6px;color:var(--yellow,#d29922);">现状薄弱环节（有防护仍被突破）</div>';
    weak.forEach(function(w) { html += '<div style="font-size:12px;padding:2px 0;">• ' + nm(w.step) + '</div>'; });
  }
  // 拦截来源
  var tvc = (r2.topo_validation || {}).defense_contribution || [];
  if (tvc.length) {
    html += '<div style="font-weight:600;margin:10px 0 6px;">拦截来源（现状防护 vs 整改新增）</div>';
    tvc.forEach(function(d) {
      var src = d.source === 'remediation' ? '【整改新增】' : '【现状防护】';
      var srcColor = d.source === 'remediation' ? '#ff7bce' : 'var(--text-secondary)';
      html += '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:8px;margin-bottom:6px;">';
      html += '<div style="display:flex;justify-content:space-between;"><span style="font-weight:500;">' +
        '<span style="color:' + srcColor + ';">' + src + '</span> ' + d.defense + '</span>';
      html += '<span style="font-size:11px;color:var(--text-secondary);">成本:' + d.cost + '</span></div>';
      if (d.blocked_steps && d.blocked_steps.length) {
        html += '<div style="font-size:11px;color:var(--green);margin-top:4px;">拦截步骤: ' + d.blocked_steps.map(nm).join(', ') + '</div>';
      } else {
        html += '<div style="font-size:11px;color:var(--text-secondary);margin-top:4px;">本轮未触发拦截（纵深防御前置断链，属正常）</div>';
      }
      html += '</div>';
    });
  }
  // 残余风险
  if (residual.length) {
    html += '<div style="font-weight:600;margin:10px 0 6px;color:var(--yellow,#d29922);">残余风险（整改后仍可达）</div>';
    residual.forEach(function(x) { html += '<div style="font-size:12px;padding:2px 0;">• ' + nm(x.step) + '</div>'; });
  } else {
    html += '<div style="font-weight:600;margin:10px 0 6px;color:var(--green);">残余风险：无（整改后无可达攻击环节）</div>';
  }
  // 演练评估评分卡（2026-09-23 丈八「人才培养 PDCA」思想，主流程展示）
  var sc = r2.scorecard;
  if (sc && sc.dimensions && sc.dimensions.length) {
    html += '<div style="background:rgba(63,185,80,0.08);border:1px solid rgba(63,185,80,0.35);border-radius:8px;padding:12px;margin:12px 0;">';
    html += '<div style="display:flex;align-items:center;gap:14px;margin-bottom:8px;">';
    html += '<span style="font-weight:600;">演练评估评分卡</span>';
    html += '<span style="font-size:24px;font-weight:700;color:var(--accent);">' + sc.total + '<span style="font-size:11px;color:var(--text-muted);font-weight:400;"> 分</span></span>';
    html += '<span style="font-size:14px;font-weight:600;">' + sc.grade + '</span></div>';
    sc.dimensions.forEach(function(d) {
      var pct = Math.round(d.score * 100 / d.max);
      html += '<div style="margin-bottom:5px;">' +
        '<div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-secondary);">' +
        '<span>' + d.name + '</span><span>' + d.score + '/' + d.max + '</span></div>' +
        '<div style="height:6px;background:var(--bg-hover);border-radius:3px;margin-top:2px;">' +
        '<div style="width:' + pct + '%;height:6px;background:var(--accent);border-radius:3px;"></div></div>' +
        '<div style="font-size:10px;color:var(--text-muted);margin-top:2px;">' + d.detail + '</div></div>';
    });
    html += '<div style="font-size:10px;color:var(--text-muted);margin-top:4px;">' + (sc.disclaimer || '') + '</div></div>';
  }
  // 防御策略调优体检（2026-09-23 丈八「策略验证」思想，主流程展示）
  var tuning = r1.tuning_suggestions || [];
  if (tuning.length) {
    html += '<div style="font-weight:600;margin:10px 0 6px;color:var(--orange,#e8a13c);">防御策略调优体检（现有防御参数核查）</div>';
    tuning.forEach(function(t) {
      var sev = t.severity === '高' ? 'var(--red)' : 'var(--orange,#e8a13c)';
      html += '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:8px;margin-bottom:6px;">';
      html += '<div style="font-size:12px;"><b style="color:' + sev + ';">[' + t.severity + ']</b> ' + t.defense +
        '<span style="color:var(--text-secondary);"> — ' + t.fact + '</span></div>';
      html += '<div style="font-size:11px;color:var(--text-secondary);margin-top:4px;">核查建议：' + t.advice + '</div></div>';
    });
  }
  html += '<div style="margin-top:12px;"><button class="btn btn-primary" onclick="finalizeWorkflowReport()">生成最终推演报告（落盘）</button>';
  html += '<button class="btn" onclick="showComparePlans()" style="margin-left:8px;">多方案对比</button>';
  html += '<span id="wfFinalizeNote" style="margin-left:10px;font-size:12px;"></span></div>';
  html += '<div id="wfReportView" style="margin-top:10px;"></div>';
  content.innerHTML = html;
}

async function showComparePlans() {
  // P0-2 多方案对比推演（丈八「方案自动生成」思想）
  var content = document.getElementById('graphContent');
  content.innerHTML = '<p style="color:var(--text-secondary);">正在运行多方案对比推演（基线 / 方案A低成本快赢 / 方案B全量整改）…</p>';
  var res = await fetch('/api/scenario/' + currentSid + '/compare_plans', { method: 'POST' });
  var r = await res.json();
  if (!r.ok) {
    content.innerHTML = '<p style="color:var(--red);">对比失败：' + (r.error || '') + '</p>';
    return;
  }
  var c = r.comparison.compromised;
  var b = r.comparison.blocked_steps;
  var html = '<div style="font-size:15px;font-weight:600;margin-bottom:10px;">多方案对比推演 · ' + r.scenario + '</div>';
  html += '<div style="font-size:11px;color:var(--text-secondary);margin-bottom:8px;">' + (r.baseline_note || '') + '</div>';
  html += '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:14px;">';
  html += '<tr style="border-bottom:1px solid var(--border);"><th style="text-align:left;padding:6px;">方案</th>' +
    '<th>攻陷节点</th><th>拦截攻击步</th><th>残余风险步骤</th></tr>';
  html += planRow('基线（现状·防护全开）', c.baseline, b.baseline, r.baseline.residual_risks.length, 'rgba(248,81,73,0.08)');
  html += planRow(r.plan_a.name + '（' + r.plan_a.count + ' 项）', c.plan_a, b.plan_a, r.plan_a.result.residual_risks.length, 'rgba(210,153,34,0.08)');
  html += planRow(r.plan_b.name + '（' + r.plan_b.count + ' 项）', c.plan_b, b.plan_b, r.plan_b.result.residual_risks.length, 'rgba(63,185,80,0.08)');
  html += '</table>';
  html += '<div style="font-weight:600;margin-bottom:6px;">方案 A 措施清单（现状+低成本快赢整改）</div>';
  r.plan_a.defenses.forEach(function(d) {
    html += '<div style="font-size:12px;padding:3px 0;">• ' + d.name + ' <span style="color:var(--text-secondary);">[' + d.cost + ']</span></div>';
  });
  html += '<div style="font-size:10px;color:var(--text-muted);margin-top:10px;">' + (r.disclaimer || '') + '</div>';
  content.innerHTML = html;
}

function planRow(name, compromised, blocked, residual, bg) {
  return '<tr style="background:' + bg + ';border-bottom:1px solid var(--border);">' +
    '<td style="padding:6px;font-weight:500;">' + name + '</td>' +
    '<td style="text-align:center;padding:6px;">' + compromised + '</td>' +
    '<td style="text-align:center;padding:6px;">' + blocked + '</td>' +
    '<td style="text-align:center;padding:6px;">' + residual + '</td></tr>';
}

function roundCard(title, round, bg) {
  var itemsHtml = '';
  if (round.compromised_nodes && round.compromised_nodes.length) {
    itemsHtml = '<div style="font-size:11px;color:var(--text-secondary);margin-top:4px;">攻陷：' +
      round.compromised_nodes.join(', ') + '</div>';
  } else {
    itemsHtml = '<div style="font-size:11px;color:var(--green);margin-top:4px;">无节点被攻陷</div>';
  }
  return '<div style="flex:1;background:' + bg + ';border-radius:8px;padding:12px;">' +
    '<div style="font-weight:600;font-size:13px;margin-bottom:6px;">' + title + '</div>' +
    '<div style="font-size:11px;color:var(--text-secondary);margin-bottom:6px;">完成 ' +
    round.completed_steps.length + ' 步 · 拦截 ' + round.blocked_steps.length + ' 步</div>' +
    '<div style="font-size:22px;font-weight:700;margin-bottom:6px;">' + round.compromised_nodes.length +
    '<span style="font-size:11px;font-weight:400;color:var(--text-secondary);"> 攻陷节点</span></div>' +
    itemsHtml + '</div>';
}

// ===== 侧栏/底部 tab 切换 + 整改措施/资产清单/ATT&CK 面板（2026-09-06）=====

function switchSideTab(name) {
  document.querySelectorAll('.side-tabs .side-tab').forEach(function(t) {
    t.classList.toggle('active', t.getAttribute('data-tab') === name);
  });
  ['attacks', 'defenses', 'remediations', 'assets'].forEach(function(p) {
    var el = document.getElementById('panel-' + p);
    if (el) el.classList.toggle('active', p === name);
  });
}

function switchBottomTab(name) {
  document.querySelectorAll('.bottom-tabs .side-tab').forEach(function(t) {
    t.classList.toggle('active', t.getAttribute('data-btab') === name);
  });
  ['events', 'timeline', 'attck'].forEach(function(p) {
    var el = document.getElementById('bpanel-' + p);
    if (el) el.classList.toggle('active', p === name);
  });
  if (name === 'attck') loadAttckPanel();
}

function renderRemediations() {
  var list = document.getElementById('remediationList');
  if (!list) return;
  var rems = state.candidate_remediations || [];
  var cnt = document.getElementById('remediationCount');
  if (cnt) cnt.textContent = rems.length;
  if (!rems.length) {
    list.innerHTML = '<div class="log-entry"><span class="log-msg">本场景暂无增量整改候选措施（拓扑导入场景按无防护资产自动生成）</span></div>';
    return;
  }
  var html = '<div style="font-size:11px;color:var(--text-muted);padding:4px 6px;">增量整改候选措施（仅整改推演轮2 生效，不参与现状推演）</div>';
  rems.forEach(function(r) {
    var trapTag = r.trap ? ' <span style="color:#bc8cff;font-size:10px;">诱捕</span>' : '';
    html += '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:8px;margin:4px 6px;">';
    html += '<div style="font-weight:500;font-size:12px;">' + r.name + trapTag +
      ' <span style="color:var(--text-muted);font-size:11px;float:right;">' + r.cost + '</span></div>';
    html += '<div style="font-size:11px;color:var(--text-secondary);margin-top:2px;">' + r.desc + '</div>';
    if (r.root_cause) html += '<div style="font-size:10px;color:var(--orange);margin-top:2px;">针对：' + r.root_cause + '</div>';
    html += '</div>';
  });
  list.innerHTML = html;
}

function renderAssets() {
  var list = document.getElementById('assetList');
  if (!list) return;
  // 2026-09-14：未启动时不列出轮2 整改新增设备（rem_ 前缀），
  // 资产清单与画布一致——重置后回到原始拓扑资产。
  var nodes = (state.nodes || []).filter(function(n) {
    return state.started || (!String(n.id).startsWith('rem_') && !n.remediation);
  });
  var html = '<div style="font-size:11px;color:var(--text-muted);padding:4px 6px;">资产清单（' + nodes.length + ' 节点，色标见拓扑图例）</div>';
  nodes.forEach(function(n) {
    var color = NODE_COLORS[n.type] || '#8b949e';
    var bare = n.security_level === 'none' && n.type !== 'external';
    html += '<div style="display:flex;align-items:center;gap:8px;padding:5px 8px;border-bottom:1px solid var(--border);">';
    html += '<span style="width:10px;height:10px;border-radius:50%;background:' + color +
      (bare ? ';box-shadow:0 0 0 2px #f85149' : '') + ';flex-shrink:0;"></span>';
    html += '<span style="font-size:12px;flex:1;">' + n.label + (bare ? ' <span style="color:#f85149;font-size:10px;">无防护</span>' : '') + '</span>';
    html += '<span style="font-size:10px;color:var(--text-muted);">' + n.type + '</span></div>';
  });
  list.innerHTML = html;
}

async function loadAttckPanel() {
  var body = document.getElementById('attckBody');
  if (!body) return;
  body.innerHTML = '<div class="log-entry"><span class="log-msg">正在加载 ATT&amp;CK 覆盖度…</span></div>';
  var res = await fetch('/api/scenario/' + currentSid + '/attck_coverage');
  var d = await res.json();
  if (!d || !d.matrix) {
    body.innerHTML = '<div class="log-entry"><span class="log-msg">覆盖度数据不可用</span></div>';
    return;
  }
  var html = '<div style="font-size:11px;color:var(--text-muted);padding:6px;">场景技术 ' + d.total_techniques +
    ' 项 / 覆盖战术 ' + d.covered_tactics + '/' + d.tactic_order_total + '</div>';
  d.matrix.forEach(function(m) {
    var pct = Math.min(100, m.technique_count * 10);
    html += '<div style="padding:4px 8px;border-bottom:1px solid var(--border);">';
    html += '<div style="display:flex;justify-content:space-between;font-size:12px;"><span>' + m.tactic + '</span>' +
      '<span style="color:var(--text-muted);font-size:11px;">' + m.step_count + ' 步</span></div>';
    html += '<div style="height:5px;background:var(--bg-hover);border-radius:3px;margin-top:3px;">' +
      '<div style="width:' + pct + '%;height:5px;background:var(--accent);border-radius:3px;"></div></div>';
    html += '</div>';
  });
  body.innerHTML = html;
}
