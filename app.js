/* Sentinel — AI Web Vulnerability Scanner
   Developer: Anoop Dubey */

const $ = (id) => document.getElementById(id);

/* ---------------- Matrix background ---------------- */
(function matrixRain(){
  const canvas = $('matrixCanvas');
  const ctx = canvas.getContext('2d');
  function resize(){canvas.width=window.innerWidth;canvas.height=window.innerHeight;}
  resize();window.addEventListener('resize',resize);
  const chars='01アイウエオカキクケコ{}<>/;$#'.split('');
  const fontSize=14;
  let columns=Math.floor(canvas.width/fontSize);
  let drops=new Array(columns).fill(1);
  function draw(){
    ctx.fillStyle='rgba(6,11,20,0.08)';
    ctx.fillRect(0,0,canvas.width,canvas.height);
    ctx.fillStyle='#2FE6D9';
    ctx.font=fontSize+'px monospace';
    for(let i=0;i<drops.length;i++){
      const text=chars[Math.floor(Math.random()*chars.length)];
      ctx.fillText(text, i*fontSize, drops[i]*fontSize);
      if(drops[i]*fontSize>canvas.height && Math.random()>0.975) drops[i]=0;
      drops[i]++;
    }
  }
  setInterval(draw,60);
})();

/* ---------------- Auth ---------------- */
const loginForm = $('loginForm');
const pwInput = $('pw');
const pwWrap = $('pwWrap');
const loginBtn = $('loginBtn');
const loginSpinner = $('loginSpinner');
const loginBtnText = $('loginBtnText');
const loginError = $('loginError');
const toggleEye = $('toggleEye');

toggleEye.addEventListener('click', () => {
  const isPw = pwInput.type === 'password';
  pwInput.type = isPw ? 'text' : 'password';
  toggleEye.textContent = isPw ? '\u{1F648}' : '\u{1F441}';
});

function showDashboard(withTransition){
  $('loginScreen').classList.add('fade-out');
  setTimeout(()=>{
    $('loginScreen').hidden = true;
    $('loginScreen').classList.remove('fade-out');
    $('dashboard').hidden = false;
    if(withTransition){
      $('dashboard').classList.add('fade-in-scale');
      setTimeout(()=>$('dashboard').classList.remove('fade-in-scale'), 550);
    }
    history.pushState({auth:true}, '', '#dashboard');
  }, withTransition ? 350 : 0);
}

function showLogin(){
  $('dashboard').hidden = true;
  $('loginScreen').hidden = false;
  $('loginScreen').classList.remove('fade-out');
  history.pushState({auth:false}, '', '#login');
}

// Prevent back-nav bypass
window.addEventListener('popstate', () => {
  if(!sessionStorage.getItem('sentinel_token')) showLogin();
});

// Boot: check existing session
(function boot(){
  if(sessionStorage.getItem('sentinel_token')){
    $('loginScreen').hidden = true;
    $('dashboard').hidden = false;
  } else {
    showLogin();
  }
})();

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  loginBtn.disabled = true;
  loginBtnText.textContent = 'Verifying…';
  loginSpinner.hidden = false;
  loginError.hidden = true;
  try{
    const res = await fetch('/api/auth', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ password: pwInput.value })
    });
    const data = await res.json();
    if(res.ok && data.token){
      sessionStorage.setItem('sentinel_token', data.token);
      pwWrap.classList.add('success-flash');
      loginBtnText.textContent = 'Access granted';
      setTimeout(()=> showDashboard(true), 500);
    } else {
      throw new Error('bad password');
    }
  }catch(err){
    pwWrap.classList.add('shake');
    loginError.hidden = false;
    pwInput.value = '';
    setTimeout(()=>pwWrap.classList.remove('shake'), 450);
  }finally{
    loginBtn.disabled = false;
    loginBtnText.textContent = 'Unlock Sentinel';
    loginSpinner.hidden = true;
  }
});

$('logoutBtn').addEventListener('click', () => {
  sessionStorage.removeItem('sentinel_token');
  showLogin();
});

/* ---------------- Theme ---------------- */
$('themeToggle').addEventListener('click', () => {
  const html = document.documentElement;
  const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('sentinel_theme', next);
});
(function initTheme(){
  const saved = localStorage.getItem('sentinel_theme');
  if(saved) document.documentElement.setAttribute('data-theme', saved);
})();

/* ---------------- Toast ---------------- */
function toast(msg){
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(t._timer);
  t._timer = setTimeout(()=> t.hidden = true, 2600);
}

/* ---------------- Scan flow ---------------- */
const scanForm = $('scanForm');
const progressSection = $('progressSection');
const progressText = $('progressText');
const resultsSection = $('resultsSection');
let lastReport = null;

const progressSteps = [
  'Resolving DNS & IP intelligence…',
  'Establishing TLS connection…',
  'Reading security headers…',
  'Checking robots.txt, sitemap.xml, security.txt…',
  'Analyzing cookies & CORS policy…',
  'Detecting technology & CDN fingerprints…',
  'Computing risk score…',
  'Generating AI security report…'
];

scanForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = $('targetUrl').value.trim();
  if(!url) return;

  resultsSection.hidden = true;
  progressSection.hidden = false;
  let step = 0;
  progressText.textContent = progressSteps[0];
  const stepTimer = setInterval(()=>{
    step = Math.min(step+1, progressSteps.length-1);
    progressText.textContent = progressSteps[step];
  }, 700);

  const token = sessionStorage.getItem('sentinel_token');
  try{
    const scanRes = await fetch('/api/scan', {
      method:'POST',
      headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
      body: JSON.stringify({ url })
    });
    if(scanRes.status === 401){
      clearInterval(stepTimer);
      progressSection.hidden = true;
      toast('Session expired — please log in again.');
      showLogin();
      return;
    }
    const scanData = await scanRes.json();
    if(!scanRes.ok || scanData.error) throw new Error(scanData.error || 'Scan failed');

    progressText.textContent = 'Generating AI security report…';
    const reportRes = await fetch('/api/report', {
      method:'POST',
      headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
      body: JSON.stringify({ scan: scanData })
    });
    const reportData = await reportRes.json();

    const fullReport = { ...scanData, ai: reportData };
    lastReport = fullReport;
    renderReport(fullReport);
    saveToHistory(fullReport);

    clearInterval(stepTimer);
    progressSection.hidden = true;
    resultsSection.hidden = false;
  }catch(err){
    clearInterval(stepTimer);
    progressSection.hidden = true;
    toast('Error: ' + err.message);
  }
});

function statusDot(ok){
  if(ok === true) return 'pass';
  if(ok === 'warn') return 'warn';
  return 'fail';
}

function renderReport(r){
  $('scoreNumber').textContent = '0';
  animateScore(r.riskScore || 0);
  $('radarGauge').style.background =
    `conic-gradient(${scoreColor(r.riskScore)} ${(r.riskScore||0)*3.6}deg, var(--panel-border) 0deg)`;
  $('gradeBadge').textContent = r.grade || '—';
  $('gradeBadge').style.color = scoreColor(r.riskScore);

  $('execSummary').textContent = r.ai?.executiveSummary || 'No summary available.';
  $('techSummary').textContent = r.ai?.technicalSummary || '—';
  $('bizImpact').textContent = r.ai?.businessImpact || '—';

  const chipWrap = $('severityChips');
  chipWrap.innerHTML = '';
  (r.severityCounts ? Object.entries(r.severityCounts) : []).forEach(([sev,count])=>{
    if(!count) return;
    const chip = document.createElement('span');
    chip.className = 'chip ' + sev.toLowerCase();
    chip.textContent = `${sev}: ${count}`;
    chipWrap.appendChild(chip);
  });

  const hc = $('headerCards'); hc.innerHTML = '';
  (r.headerChecks || []).forEach(h=>{
    const div = document.createElement('div');
    div.className = 'header-card';
    div.innerHTML = `<span>${h.name}</span><span class="status-dot ${statusDot(h.pass)}"></span>`;
    hc.appendChild(div);
  });

  const intel = $('intelList'); intel.innerHTML = '';
  Object.entries(r.intel || {}).forEach(([k,v])=>{
    const div = document.createElement('div');
    div.innerHTML = `<span>${k}</span><span>${v ?? '—'}</span>`;
    intel.appendChild(div);
  });

  const owasp = $('owaspList'); owasp.innerHTML = '';
  (r.ai?.owaspMapping || []).forEach(o=>{
    const div = document.createElement('div');
    div.className = 'owasp-item';
    div.innerHTML = `<span class="owasp-title">${o.category}</span><span class="owasp-desc">${o.finding}</span>`;
    owasp.appendChild(div);
  });
  if(!owasp.children.length) owasp.innerHTML = '<p style="color:var(--muted);font-size:12px;">No mapped findings — configuration looks solid.</p>';

  const fixList = $('fixList'); fixList.innerHTML = '';
  (r.ai?.priorityFixes || []).forEach(f=>{
    const li = document.createElement('li');
    li.innerHTML = `${f.action}<span class="fix-meta">Difficulty: ${f.difficulty} · ETA: ${f.eta}</span>`;
    fixList.appendChild(li);
  });
  if(!fixList.children.length) fixList.innerHTML = '<li style="color:var(--muted);">No priority fixes — nice work.</li>';

  const tl = $('timeline'); tl.innerHTML = '';
  (r.ai?.riskTimeline || []).forEach(t=>{
    const div = document.createElement('div');
    div.className = 'timeline-item';
    div.innerHTML = `<div class="timeline-dot"></div><div class="timeline-content"><div class="t-label">${t.when}</div><div class="t-text">${t.event}</div></div>`;
    tl.appendChild(div);
  });
}

function scoreColor(score){
  if(score >= 85) return 'var(--success)';
  if(score >= 60) return 'var(--cyan)';
  if(score >= 40) return 'var(--warning)';
  return 'var(--danger)';
}

function animateScore(target){
  let cur = 0;
  const el = $('scoreNumber');
  const step = Math.max(1, Math.round(target/30));
  const t = setInterval(()=>{
    cur += step;
    if(cur >= target){ cur = target; clearInterval(t); }
    el.textContent = cur;
  }, 20);
}

/* ---------------- History (localStorage, last 10) ---------------- */
function saveToHistory(report){
  const list = JSON.parse(localStorage.getItem('sentinel_history') || '[]');
  list.unshift({ url: report.target, date: new Date().toISOString(), score: report.riskScore, grade: report.grade, report });
  localStorage.setItem('sentinel_history', JSON.stringify(list.slice(0,10)));
}

$('historyBtn').addEventListener('click', () => {
  const drawer = $('historyDrawer');
  drawer.hidden = !drawer.hidden;
  renderHistory();
});
$('closeHistory').addEventListener('click', () => $('historyDrawer').hidden = true);

function renderHistory(){
  const list = JSON.parse(localStorage.getItem('sentinel_history') || '[]');
  const wrap = $('historyList');
  wrap.innerHTML = list.length ? '' : '<p style="color:var(--muted);font-size:12px;">No scans yet.</p>';
  list.forEach((item)=>{
    const div = document.createElement('div');
    div.className = 'history-item';
    div.innerHTML = `<strong>${item.url}</strong><br/>Score: ${item.score} · ${item.grade}<br/><span style="color:var(--muted)">${new Date(item.date).toLocaleString()}</span>`;
    div.addEventListener('click', ()=>{
      lastReport = item.report;
      renderReport(item.report);
      resultsSection.hidden = false;
      $('historyDrawer').hidden = true;
    });
    wrap.appendChild(div);
  });
}

/* ---------------- Compare ---------------- */
$('compareBtn').addEventListener('click', () => {
  const list = JSON.parse(localStorage.getItem('sentinel_history') || '[]');
  if(list.length < 2){ toast('Need at least 2 scans to compare.'); return; }
  const a = list[0].report, b = list[1].report;
  $('compareBody').innerHTML = `
    <div><h4>${a.target}</h4><p>Score: ${a.riskScore} (${a.grade})</p></div>
    <div><h4>${b.target}</h4><p>Score: ${b.riskScore} (${b.grade})</p></div>
  `;
  $('compareModal').hidden = false;
});
$('closeCompare').addEventListener('click', () => $('compareModal').hidden = true);

/* ---------------- Export / Share ---------------- */
$('exportJson').addEventListener('click', () => {
  if(!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'sentinel-report.json';
  a.click();
});

$('exportPdf').addEventListener('click', () => {
  if(!lastReport) return;
  const win = window.open('', '_blank');
  win.document.write(`
    <html><head><title>Sentinel Report — ${lastReport.target}</title></head>
    <body style="font-family:sans-serif;padding:30px;">
      <h1>Sentinel Security Report</h1>
      <p><strong>Target:</strong> ${lastReport.target}</p>
      <p><strong>Score:</strong> ${lastReport.riskScore} — <strong>Grade:</strong> ${lastReport.grade}</p>
      <h2>Executive Summary</h2><p>${lastReport.ai?.executiveSummary || ''}</p>
      <h2>Technical Summary</h2><p>${lastReport.ai?.technicalSummary || ''}</p>
      <h2>Business Impact</h2><p>${lastReport.ai?.businessImpact || ''}</p>
      <p style="margin-top:40px;color:#888;font-size:11px;">Generated by Sentinel — Developer: Anoop Dubey</p>
    </body></html>
  `);
  win.document.close();
  win.print();
});

$('copyReport').addEventListener('click', () => {
  if(!lastReport) return;
  navigator.clipboard.writeText(JSON.stringify(lastReport, null, 2));
  toast('Report copied to clipboard.');
});

$('shareReport').addEventListener('click', async () => {
  if(!lastReport) return;
  const text = `Sentinel scan for ${lastReport.target}: ${lastReport.riskScore}/100 (${lastReport.grade})`;
  if(navigator.share){
    try{ await navigator.share({ title:'Sentinel Report', text }); }catch(e){}
  } else {
    navigator.clipboard.writeText(text);
    toast('Summary copied — sharing not supported on this browser.');
  }
});

/* ---------------- Keyboard shortcuts ---------------- */
document.addEventListener('keydown', (e) => {
  if(e.key === '/' && document.activeElement !== $('targetUrl')){
    e.preventDefault(); $('targetUrl').focus();
  }
  if(e.key === 'Escape'){
    $('historyDrawer').hidden = true;
    $('compareModal').hidden = true;
  }
});
