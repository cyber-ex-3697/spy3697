const ledger = document.getElementById('ledger');
const runBtn = document.getElementById('run-btn');
const targetInput = document.getElementById('target');
const goalInput = document.getElementById('goal');
const confirmBox = document.getElementById('confirm');
const cfgSub = document.getElementById('cfg-sub');
const stages = document.querySelectorAll('.stage');
const radarNodes = document.getElementById('radar-nodes');
const coverageGrid = document.getElementById('coverage-grid');

const COVERAGE = [
  { name: 'SQL Injection', status: 'covered' },
  { name: 'XSS', status: 'covered' },
  { name: 'CSRF / SSRF / XXE', status: 'covered' },
  { name: 'Security Misconfig', status: 'covered' },
  { name: 'Command Injection / Path Traversal', status: 'covered' },
  { name: 'Known-CVE / Log4Shell (nuclei)', status: 'covered' },
  { name: 'Insecure Deserialization', status: 'covered' },
  { name: 'Supply Chain (trivy)', status: 'covered' },
  { name: 'Broken Access Control / IDOR', status: 'assist' },
  { name: 'Missing Authorization', status: 'assist' },
  { name: 'AI Prompt Injection', status: 'assist' },
  { name: 'API BOLA / Data Exposure', status: 'assist' },
  { name: 'Privilege Escalation (post-shell)', status: 'assist' },
  { name: 'Insecure Design', status: 'manual' },
  { name: 'Auth Bypass (n-day)', status: 'assist' },
  { name: 'Memory Safety (BOF/UAF)', status: 'manual' },
  { name: 'Named Zero-Days', status: 'manual' },
  { name: 'Model Poisoning', status: 'manual' },
];

function renderCoverage() {
  coverageGrid.innerHTML = '';
  for (const item of COVERAGE) {
    const div = document.createElement('div');
    div.className = `coverage-item ${item.status}`;
    const label = item.status === 'covered' ? 'auto' : (item.status === 'assist' ? 'assist' : 'manual');
    div.innerHTML = `<span class="dot"></span><span class="coverage-item-name">${item.name}</span><span>${label}</span>`;
    coverageGrid.appendChild(div);
  }
}
renderCoverage();

fetch('/api/config-summary').then(r => r.json()).then(cfg => {
  cfgSub.textContent = `llm: ${cfg.llm_provider}/${cfg.llm_model} · authorized targets: ${cfg.authorized_targets.length}`;
}).catch(() => { cfgSub.textContent = 'config unavailable'; });

let nodeCount = 0;
function addRadarNode(kind) {
  // kind: 'candidate' | 'verified' | 'rejected' -- placed at a pseudo-random
  // angle/radius so repeated findings visually spread across the sweep.
  nodeCount += 1;
  const angle = (nodeCount * 47) % 360;
  const radius = 40 + ((nodeCount * 23) % 100);
  const rad = (angle * Math.PI) / 180;
  const x = 150 + radius * Math.cos(rad);
  const y = 150 + radius * Math.sin(rad);
  const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  circle.setAttribute('cx', x);
  circle.setAttribute('cy', y);
  circle.setAttribute('r', kind === 'verified' ? 6 : 4);
  circle.setAttribute('class', `radar-node ${kind}`);
  radarNodes.appendChild(circle);
}

function upgradeLastCandidateToVerified() {
  const nodes = radarNodes.querySelectorAll('.radar-node.candidate');
  if (nodes.length) {
    const last = nodes[nodes.length - 1];
    last.classList.remove('candidate');
    last.classList.add('verified');
    last.setAttribute('r', 6);
  }
}

function appendLine(text) {
  let cls = '';
  if (text.startsWith('[recon]')) cls = 'line-recon';
  else if (text.startsWith('[identify]')) cls = 'line-identify';
  else if (text.startsWith('[verify]')) cls = 'line-verify';
  else if (text.startsWith('[report]')) cls = 'line-report';
  else if (text.includes('error') || text.includes('Error') || text.includes('REJECTED')) cls = 'line-error';

  const span = document.createElement('span');
  if (cls) span.className = cls;
  span.textContent = text + '\n';
  ledger.appendChild(span);
  ledger.scrollTop = ledger.scrollHeight;

  if (text.startsWith('[recon]')) setStage('recon');
  if (text.startsWith('[identify]')) setStage('identify');
  if (text.startsWith('[verify]')) setStage('verify');
  if (text.startsWith('[report]')) setStage('report');

  if (text.includes('candidate #')) addRadarNode('candidate');
  if (text.includes('VERIFIED')) upgradeLastCandidateToVerified();
  if (text.includes('NOT verified') || text.includes('REJECTED')) addRadarNode('rejected');
}

function setStage(name) {
  let reached = false;
  stages.forEach(s => {
    if (s.dataset.stage === name) { s.classList.add('active'); s.classList.remove('done'); reached = true; }
    else if (!reached) { s.classList.remove('active'); s.classList.add('done'); }
    else { s.classList.remove('active', 'done'); }
  });
}

runBtn.addEventListener('click', () => {
  const target = targetInput.value.trim();
  const goal = goalInput.value.trim();
  if (!target) { appendLine('[error] enter a target first'); return; }
  if (!confirmBox.checked) { appendLine('[error] check the authorization confirmation box first'); return; }

  ledger.textContent = '';
  radarNodes.innerHTML = '';
  nodeCount = 0;
  runBtn.disabled = true;
  runBtn.querySelector('.run-btn-label').textContent = 'RUNNING…';
  stages.forEach(s => s.classList.remove('active', 'done'));

  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/run`);

  ws.onopen = () => {
    ws.send(JSON.stringify({
      target, goal, i_confirm_authorization: confirmBox.checked,
    }));
  };
  ws.onmessage = (ev) => {
    if (ev.data === '[[DONE]]') {
      appendLine('[+] pipeline finished — see workspace/ for report.md and poc/ scripts');
      runBtn.disabled = false;
      runBtn.querySelector('.run-btn-label').textContent = 'RUN FULL PIPELINE';
      stages.forEach(s => { s.classList.remove('active'); s.classList.add('done'); });
      ws.close();
      return;
    }
    appendLine(ev.data);
  };
  ws.onerror = () => appendLine('[error] websocket connection error');
});
