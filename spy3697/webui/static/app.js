const ledger = document.getElementById('ledger');
const runBtn = document.getElementById('run-btn');
const targetInput = document.getElementById('target');
const goalInput = document.getElementById('goal');
const confirmBox = document.getElementById('confirm');
const cfgSub = document.getElementById('cfg-sub');
const stages = document.querySelectorAll('.stage');

fetch('/api/config-summary').then(r => r.json()).then(cfg => {
  cfgSub.textContent = `llm: ${cfg.llm_provider}/${cfg.llm_model} · authorized targets: ${cfg.authorized_targets.length}`;
}).catch(() => { cfgSub.textContent = 'config unavailable'; });

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
