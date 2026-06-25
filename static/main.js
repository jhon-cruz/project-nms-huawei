const state = {
  user: null,
  devices: [],
  deviceTypes: [],
  commandActions: [],
  brasActions: { queries: [], admin_actions: [] },
  users: [],
  audits: [],
  system: null,
  interfaces: [],
  activeDeviceId: null,
  selectedInterface: null,
  page: 'dashboard',
  snmpTimer: null,
  brasAuthTimer: null,
  snmpLoading: false,
};

const $ = (id) => document.getElementById(id);
const isAdmin = () => state.user?.role === 'admin';

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function toast(message) {
  const el = $('toast');
  el.textContent = message;
  el.classList.add('show');
  window.setTimeout(() => el.classList.remove('show'), 3200);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text();
    if (response.status === 401) showAuth(false);
    throw new Error(text || `Erro HTTP ${response.status}`);
  }
  return response.status === 204 ? null : response.json();
}

function parseErrorMessage(error) {
  try {
    const data = JSON.parse(error.message);
    if (typeof data.detail === 'string') return data.detail;
    if (data.detail && typeof data.detail === 'object') {
      const diagnostics = (data.detail.diagnostics || [])
        .map((item) => `${item.oid}: ${item.ok ? 'OK' : 'falhou'} (${item.count || 0})${item.error ? ' - ' + item.error : ''}`)
        .join('\n');
      return [
        data.detail.message,
        data.detail.error_type ? `Tipo: ${data.detail.error_type}` : '',
        data.detail.host ? `Destino: ${data.detail.host}:${data.detail.port || 22}` : '',
        data.detail.username ? `Usuario: ${data.detail.username}` : '',
        data.detail.hint ? `Dica: ${data.detail.hint}` : '',
        diagnostics,
      ].filter(Boolean).join('\n');
    }
    return error.message;
  } catch {
    return error.message;
  }
}

function showAuth(setupRequired = false) {
  $('app-shell').classList.add('hidden');
  $('auth-screen').classList.remove('hidden');
  $('auth-title').textContent = setupRequired ? 'Criar administrador' : 'Entrar no sistema';
  $('auth-mode').textContent = setupRequired ? 'Primeiro acesso' : 'Acesso seguro';
  $('auth-submit').textContent = setupRequired ? 'Criar e entrar' : 'Entrar';
}

function showApp() {
  $('auth-screen').classList.add('hidden');
  $('app-shell').classList.remove('hidden');
}

async function submitAuth(event) {
  event?.preventDefault();
  const payload = { username: $('auth-username').value.trim(), password: $('auth-password').value };
  const status = await api('/api/auth/status');
  const path = status.setup_required ? '/api/auth/setup' : '/api/auth/login';
  $('auth-submit').disabled = true;
  $('auth-submit').textContent = 'Entrando...';
  try {
    const result = await api(path, { method: 'POST', body: JSON.stringify(payload) });
    state.user = result.user;
    $('auth-form').reset();
    showApp();
    await bootstrapApp();
  } catch (error) {
    $('auth-feedback').textContent = parseErrorMessage(error);
  } finally {
    $('auth-submit').disabled = false;
    $('auth-submit').textContent = 'Entrar';
  }
}
window.nmsSubmitAuth = submitAuth;

function applyPermissions() {
  $('session-label').textContent = state.user ? `${state.user.username}` : 'Control Center';
  $('role-label').textContent = isAdmin() ? 'Admin' : 'Leitura';
  document.querySelectorAll('.admin-only,[data-admin-only="true"]').forEach((el) => {
    el.classList.toggle('hidden', !isAdmin());
  });
  if (!isAdmin() && ['audit', 'security', 'register', 'system'].includes(state.page)) navigate('dashboard');
}

function navigate(page) {
  if (!isAdmin() && ['audit', 'security', 'register', 'system'].includes(page)) {
    toast('Seu usuario possui permissao somente leitura.');
    page = 'dashboard';
  }
  state.page = page;
  document.querySelectorAll('.page').forEach((el) => el.classList.toggle('active', el.id === `page-${page}`));
  document.querySelectorAll('#main-nav a').forEach((a) => a.classList.toggle('active', a.dataset.page === page));
  const titles = {
    dashboard: ['NMS externo via SSH + SNMP', 'Visao geral'],
    devices: ['Inventario e monitoramento', 'Equipamentos'],
    register: ['Cadastro e credenciais', 'Cadastro'],
    audit: ['Rastreabilidade', 'Auditoria'],
    security: ['Controle de acesso', 'Seguranca'],
    system: ['Instalacao e atualizacao', 'Sistema'],
  };
  $('page-eyebrow').textContent = titles[page][0];
  $('page-title').textContent = titles[page][1];
  if (page === 'system') loadSystemStatus();
}

async function loadReferenceData() {
  [state.deviceTypes, state.commandActions] = await Promise.all([
    api('/api/device-types'),
    api('/api/command-actions'),
  ]);
  state.brasActions = await api('/api/bras/actions');
  $('device-type').innerHTML = state.deviceTypes.map((t) => `<option value="${t.value}">${escapeHtml(t.label)}</option>`).join('');
  $('command-action').innerHTML = state.commandActions.map((a) => `<option value="${a.value}">${escapeHtml(a.label)}</option>`).join('');
  $('bras-query-action').innerHTML = state.brasActions.queries.map((a) => `<option value="${a.value}">${escapeHtml(a.label)}</option>`).join('');
  $('bras-admin-action').innerHTML = state.brasActions.admin_actions.map((a) => `<option value="${a.value}">${escapeHtml(a.label)}</option>`).join('');
}

async function loadDevices() {
  state.devices = await api('/api/devices');
  if (!state.activeDeviceId && state.devices.length) state.activeDeviceId = state.devices[0].id;
  renderDashboard();
  renderDeviceSelectors();
  renderDeviceList();
}

function renderDashboard() {
  $('metric-devices').textContent = state.devices.length;
  const up = state.interfaces.filter((it) => it.oper === 'up').length;
  const down = state.interfaces.filter((it) => it.oper === 'down').length;
  $('metric-online').textContent = up > 0 ? 1 : 0;
  $('metric-ports-up').textContent = up;
  $('metric-ports-down').textContent = down;
  $('dashboard-device-list').innerHTML = state.devices.length ? state.devices.map((d) => `
    <article class="device-item">
      <div><h4>${escapeHtml(d.name)}</h4><p>${escapeHtml(d.host)} ${d.description ? '- ' + escapeHtml(d.description) : ''}</p></div>
      <div class="device-tags"><span class="tag">${escapeHtml(d.model || '-')}</span><span class="tag">${escapeHtml(d.device_type)}</span></div>
    </article>`).join('') : '<div class="summary-box">Nenhum equipamento cadastrado.</div>';
}

function renderDeviceSelectors() {
  const options = state.devices.map((d) => `<option value="${d.id}">${escapeHtml(d.name)} - ${escapeHtml(d.host)}</option>`).join('');
  ['active-device', 'command-device', 'audit-device'].forEach((id) => {
    const el = $(id);
    if (!el) return;
    const first = id === 'audit-device' ? '<option value="">Todos</option>' : '';
    el.innerHTML = first + options;
    if (state.activeDeviceId && id !== 'audit-device') el.value = String(state.activeDeviceId);
  });
}

function renderDeviceList() {
  const list = $('device-list');
  if (!list) return;
  list.innerHTML = state.devices.map((d) => `
    <article class="device-item">
      <div>
        <h4>${escapeHtml(d.name)}</h4>
        <p>${escapeHtml(d.host)} ${d.description ? '- ' + escapeHtml(d.description) : ''}</p>
        <div class="device-tags"><span class="tag">${escapeHtml(d.model || '-')}</span><span class="tag">SSH ${d.ssh_port}</span><span class="tag">SNMP ${d.snmp_port}</span></div>
      </div>
      <div class="device-actions admin-only">
        <button class="icon-btn test-btn" data-ssh-test="${d.id}" title="Testar SSH">SSH</button>
        <button class="icon-btn test-btn" data-snmp-test="${d.id}" title="Testar SNMP">SNMP</button>
        <button class="icon-btn" data-edit="${d.id}" title="Editar">E</button>
        <button class="icon-btn danger" data-delete="${d.id}" title="Remover">X</button>
      </div>
    </article>`).join('');
  list.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => editDevice(Number(b.dataset.edit))));
  list.querySelectorAll('[data-delete]').forEach((b) => b.addEventListener('click', () => deleteDevice(Number(b.dataset.delete))));
  list.querySelectorAll('[data-ssh-test]').forEach((b) => b.addEventListener('click', () => testDeviceConnection(Number(b.dataset.sshTest), 'ssh')));
  list.querySelectorAll('[data-snmp-test]').forEach((b) => b.addEventListener('click', () => testDeviceConnection(Number(b.dataset.snmpTest), 'snmp')));
  applyPermissions();
}

function isPhysicalInterface(item) {
  const name = String(item?.name || '');
  const type = String(item?.type || '');
  const physicalName = /^(Ethernet|GigabitEthernet|XGigabitEthernet|10GE|25GE|40GE|50GE|100GE|GE|Eth)/i.test(name);
  const virtualName = /^(LoopBack|Loopback|NULL|Vlanif|Eth-Trunk|Virtual|Tunnel|NULL)/i.test(name);
  return name && !name.includes('.') && !virtualName && (physicalName || type === 'ethernetCsmacd');
}

function shortInterfaceName(name) {
  return String(name || '')
    .replace('GigabitEthernet', 'GE')
    .replace('XGigabitEthernet', 'XGE')
    .replace('Ethernet', 'Eth');
}

function renderFaceplate() {
  const physical = state.interfaces.filter(isPhysicalInterface);
  $('faceplate-title').textContent = selectedDevice()?.name || 'Equipamento';
  $('faceplate-subtitle').textContent = state.interfaces.length ? `${physical.length} portas fisicas | ${state.interfaces.length} interfaces SNMP` : 'Aguardando leitura SNMP';
  const shown = physical.length ? physical : state.interfaces;
  $('port-grid').innerHTML = shown.length ? shown.map((it) => {
    const cls = it.oper === 'up' ? 'up' : it.oper === 'down' ? 'down' : 'warn';
    const selected = state.selectedInterface === it.name ? ' selected' : '';
    return `<button class="port ${cls}${selected}" data-interface="${escapeHtml(it.name)}" title="${escapeHtml(it.name)} | ${escapeHtml(it.description || '-')}">${escapeHtml(shortInterfaceName(it.name))}</button>`;
  }).join('') : Array.from({ length: 24 }, (_, i) => `<button class="port">${i + 1}</button>`).join('');
  $('port-grid').querySelectorAll('[data-interface]').forEach((b) => b.addEventListener('click', () => selectInterface(b.dataset.interface)));
}

function renderInterfacesTable() {
  $('interfaces-table').innerHTML = state.interfaces.length ? `
    <table><thead><tr><th>Interface</th><th>Tipo</th><th>Admin</th><th>Oper</th><th>Speed</th><th>Descricao</th></tr></thead><tbody>
    ${state.interfaces.map((it) => `<tr data-interface-row="${escapeHtml(it.name)}"><td>${escapeHtml(it.name)}</td><td>${escapeHtml(it.type || '-')}</td><td><span class="state ${it.admin === 'up' ? 'up' : 'down'}">${escapeHtml(it.admin)}</span></td><td><span class="state ${it.oper === 'up' ? 'up' : 'down'}">${escapeHtml(it.oper)}</span></td><td>${escapeHtml(it.speed || '-')}</td><td>${escapeHtml(it.description || '')}</td></tr>`).join('')}
    </tbody></table>` : 'Nenhuma interface coletada.';
  $('interfaces-table').querySelectorAll('[data-interface-row]').forEach((r) => r.addEventListener('click', () => selectInterface(r.dataset.interfaceRow)));
}

function selectedDevice() {
  return state.devices.find((d) => d.id === Number(state.activeDeviceId));
}

async function loadInterfaces() {
  if (!state.activeDeviceId) return;
  if (state.snmpLoading) return;
  state.snmpLoading = true;
  try {
    const data = await api(`/api/devices/${state.activeDeviceId}/interfaces`);
    state.interfaces = data.interfaces || [];
    if (!state.interfaces.length && data.message) toast(data.message);
    renderFaceplate();
    renderInterfacesTable();
    renderDashboard();
  } catch (error) {
    state.interfaces = [];
    renderFaceplate();
    renderInterfacesTable();
    toast(`Falha SNMP: ${parseErrorMessage(error)}`);
  } finally {
    state.snmpLoading = false;
  }
}

async function selectInterface(name) {
  state.selectedInterface = name;
  $('command-interface').value = name;
  $('command-device').value = String(state.activeDeviceId);
  $('selected-interface-title').textContent = name;
  renderFaceplate();
  navigate('devices');
  await loadInterfaceConfig(name);
}

async function loadInterfaceConfig(name) {
  $('interface-config-output').textContent = `Buscando display current interface ${name}...`;
  try {
    const data = await api(`/api/devices/${state.activeDeviceId}/interface-config`, { method: 'POST', body: JSON.stringify({ interface: name }) });
    $('interface-config-output').textContent = `$ ${data.command}\n${data.output || ''}`;
  } catch (error) {
    $('interface-config-output').textContent = `Falha: ${parseErrorMessage(error)}`;
  }
}

function formPayload() {
  return {
    name: $('device-name').value.trim(),
    host: $('device-host').value.trim(),
    description: $('device-description').value.trim(),
    device_type: $('device-type').value,
    ssh_username: $('ssh-username').value.trim(),
    ssh_password: $('ssh-password').value,
    ssh_port: Number($('ssh-port').value || 22),
    snmp_community: $('snmp-community').value,
    snmp_port: Number($('snmp-port').value || 161),
    model: $('device-model').value.trim(),
    vrp_version: $('device-vrp').value.trim(),
    notes: $('device-notes').value.trim(),
  };
}

async function saveDevice(event) {
  event.preventDefault();
  const id = $('device-id').value;
  const method = id ? 'PUT' : 'POST';
  const path = id ? `/api/devices/${id}` : '/api/devices';
  try {
    await api(path, { method, body: JSON.stringify(formPayload()) });
    resetDeviceForm();
    await loadDevices();
    toast('Equipamento salvo.');
  } catch (error) {
    toast(`Falha ao salvar: ${parseErrorMessage(error)}`);
  }
}

function editDevice(id) {
  const d = state.devices.find((item) => item.id === id);
  if (!d) return;
  $('device-id').value = d.id;
  $('device-name').value = d.name || '';
  $('device-host').value = d.host || '';
  $('device-description').value = d.description || '';
  $('device-type').value = d.device_type || 'other';
  $('ssh-username').value = d.ssh_username || '';
  $('ssh-password').value = '';
  $('ssh-port').value = d.ssh_port || 22;
  $('snmp-community').value = '';
  $('snmp-port').value = d.snmp_port || 161;
  $('device-model').value = d.model || '';
  $('device-vrp').value = d.vrp_version || '';
  $('device-notes').value = d.notes || '';
  $('save-device').textContent = 'Atualizar';
}

function resetDeviceForm() {
  $('device-form').reset();
  $('device-id').value = '';
  $('save-device').textContent = 'Salvar';
}

async function deleteDevice(id) {
  if (!confirm('Remover equipamento?')) return;
  await api(`/api/devices/${id}`, { method: 'DELETE' });
  await loadDevices();
}

async function testDeviceConnection(id, type) {
  const device = state.devices.find((item) => item.id === id);
  const output = document.querySelector('.page.active #connection-test-output') || $('device-test-output');
  const label = type.toUpperCase();
  output.textContent = `Testando ${label} em ${device?.name || id}...`;
  try {
    const result = await api(`/api/devices/${id}/${type}-test`, { method: 'POST' });
    if (type === 'ssh') {
      const summary = result.summary || {};
      output.textContent = [
        `SSH OK - ${device?.name || id}`,
        summary.hostname ? `Hostname: ${summary.hostname}` : '',
        summary.version ? `VRP: ${summary.version}` : '',
        '',
        result.output || 'Conexao SSH validada.',
      ].filter(Boolean).join('\n');
    } else {
      const diagnostics = (result.diagnostics || [])
        .map((item) => `${item.oid}: ${item.ok ? 'OK' : 'falhou'} (${item.count || 0})${item.error ? ' - ' + item.error : ''}`)
        .join('\n');
      output.textContent = [
        `SNMP OK - ${device?.name || id}`,
        `Interfaces coletadas: ${result.count}`,
        result.message || '',
        '',
        diagnostics,
        '',
        JSON.stringify(result.interfaces || [], null, 2),
      ].filter((line) => line !== '').join('\n');
    }
    toast(`${label} OK.`);
  } catch (error) {
    output.textContent = `${label} falhou - ${device?.name || id}\n${parseErrorMessage(error)}`;
    toast(`${label} falhou.`);
  }
}

function testActiveDevice(type) {
  const id = Number($('active-device')?.value || state.activeDeviceId);
  if (!id) {
    toast('Selecione um equipamento.');
    return;
  }
  state.activeDeviceId = id;
  testDeviceConnection(id, type);
}

async function generateCommandPreview(event) {
  event.preventDefault();
  const deviceId = $('command-device').value;
  const payload = { interface: $('command-interface').value.trim(), action: $('command-action').value, description: $('command-description').value.trim() };
  try {
    const preview = await api(`/api/devices/${deviceId}/command-preview`, { method: 'POST', body: JSON.stringify(payload) });
    $('command-preview').textContent = [preview.destructive ? 'Acao altera configuracao.' : 'Acao somente leitura.', '', ...preview.commands].join('\n');
    await loadAudit();
  } catch (error) {
    toast(`Falha no preview: ${parseErrorMessage(error)}`);
  }
}

async function executeCommand() {
  if (!confirm('Aplicar configuracao no equipamento?')) return;
  const deviceId = $('command-device').value;
  const payload = { interface: $('command-interface').value.trim(), action: $('command-action').value, description: $('command-description').value.trim(), confirm: true };
  $('command-output').textContent = 'Executando...';
  try {
    const result = await api(`/api/devices/${deviceId}/command-execute`, { method: 'POST', body: JSON.stringify(payload) });
    $('command-output').textContent = result.outputs.map((o) => `$ ${o.command}\n${o.output || ''}`).join('\n\n');
    await loadInterfaces();
    await loadAudit();
  } catch (error) {
    $('command-output').textContent = `Falha: ${parseErrorMessage(error)}`;
  }
}

function snmpIntervalMs() {
  const value = Math.max(1, Number($('snmp-interval-value').value || 60));
  return $('snmp-interval-unit').value === 'minutes' ? value * 60 * 1000 : value * 1000;
}

function stopSnmpAuto() {
  if (state.snmpTimer) {
    window.clearInterval(state.snmpTimer);
    state.snmpTimer = null;
  }
  $('toggle-snmp-auto').textContent = 'Iniciar';
}

function formatOutputs(outputs) {
  return (outputs || []).map((o) => `$ ${o.command}\n${o.output || ''}`).join('\n\n');
}

function renderAuthFailures(items) {
  const box = $('bras-auth-summary');
  if (!items?.length) {
    box.innerHTML = '<div class="summary-box">Nenhuma falha simplificada encontrada na ultima leitura.</div>';
    return;
  }
  box.innerHTML = items.map((item) => `
    <article class="auth-log-item">
      <strong>${escapeHtml(item.reason)}</strong>
      <div class="device-tags">
        ${item.username ? `<span class="tag">Login ${escapeHtml(item.username)}</span>` : ''}
        ${item.ip ? `<span class="tag">IP ${escapeHtml(item.ip)}</span>` : ''}
        ${item.mac ? `<span class="tag">MAC ${escapeHtml(item.mac)}</span>` : ''}
      </div>
      <details><summary>Ver trecho original</summary><code>${escapeHtml(item.raw)}</code></details>
    </article>`).join('');
}

async function runBrasQuery(event, forcedAction = null) {
  event?.preventDefault();
  if (!state.activeDeviceId) return toast('Selecione um equipamento.');
  const payload = {
    action: forcedAction || $('bras-query-action').value,
    value: forcedAction ? '' : $('bras-query-value').value.trim(),
  };
  $('bras-output').textContent = 'Consultando equipamento...';
  try {
    const result = await api(`/api/devices/${state.activeDeviceId}/bras/query`, { method: 'POST', body: JSON.stringify(payload) });
    $('bras-output').textContent = formatOutputs(result.outputs);
    if (payload.action === 'aaa_fail_record') renderAuthFailures(result.simplified || []);
    await loadAudit();
  } catch (error) {
    $('bras-output').textContent = `Falha: ${parseErrorMessage(error)}`;
  }
}

async function previewBrasAction(event) {
  event.preventDefault();
  if (!state.activeDeviceId) return toast('Selecione um equipamento.');
  const payload = { action: $('bras-admin-action').value, value: $('bras-admin-value').value.trim() };
  try {
    const preview = await api(`/api/devices/${state.activeDeviceId}/bras/action-preview`, { method: 'POST', body: JSON.stringify(payload) });
    $('bras-preview').textContent = ['Acao sensivel. Revise antes de aplicar.', '', ...preview.commands].join('\n');
    await loadAudit();
  } catch (error) {
    $('bras-preview').textContent = `Falha no preview: ${parseErrorMessage(error)}`;
  }
}

async function executeBrasAction() {
  if (!state.activeDeviceId) return toast('Selecione um equipamento.');
  if (!confirm('Executar acao BRAS/BNG no equipamento?')) return;
  const payload = { action: $('bras-admin-action').value, value: $('bras-admin-value').value.trim(), confirm: true };
  $('bras-preview').textContent = 'Executando acao protegida...';
  try {
    const result = await api(`/api/devices/${state.activeDeviceId}/bras/action-execute`, { method: 'POST', body: JSON.stringify(payload) });
    $('bras-preview').textContent = formatOutputs(result.outputs);
    await loadAudit();
  } catch (error) {
    $('bras-preview').textContent = `Falha: ${parseErrorMessage(error)}`;
  }
}

function stopBrasAuthAuto() {
  if (state.brasAuthTimer) {
    window.clearInterval(state.brasAuthTimer);
    state.brasAuthTimer = null;
  }
  $('bras-auth-auto').textContent = 'Tempo real';
}

function toggleBrasAuthAuto() {
  if (state.brasAuthTimer) {
    stopBrasAuthAuto();
    toast('Logs de falhas em tempo real parados.');
    return;
  }
  runBrasQuery(null, 'aaa_fail_record');
  state.brasAuthTimer = window.setInterval(() => runBrasQuery(null, 'aaa_fail_record'), 10000);
  $('bras-auth-auto').textContent = 'Parar logs';
  toast('Logs de falhas atualizando a cada 10 segundos.');
}

function toggleSnmpAuto() {
  if (state.snmpTimer) {
    stopSnmpAuto();
    toast('Atualizacao automatica SNMP parada.');
    return;
  }
  loadInterfaces();
  state.snmpTimer = window.setInterval(loadInterfaces, snmpIntervalMs());
  $('toggle-snmp-auto').textContent = 'Parar';
  toast('Atualizacao automatica SNMP iniciada.');
}

async function loadAudit() {
  if (!isAdmin()) return;
  const params = new URLSearchParams();
  if ($('audit-device')?.value) params.set('device_id', $('audit-device').value);
  if ($('audit-date-from')?.value) params.set('date_from', $('audit-date-from').value);
  if ($('audit-date-to')?.value) params.set('date_to', $('audit-date-to').value);
  state.audits = await api(`/api/command-audit?${params.toString()}`);
  $('audit-list').innerHTML = state.audits.length ? state.audits.map((a) => `
    <article class="audit-item">
      <header><strong>${escapeHtml(a.device_name)} - ${escapeHtml(a.interface)}</strong><span>${escapeHtml(a.created_at)}</span></header>
      <div class="device-tags"><span class="tag">${escapeHtml(a.action)}</span><span class="tag">${escapeHtml(a.username)}</span><span class="tag">${escapeHtml(a.source_ip || '-')}</span><span class="tag">${a.executed ? 'executado' : 'preview'}</span></div>
      <code>${escapeHtml(a.commands_preview)}</code>
    </article>`).join('') : '<div class="summary-box">Nenhum registro encontrado.</div>';
}

async function loadUsers() {
  if (!isAdmin()) return;
  state.users = await api('/api/users');
  $('user-list').innerHTML = state.users.map((u) => `
    <article class="device-item">
      <div><h4>${escapeHtml(u.username)}</h4><p>${escapeHtml(u.role)}</p></div>
      <div class="device-actions"><button class="icon-btn" data-user-edit="${u.id}">E</button><button class="icon-btn danger" data-user-delete="${u.id}">X</button></div>
    </article>`).join('');
  $('user-list').querySelectorAll('[data-user-edit]').forEach((b) => b.addEventListener('click', () => editUser(Number(b.dataset.userEdit))));
  $('user-list').querySelectorAll('[data-user-delete]').forEach((b) => b.addEventListener('click', () => deleteUser(Number(b.dataset.userDelete))));
}

function renderSystemStatus() {
  const data = state.system;
  $('system-status').innerHTML = data ? `
    <div class="device-list">
      <article class="device-item"><div><h4>Servico</h4><p>${escapeHtml(data.service)} - ${escapeHtml(data.service_active)}</p></div></article>
      <article class="device-item"><div><h4>Repositorio</h4><p>${escapeHtml(data.branch)} @ ${escapeHtml(data.commit)}</p></div></article>
      <article class="device-item"><div><h4>Diretorio</h4><p>${escapeHtml(data.project_root)}</p></div></article>
    </div>` : 'Status ainda nao carregado.';
}

async function loadSystemStatus() {
  if (!isAdmin()) return;
  try {
    state.system = await api('/api/system/status');
    renderSystemStatus();
  } catch (error) {
    $('system-status').textContent = `Falha ao carregar status: ${parseErrorMessage(error)}`;
  }
}

async function runSystemUpdate() {
  if (!confirm('Atualizar o sistema a partir do GitHub e reiniciar o servico?')) return;
  $('run-system-update').disabled = true;
  $('system-update-output').textContent = 'Atualizando a partir do repositorio...';
  try {
    const result = await api('/api/system/update', { method: 'POST' });
    $('system-update-output').textContent = [
      result.ok ? 'Atualizacao concluida.' : 'Atualizacao falhou.',
      `Versao: ${result.branch || '-'} @ ${result.commit || '-'}`,
      '',
      ...(result.steps || []).map((step) => [
        `$ ${step.command}`,
        step.stdout || '',
        step.stderr || '',
        `exit ${step.returncode}`,
      ].filter(Boolean).join('\n')),
    ].join('\n\n');
    await loadSystemStatus();
  } catch (error) {
    $('system-update-output').textContent = `Falha: ${parseErrorMessage(error)}`;
  } finally {
    $('run-system-update').disabled = false;
  }
}

async function saveUser(event) {
  event.preventDefault();
  const id = $('user-id').value;
  const payload = { username: $('user-username').value.trim(), password: $('user-password').value, role: $('user-role').value };
  const path = id ? `/api/users/${id}` : '/api/users';
  const method = id ? 'PUT' : 'POST';
  if (id) delete payload.username;
  try {
    await api(path, { method, body: JSON.stringify(payload) });
    $('user-form').reset(); $('user-id').value = ''; $('save-user').textContent = 'Salvar usuario';
    await loadUsers();
  } catch (error) {
    toast(`Falha usuario: ${parseErrorMessage(error)}`);
  }
}

function editUser(id) {
  const u = state.users.find((item) => item.id === id);
  if (!u) return;
  $('user-id').value = u.id;
  $('user-username').value = u.username;
  $('user-username').disabled = true;
  $('user-password').value = '';
  $('user-role').value = u.role;
  $('save-user').textContent = 'Atualizar usuario';
}

async function deleteUser(id) {
  if (!confirm('Remover usuario?')) return;
  await api(`/api/users/${id}`, { method: 'DELETE' });
  await loadUsers();
}

async function logout() {
  await api('/api/auth/logout', { method: 'POST' });
  state.user = null;
  showAuth(false);
}

async function bootstrapApp() {
  applyPermissions();
  await loadReferenceData();
  await loadDevices();
  if (state.activeDeviceId) await loadInterfaces();
  if (isAdmin()) {
    await loadAudit();
    await loadUsers();
    await loadSystemStatus();
  }
  navigate(location.hash?.replace('#', '') || 'dashboard');
}

async function bootstrap() {
  document.querySelectorAll('#main-nav a').forEach((a) => a.addEventListener('click', (event) => {
    event.preventDefault();
    navigate(a.dataset.page);
  }));
  $('auth-form').addEventListener('submit', submitAuth);
  $('logout').addEventListener('click', logout);
  $('device-form').addEventListener('submit', saveDevice);
  $('reset-form').addEventListener('click', resetDeviceForm);
  $('active-device').addEventListener('change', async () => { state.activeDeviceId = Number($('active-device').value); await loadInterfaces(); });
  $('refresh-interfaces').addEventListener('click', loadInterfaces);
  $('test-active-ssh').addEventListener('click', () => testActiveDevice('ssh'));
  $('test-active-snmp').addEventListener('click', () => testActiveDevice('snmp'));
  $('toggle-snmp-auto').addEventListener('click', toggleSnmpAuto);
  $('snmp-interval-value').addEventListener('change', stopSnmpAuto);
  $('snmp-interval-unit').addEventListener('change', stopSnmpAuto);
  $('command-form').addEventListener('submit', generateCommandPreview);
  $('execute-command').addEventListener('click', executeCommand);
  $('bras-query-form').addEventListener('submit', runBrasQuery);
  $('bras-action-form').addEventListener('submit', previewBrasAction);
  $('bras-action-execute').addEventListener('click', executeBrasAction);
  $('bras-auth-refresh').addEventListener('click', () => runBrasQuery(null, 'aaa_fail_record'));
  $('bras-auth-auto').addEventListener('click', toggleBrasAuthAuto);
  ['audit-device', 'audit-date-from', 'audit-date-to'].forEach((id) => $(id).addEventListener('change', loadAudit));
  $('refresh-audit').addEventListener('click', loadAudit);
  $('refresh-system').addEventListener('click', loadSystemStatus);
  $('run-system-update').addEventListener('click', runSystemUpdate);
  $('user-form').addEventListener('submit', saveUser);
  $('reset-user-form').addEventListener('click', () => { $('user-form').reset(); $('user-id').value = ''; $('user-username').disabled = false; $('save-user').textContent = 'Salvar usuario'; });

  const status = await api('/api/auth/status');
  if (!status.authenticated) {
    showAuth(status.setup_required);
    return;
  }
  state.user = status.user;
  showApp();
  await bootstrapApp();
}

bootstrap().catch((error) => toast(`Falha ao iniciar: ${parseErrorMessage(error)}`));
