'use strict';
// Claude Forensics — single page UI. All evidence content is untrusted: it is
// only ever inserted with textContent (never innerHTML).

const $ = (sel, root = document) => root.querySelector(sel);
const main = () => $('#main');

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

async function api(path, opts = {}) {
  const res = await fetch('/api' + path, { credentials: 'same-origin', ...opts });
  if (res.status === 401 && !path.startsWith('/login')) { showLogin(); throw new HttpError(401, 'unauthorized'); }
  const ct = res.headers.get('content-type') || '';
  const body = ct.includes('json') ? await res.json() : await res.text();
  if (!res.ok) throw new HttpError(res.status, body && body.error ? body.error : String(body));
  return body;
}

const fmtNum = n => (n === null || n === undefined || n === '') ? '' : Number(n).toLocaleString('en-US');
function fmtBytes(n) {
  n = Number(n); if (!isFinite(n)) return '';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}
function fmtTs(s) {
  if (!s) return '';
  return String(s).replace('T', ' ').replace(/Z$/, '');
}
function fmtDuration(s) {
  s = Number(s); if (!isFinite(s) || s <= 0) return s === 0 ? '0s' : '';
  const d = Math.floor(s / 86400), hh = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60), sec = s % 60;
  return [d && `${d}d`, hh && `${hh}h`, m && `${m}m`, !d && `${sec}s`].filter(Boolean).join(' ');
}
function toast(msg, err) { alert((err ? 'Error: ' : '') + msg); }

// ------------------------------------------------------------------ modal
function openModal(title, body, actions = []) {
  $('#modal-title').textContent = title;
  $('#modal-body').replaceChildren(body);
  $('#modal-actions').replaceChildren(...actions);
  $('#modal').hidden = false;
}
function closeModal() { $('#modal').hidden = true; $('#modal-body').replaceChildren(); }
document.addEventListener('DOMContentLoaded', () => {
  $('#modal-close').addEventListener('click', closeModal);
  $('#modal').addEventListener('click', e => { if (e.target.id === 'modal') closeModal(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
});
function copyBtn(getText) {
  return h('button', { class: 'btn small', onclick: async e => {
    try { await navigator.clipboard.writeText(getText()); e.target.textContent = 'Copied'; }
    catch { e.target.textContent = 'Copy failed'; }
  } }, 'Copy');
}

// ------------------------------------------------------------------ state & routing
const state = { user: null, caseId: null, caseOverview: null };

function parseHash() {
  const raw = location.hash.replace(/^#/, '') || '/';
  const [path, qs] = raw.split('?');
  return { parts: path.split('/').filter(Boolean).map(decodeURIComponent), params: new URLSearchParams(qs || '') };
}
function go(path) { location.hash = path; }
function setHashParams(params) {
  const { parts } = parseHash();
  const qs = params.toString();
  history.replaceState(null, '', '#/' + parts.map(encodeURIComponent).join('/') + (qs ? '?' + qs : ''));
}

window.addEventListener('hashchange', route);
window.addEventListener('DOMContentLoaded', async () => {
  try { const me = await api('/me'); state.user = me.user; renderUserbox(); route(); } catch { /* login shown */ }
});

function renderUserbox() {
  $('#userbox').replaceChildren(
    h('span', {}, state.user || ''),
    state.user ? h('button', { class: 'btn small', onclick: async () => { await api('/logout', { method: 'POST' }); location.reload(); } }, 'Log out') : ''
  );
}

function setCrumbs(...items) {
  $('#crumbs').replaceChildren(...items.flatMap((it, i) => [i ? ' / ' : '', it.href ? h('a', { href: it.href }, it.label) : h('span', {}, it.label)]));
}

let pollTimer = null;
async function route() {
  clearTimeout(pollTimer);
  const { parts, params } = parseHash();
  window.scrollTo(0, 0);
  try {
    if (parts[0] === 'case' && parts[1]) {
      await ensureCase(parts[1]);
      const section = parts[2] || 'overview';
      renderSidebar(section);
      if (section === 'overview') return renderOverview();
      if (section === 'session') return renderSession(parts[3], params);
      if (section === 'sid') return resolveSid(parts[3]);
      if (section === 'search') return renderSearch(params);
      const def = SECTIONS[section];
      if (def) return renderTableSection(section, def, params);
      main().replaceChildren(h('div', { class: 'empty' }, 'Unknown section'));
    } else {
      state.caseId = null; state.caseOverview = null;
      $('#sidebar').hidden = true;
      return renderCases();
    }
  } catch (e) {
    if (e.status !== 401) main().replaceChildren(h('div', { class: 'card err' }, String(e.message || e)));
  }
}

async function ensureCase(id) {
  if (state.caseId !== id || !state.caseOverview) {
    state.caseId = id;
    state.caseOverview = await api(`/cases/${encodeURIComponent(id)}`);
  }
}
const caseHref = (section, qs) => `#/case/${encodeURIComponent(state.caseId)}/${section}${qs ? '?' + qs : ''}`;

// ------------------------------------------------------------------ login
function showLogin() {
  state.user = null; renderUserbox();
  $('#sidebar').hidden = true; setCrumbs();
  const err = h('div', { class: 'err small' });
  const user = h('input', { name: 'username', autocomplete: 'username', required: true, autofocus: true });
  const pass = h('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true });
  const form = h('form', { onsubmit: async e => {
    e.preventDefault(); err.textContent = '';
    try {
      const r = await api('/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: user.value, password: pass.value }) });
      state.user = r.user; renderUserbox(); route();
    } catch (ex) { err.textContent = ex.message; pass.value = ''; pass.focus(); }
  } },
    h('h1', {}, 'Sign in'),
    h('label', { class: 'field' }, 'Username', user),
    h('label', { class: 'field' }, 'Password', pass),
    err,
    h('button', { class: 'btn primary', type: 'submit' }, 'Sign in'));
  main().replaceChildren(h('div', { class: 'login' }, h('div', { class: 'card' }, form)));
}

// ------------------------------------------------------------------ cases list & upload
const statusBadge = s => h('span', { class: 'badge ' + ({ ready: 'ok', ingesting: 'warn', error: 'err' }[s] || '') }, s || '?');

async function renderCases() {
  setCrumbs({ label: 'Cases' });
  const cases = await api('/cases');
  const list = cases.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
    h('thead', {}, h('tr', {}, ['Case', 'Status', 'Created (UTC)', 'Examiner', 'Archive', 'Size', 'SHA-256', ''].map(c => h('th', {}, c)))),
    h('tbody', {}, cases.map(c => h('tr', {},
      h('td', {}, h('a', { href: `#/case/${encodeURIComponent(c.id)}` }, c.name || c.id), h('div', { class: 'muted small mono' }, c.id)),
      h('td', {}, statusBadge(c.status), c.status === 'ingesting' ? h('div', { class: 'muted small' }, c.stage) : ''),
      h('td', { class: 'ts' }, fmtTs(c.created)),
      h('td', {}, c.examiner || ''),
      h('td', { class: 'mono' }, c.archive_name || ''),
      h('td', { class: 'num' }, fmtBytes(c.archive_size)),
      h('td', { class: 'mono small' }, c.sha256 || ''),
      h('td', {}, h('button', { class: 'btn small danger', onclick: async () => {
        if (!confirm(`Delete case "${c.name || c.id}" and its evidence copy? This cannot be undone.`)) return;
        try { await api(`/cases/${encodeURIComponent(c.id)}`, { method: 'DELETE' }); renderCases(); } catch (e) { toast(e.message, true); }
      } }, 'Delete')))))))
    : h('div', { class: 'empty' }, 'No case yet. Upload a collection to start.');

  main().replaceChildren(
    h('div', { class: 'card' }, h('h2', {}, 'New case'), uploadForm()),
    h('h2', {}, 'Cases'), list);
  if (cases.some(c => c.status === 'ingesting')) pollTimer = setTimeout(() => { if (!state.caseId) renderCases(); }, 3000);
}

function uploadForm() {
  let file = null;
  const fileInput = h('input', { type: 'file', accept: '.zip,.7z', hidden: true, onchange: () => pick(fileInput.files[0]) });
  const label = h('div', {}, h('strong', {}, 'Drop a ZIP or 7z collection here'), h('div', { class: 'small' }, 'or click to browse — e.g. a zipped ~/.claude, a KAPE/UAC triage archive, a user profile'));
  const drop = h('div', { class: 'drop', onclick: () => fileInput.click() }, label);
  ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', e => { if (e.dataTransfer.files[0]) pick(e.dataTransfer.files[0]); });
  const name = h('input', { placeholder: 'Case name (default: file name)' });
  const examiner = h('input', { placeholder: 'Examiner', value: state.user || '' });
  const notes = h('input', { placeholder: 'Notes / reference (optional)' });
  const password = h('input', { type: 'password', placeholder: 'Archive password (optional)', autocomplete: 'off' });
  const bar = h('div'); const progress = h('div', { class: 'progress', hidden: true }, bar);
  const status = h('div', { class: 'small muted' });
  const submit = h('button', { class: 'btn primary', type: 'submit', disabled: true }, 'Ingest');

  function pick(f) {
    if (!f) return;
    file = f;
    label.replaceChildren(h('strong', {}, f.name), h('div', { class: 'small' }, fmtBytes(f.size)));
    if (!name.value) name.value = f.name.replace(/\.(zip|7z)$/i, '');
    submit.disabled = false;
  }
  function upload() {
    if (!file) return;
    const fd = new FormData();
    fd.append('name', name.value); fd.append('examiner', examiner.value); fd.append('notes', notes.value); fd.append('password', password.value);
    fd.append('file', file, file.name);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/cases');
    progress.hidden = false; submit.disabled = true;
    xhr.upload.onprogress = e => { if (e.lengthComputable) { bar.style.width = (100 * e.loaded / e.total).toFixed(1) + '%'; status.textContent = `Uploading… ${fmtBytes(e.loaded)} / ${fmtBytes(e.total)}`; } };
    xhr.upload.onload = () => { status.textContent = 'Upload complete — hashing and verifying…'; };
    xhr.onload = () => {
      let r = {}; try { r = JSON.parse(xhr.responseText); } catch { }
      if (xhr.status === 200 && r.id) go(`/case/${encodeURIComponent(r.id)}`);
      else { status.textContent = 'Error: ' + (r.error || xhr.statusText); status.className = 'small err'; submit.disabled = false; }
    };
    xhr.onerror = () => { status.textContent = 'Network error'; submit.disabled = false; };
    xhr.send(fd);
  }
  return h('div', { class: 'grid' }, drop, fileInput,
    h('form', { class: 'row', onsubmit: e => { e.preventDefault(); upload(); } }, name, examiner, notes, password, submit),
    progress, status,
    h('div', { class: 'small muted' }, 'The archive is stored untouched in the case folder; MD5, SHA-1 and SHA-256 are computed during upload, and every extracted file is hashed (SHA-256).'));
}

// ------------------------------------------------------------------ sidebar
const NAV = [
  ['Investigation', [['overview', 'Overview'], ['timeline', 'Timeline', 'timeline'], ['search', 'Full-text search']]],
  ['Claude Code', [['profiles', 'Profiles', 'profiles'], ['projects', 'Projects', 'projects'], ['sessions', 'Sessions', 'sessions'],
    ['history', 'Prompt history', 'history'], ['tools', 'Tool calls', 'tool_calls'], ['filehistory', 'File history', 'file_history'],
    ['todos', 'Todos', 'todos'], ['registry', 'Process registry']]],
  ['Identity & secrets', [['accounts', 'Accounts', 'accounts'], ['credentials', 'Credentials & secrets', 'credentials']]],
  ['Configuration', [['mcp', 'MCP servers', 'mcp_servers'], ['config', 'Config & instructions', 'config_files']]],
  ['Claude Desktop', [['cookies', 'Cookies', 'cookies'], ['localstorage', 'Local Storage', 'local_storage']]],
  ['Evidence', [['files', 'Files', 'files'], ['warnings', 'Parser warnings', 'warnings'], ['audit', 'Audit log']]],
];

function renderSidebar(active) {
  const counts = state.caseOverview?.counts || {};
  const sb = $('#sidebar');
  sb.hidden = false;
  sb.replaceChildren(...NAV.flatMap(([group, items]) => [
    h('div', { class: 'group' }, group),
    ...items.map(([key, label, countKey]) => h('a', { href: caseHref(key), class: key === active ? 'active' : '' },
      h('span', {}, label), countKey && counts[countKey] !== undefined ? h('span', { class: 'n' }, fmtNum(counts[countKey])) : '')),
  ]));
  const meta = state.caseOverview?.meta || {};
  setCrumbs({ label: 'Cases', href: '#/' }, { label: meta.name || state.caseId, href: caseHref('overview') },
    ...(active !== 'overview' ? [{ label: NAV.flatMap(g => g[1]).find(i => i[0] === active)?.[1] || active }] : []));
}

// ------------------------------------------------------------------ overview
async function renderOverview() {
  state.caseOverview = await api(`/cases/${encodeURIComponent(state.caseId)}`);
  renderSidebar('overview');
  const { meta, counts, profiles, accounts, activity_range, top_tools } = state.caseOverview;
  const out = [];
  if (meta.status === 'ingesting') {
    out.push(h('div', { class: 'notice' }, `Ingestion in progress: ${meta.stage || ''}…`));
    pollTimer = setTimeout(() => { if (parseHash().parts[2] === undefined || parseHash().parts[2] === 'overview') renderOverview(); }, 2000);
  } else if (meta.status === 'error') {
    out.push(h('div', { class: 'notice' }, `Ingestion failed: ${meta.error || 'unknown error'}`));
  }
  const kv = rows => h('dl', { class: 'kv' }, rows.filter(r => r[1] !== undefined && r[1] !== '').flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]));
  out.push(h('h1', {}, meta.name || state.caseId));
  out.push(h('div', { class: 'grid two' },
    h('div', { class: 'card' }, h('h2', {}, 'Evidence'), kv([
      ['Archive', meta.archive_name], ['Format', meta.archive_format], ['Size', `${fmtBytes(meta.archive_size)} (${fmtNum(meta.archive_size)} bytes)`],
      ['SHA-256', h('span', { class: 'mono small' }, meta.archive_sha256 || '')], ['SHA-1', h('span', { class: 'mono small' }, meta.archive_sha1 || '')],
      ['MD5', h('span', { class: 'mono small' }, meta.archive_md5 || '')], ['Encrypted', meta.archive_password_used],
      ['Extracted', meta.extracted_files ? `${fmtNum(meta.extracted_files)} files, ${fmtBytes(meta.extracted_bytes)}` : ''],
    ])),
    h('div', { class: 'card' }, h('h2', {}, 'Case'), kv([
      ['Case ID', h('span', { class: 'mono' }, meta.id || state.caseId)], ['Status', statusBadge(meta.status)], ['Examiner', meta.examiner], ['Notes', meta.notes],
      ['Created (UTC)', fmtTs(meta.created)], ['Uploaded by', meta.created_by], ['Ingest finished', fmtTs(meta.ingest_finished)],
      ['Ingest duration', meta.ingest_seconds ? fmtDuration(meta.ingest_seconds) : ''], ['Tool version', meta.tool_version],
      ['Activity range', activity_range?.[0]?.first ? `${fmtTs(activity_range[0].first)} → ${fmtTs(activity_range[0].last)} UTC` : ''],
    ]))));

  const tiles = [['profiles', 'Profiles', 'profiles'], ['projects', 'Projects', 'projects'], ['sessions', 'Sessions', 'sessions'], ['sessions', 'Sub-agent runs', 'subagents', 'f_is_subagent=1'],
    ['search', 'Messages', 'messages'], ['tools', 'Tool calls', 'tool_calls'], ['history', 'Typed prompts', 'history'], ['accounts', 'Accounts', 'accounts'],
    ['credentials', 'Secrets found', 'credentials'], ['mcp', 'MCP servers', 'mcp_servers'], ['cookies', 'Cookies', 'cookies'], ['filehistory', 'File backups', 'file_history'],
    ['files', 'Files', 'files'], ['warnings', 'Warnings', 'warnings']];
  out.push(h('div', { class: 'grid tiles' }, tiles.map(([s, label, k, qs]) =>
    h('a', { class: 'tile', href: caseHref(s, qs) }, h('div', { class: 'v' }, fmtNum(counts[k] ?? 0)), h('div', { class: 'k' }, label)))));

  out.push(h('div', { class: 'card' }, h('h2', {}, 'User profiles'), profiles.length ? simpleTable(profiles,
    ['label', 'os_guess', 'root', 'accounts', 'sessions', 'projects', 'claude_dir', 'desktop_dir']) : h('div', { class: 'empty' }, 'No Claude artifact found in this archive.')));
  if (accounts.length) out.push(h('div', { class: 'card' }, h('h2', {}, 'Accounts'), simpleTable(accounts,
    ['profile', 'email', 'display_name', 'org_name', 'org_role', 'billing_type', 'account_created', 'first_start', 'machine_id'])));
  if (top_tools.length) {
    const max = Math.max(...top_tools.map(t => t.n));
    out.push(h('div', { class: 'card' }, h('h2', {}, 'Most used tools'), h('div', { class: 'bars' }, top_tools.map(t => {
      const fill = h('div', { class: 'fill' }); fill.style.width = (100 * t.n / max) + '%';
      return h('div', { class: 'bar' }, h('a', { href: caseHref('tools', 'f_tool_name=' + encodeURIComponent(t.tool_name)) }, t.tool_name), h('div', {}, fill), h('span', { class: 'n' }, fmtNum(t.n)));
    }))));
  }
  main().replaceChildren(...out);
}

function simpleTable(rows, cols) {
  return h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
    h('thead', {}, h('tr', {}, cols.map(c => h('th', {}, c)))),
    h('tbody', {}, rows.map(r => h('tr', {}, cols.map(c => renderCell(c, r[c], r, {})))))));
}

// ------------------------------------------------------------------ generic tables
const SECTIONS = {
  timeline: { view: 'timeline', title: 'Super-timeline', desc: 'Every timestamped event from all sources, in UTC. Click a value to pivot.', pivots: ['source', 'kind', 'profile', 'session_id'], hide: ['id'], wrap: ['summary'], dates: true },
  profiles: { view: 'profiles', title: 'Profiles', desc: 'Directories identified as a user home holding Claude Code (~/.claude) and/or Claude Desktop data.', pivots: ['os_guess'] },
  projects: { view: 'projects', title: 'Projects', desc: 'Working directories in which Claude Code was used (from ~/.claude/projects, ~/.claude.json and prompt history).', pivots: ['profile', 'trust_accepted'], hide: ['id'], dates: true, rowLink: r => caseHref('sessions', 'f_project=' + encodeURIComponent(r.path)) },
  sessions: { view: 'sessions', title: 'Sessions', desc: 'One row per transcript (projects/<dir>/<session>.jsonl). Click a row to read the conversation.', pivots: ['profile', 'project', 'models', 'versions', 'entrypoints', 'permission_modes', 'git_branches', 'is_subagent'],
    hide: ['cache_read_tokens', 'parse_errors', 'file_rel', 'parent_session'], dates: true, sort: 'first_ts', rowLink: r => caseHref('session/' + r.id) },
  history: { view: 'history', title: 'Prompt history', desc: 'Prompts typed by the user (~/.claude/history.jsonl), including prompts whose transcript was deleted.', pivots: ['profile', 'project', 'session_id'], hide: ['id'], wrap: ['display', 'pasted'], dates: true },
  tools: { view: 'tool_calls', title: 'Tool calls', desc: 'Every tool invoked by the agent: shell commands, file reads/writes, web fetches… Errors are flagged.', pivots: ['tool_name', 'profile', 'project', 'session_id', 'is_error'], hide: ['id', 'session_rowid', 'tool_use_id'], wrap: ['summary', 'result_excerpt'], dates: true },
  filehistory: { view: 'file_history', title: 'File history', desc: 'Pre-edit backups of files modified by Claude Code (~/.claude/file-history). Open a backup to see the prior content.', pivots: ['profile', 'session_id', 'original_path'], hide: ['id'], dates: true },
  todos: { view: 'todos', title: 'Todos', desc: 'Task lists maintained by the agent (~/.claude/todos).', pivots: ['profile', 'session_id', 'status'], hide: ['id'], wrap: ['content'] },
  registry: { view: 'registry', title: 'Process registry', desc: 'Claude Code processes registered at collection time (~/.claude/sessions/<pid>.json).', pivots: ['profile', 'status', 'kind', 'cwd'], hide: ['id'], dates: true },
  accounts: { view: 'accounts', title: 'Accounts', desc: 'Anthropic account identity from ~/.claude.json and its backups.', pivots: ['profile', 'email', 'org_name', 'source'], hide: ['id'] },
  credentials: { view: 'credentials', title: 'Credentials & secrets', desc: 'Tokens from credential files and configs, plus regex hits across all evidence (transcripts, logs, snapshots). Values are masked; revealing one is written to the audit log.', pivots: ['profile', 'origin', 'kind', 'file_rel'], hide: ['id'], wrap: ['context'], reveal: 'credentials' },
  mcp: { view: 'mcp', title: 'MCP servers', desc: 'Model Context Protocol servers configured at user, project, local and desktop scope.', pivots: ['profile', 'scope', 'transport', 'name', 'command'], hide: ['id'] },
  config: { view: 'config', title: 'Config & instructions', desc: 'Settings (hooks, permissions, env), CLAUDE.md, agents, slash commands, skills, memory, shell snapshots, desktop config and logs. Click to view.', pivots: ['profile', 'kind'], hide: ['id'], wrap: ['summary'], fileCol: 'file_rel' },
  cookies: { view: 'cookies', title: 'Cookies (Claude Desktop)', desc: 'Chromium cookie store of the Electron app. Values are normally encrypted (v10/v11/v20, DPAPI): metadata only.', pivots: ['profile', 'host', 'name', 'encryption', 'samesite'], hide: ['id'], dates: true, reveal: 'cookies' },
  localstorage: { view: 'local_storage', title: 'Local Storage (Claude Desktop)', desc: 'Decoded Chromium Local Storage LevelDB entries.', pivots: ['profile', 'origin', 'key'], hide: ['id'], wrap: ['value'] },
  files: { view: 'files', title: 'Files', desc: 'Every file extracted from the archive with SHA-256 and the timestamps recorded in the archive.', pivots: ['profile', 'category', 'mtime_note', 'encrypted'], hide: ['id', 'atime'], dates: true, fileCol: 'rel_path' },
  warnings: { view: 'warnings', title: 'Parser warnings', desc: 'Entries that could not be extracted or parsed.', pivots: ['source'], wrap: ['message'] },
  audit: { view: 'audit', title: 'Audit log', desc: 'Analyst actions on this case (ingest, exports, downloads, secret reveals).', pivots: ['user', 'action'], wrap: ['detail'], sort: 'ts', dir: 'desc' },
};

const TS_COLS = new Set(['ts', 'first_ts', 'last_ts', 'created', 'expires', 'last_access', 'last_update', 'backup_ts', 'started_ts', 'updated_ts', 'account_created', 'subscription_created', 'first_start', 'mtime', 'ctime', 'atime', 'result_ts']);
const NUM_COLS = new Set(['sessions', 'projects', 'user_msgs', 'assistant_msgs', 'tool_calls', 'input_tokens', 'output_tokens', 'cache_read_tokens', 'value_len', 'encrypted_len', 'version', 'pid', 'records', 'parse_errors']);
const FILE_COLS = new Set(['file_rel', 'rel_path', 'backup_rel']);

function renderCell(col, v, row, opts) {
  const cls = TS_COLS.has(col) ? 'ts' : NUM_COLS.has(col) || col === 'size' || col === 'cost_usd' || col === 'duration_s' ? 'num' : (opts.wrap || []).includes(col) ? 'wrap' : 'clip';
  const td = h('td', { class: cls, title: v !== null && v !== undefined && String(v).length > 60 ? String(v).slice(0, 2000) : null });
  if (v === null || v === undefined || v === '') return td;
  let content;
  if (TS_COLS.has(col)) content = fmtTs(v);
  else if (col === 'size' || col === 'value_len' && v > 4096) content = fmtBytes(v);
  else if (col === 'duration_s') content = fmtDuration(v);
  else if (col === 'cost_usd') content = '$' + Number(v).toFixed(2);
  else if (NUM_COLS.has(col)) content = fmtNum(v);
  else if (col === 'is_error') content = Number(v) ? h('span', { class: 'badge err' }, 'error') : h('span', { class: 'badge ok' }, 'ok');
  else if (col === 'is_subagent') content = Number(v) ? h('span', { class: 'badge tool' }, 'sub-agent') : '';
  else if (col === 'status' && opts.view === 'todos') content = h('span', { class: 'badge ' + (v === 'completed' ? 'ok' : v === 'in_progress' ? 'warn' : '') }, v);
  else if (FILE_COLS.has(col) || (col === 'source' && opts.view === 'accounts')) content = h('a', { onclick: e => { e.stopPropagation(); viewFile(v); } }, v);
  else if (col === 'session_id' && !(opts.pivots || []).includes(col)) content = h('a', { href: caseHref('sid/' + encodeURIComponent(v)), onclick: e => e.stopPropagation() }, v);
  else if (col === 'ref') content = refLink(v);
  else if (col === 'value_masked' && opts.reveal) content = h('span', {}, h('span', { class: 'mono' }, v), ' ', h('button', { class: 'btn small', onclick: e => { e.stopPropagation(); reveal(opts.reveal, row.id); } }, 'Reveal'));
  else content = String(v);
  if ((opts.pivots || []).includes(col) && opts.onPivot) {
    const val = String(v);
    const pv = h('span', { class: 'pivot', title: `Filter ${col} = ${val}`, onclick: e => { e.stopPropagation(); opts.onPivot(col, val); } }, content);
    td.append(pv);
    if (col === 'session_id') td.append(' ', h('a', { href: caseHref('sid/' + encodeURIComponent(v)), title: 'Open session', onclick: e => e.stopPropagation() }, '↗'));
  } else if (cls === 'wrap') td.append(h('div', { class: 'clamp', title: 'Click to expand', onclick: e => { e.stopPropagation(); e.currentTarget.classList.toggle('open'); } }, content));
  else td.append(content);
  return td;
}

function refLink(ref) {
  if (ref.startsWith('session:')) {
    const [sid, line] = ref.slice(8).split('#');
    return h('a', { href: caseHref('session/' + sid, line ? 'line=' + line : ''), onclick: e => e.stopPropagation() }, line ? `session #${sid} line ${line}` : `session #${sid}`);
  }
  if (ref.startsWith('file:') && ref.length > 5) return h('a', { onclick: e => { e.stopPropagation(); viewFile(ref.slice(5)); } }, 'file');
  return ref;
}

async function renderTableSection(section, def, params) {
  const head = h('div', {}, h('h1', {}, def.title), h('p', { class: 'muted' }, def.desc));
  const container = h('div');
  main().replaceChildren(head, container);
  dataTable(container, def, params);
}

function dataTable(container, def, initialParams, { syncHash = true } = {}) {
  const p = new URLSearchParams(initialParams);
  const st = {
    q: p.get('q') || '', from: p.get('from') || '', to: p.get('to') || '',
    sort: p.get('sort') || def.sort || '', dir: p.get('dir') || def.dir || '',
    limit: Number(p.get('limit')) || 100, offset: Number(p.get('offset')) || 0,
    filters: Object.fromEntries([...p.entries()].filter(([k]) => k.startsWith('f_')).map(([k, v]) => [k.slice(2), v])),
  };
  const search = h('input', { type: 'search', placeholder: 'Filter (all columns, space = AND)…', value: st.q });
  let t; search.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { st.q = search.value; st.offset = 0; load(); }, 300); });
  const from = h('input', { type: 'date', value: st.from.slice(0, 10), title: 'From (UTC)', onchange: e => { st.from = e.target.value; st.offset = 0; load(); } });
  const to = h('input', { type: 'date', value: st.to.slice(0, 10), title: 'To (UTC, inclusive)', onchange: e => { st.to = e.target.value; st.offset = 0; load(); } });
  const pageSize = h('select', { onchange: e => { st.limit = Number(e.target.value); st.offset = 0; load(); } },
    [50, 100, 250, 1000].map(n => h('option', { value: n, selected: n === st.limit }, `${n} rows`)));
  const exp = fmt => {
    const qs = queryString(false); qs.set('format', fmt);
    window.location.href = `/api/cases/${encodeURIComponent(state.caseId)}/export/${def.view}?${qs}`;
  };
  const toolbar = h('div', { class: 'toolbar' }, search, def.dates ? [h('span', { class: 'muted small' }, 'from'), from, h('span', { class: 'muted small' }, 'to'), to] : '',
    h('span', { class: 'spacer' }), pageSize, h('button', { class: 'btn small', onclick: () => exp('csv') }, 'Export CSV'), h('button', { class: 'btn small', onclick: () => exp('json') }, 'Export JSON'));
  const chips = h('div', { class: 'chips' });
  const wrap = h('div', { class: 'table-wrap' });
  const pager = h('div', { class: 'pager' });
  container.replaceChildren(toolbar, chips, wrap, pager);

  function queryString(withPaging = true) {
    const qs = new URLSearchParams();
    if (st.q) qs.set('q', st.q);
    if (st.from) qs.set('from', st.from);
    if (st.to) qs.set('to', st.to);
    if (st.sort) qs.set('sort', st.sort);
    if (st.dir) qs.set('dir', st.dir);
    for (const [k, v] of Object.entries(st.filters)) qs.set('f_' + k, v);
    if (withPaging) { qs.set('limit', st.limit); qs.set('offset', st.offset); }
    return qs;
  }
  const onPivot = (col, val) => { st.filters[col] = val; st.offset = 0; load(); };

  async function load() {
    const qs = queryString();
    if (syncHash) {
      const hq = queryString(false); if (st.offset) hq.set('offset', st.offset); if (st.limit !== 100) hq.set('limit', st.limit);
      setHashParams(hq);
    }
    chips.replaceChildren(...Object.entries(st.filters).map(([k, v]) => h('span', { class: 'chip' }, `${k} = ${v}`,
      h('button', { title: 'Remove filter', onclick: () => { delete st.filters[k]; st.offset = 0; load(); } }, '✕'))));
    wrap.replaceChildren(h('div', { class: 'empty' }, 'Loading…'));
    let data;
    try { data = await api(`/cases/${encodeURIComponent(state.caseId)}/table/${def.view}?${qs}`); }
    catch (e) { wrap.replaceChildren(h('div', { class: 'empty err' }, e.message)); return; }
    const cols = data.columns.filter(c => !(def.hide || []).includes(c));
    const opts = { ...def, onPivot };
    const thead = h('thead', {}, h('tr', {}, cols.map(c => {
      const sorted = (st.sort || '') === c;
      return h('th', { class: sorted ? 'sorted' : '', title: 'Sort', onclick: () => {
        if (st.sort === c) st.dir = st.dir === 'desc' ? 'asc' : 'desc'; else { st.sort = c; st.dir = 'asc'; }
        st.offset = 0; load();
      } }, c + (TS_COLS.has(c) ? ' (UTC)' : ''), sorted ? (st.dir === 'desc' ? ' ▼' : ' ▲') : '');
    })));
    const rows = data.rows.map(r => Object.fromEntries(data.columns.map((c, i) => [c, r[i]])));
    const tbody = h('tbody', {}, rows.map(r => {
      const tr = h('tr', {}, cols.map(c => renderCell(c, r[c], r, opts)));
      if (def.rowLink) { tr.style.cursor = 'pointer'; tr.addEventListener('click', () => { location.hash = def.rowLink(r).slice(1); }); }
      else if (def.fileCol) { tr.style.cursor = 'pointer'; tr.addEventListener('click', () => viewFile(r[def.fileCol])); }
      return tr;
    }));
    wrap.replaceChildren(rows.length ? h('table', { class: 'data' }, thead, tbody) : h('div', { class: 'empty' }, 'No rows match.'));
    wrap.scrollTop = 0;
    const end = Math.min(st.offset + st.limit, data.total);
    pager.replaceChildren(
      h('span', {}, data.total ? `${fmtNum(st.offset + 1)}–${fmtNum(end)} of ${fmtNum(data.total)}` : '0 rows'),
      h('button', { class: 'btn small', disabled: st.offset === 0, onclick: () => { st.offset = Math.max(0, st.offset - st.limit); load(); } }, '‹ Prev'),
      h('button', { class: 'btn small', disabled: end >= data.total, onclick: () => { st.offset += st.limit; load(); } }, 'Next ›'));
  }
  load();
}

// ------------------------------------------------------------------ file viewer & secrets
async function viewFile(rel) {
  openModal(rel, h('div', { class: 'empty' }, 'Loading…'));
  try {
    const r = await api(`/cases/${encodeURIComponent(state.caseId)}/file?path=${encodeURIComponent(rel)}`);
    const m = r.meta;
    let content = r.content;
    let pretty = false;
    if (!r.binary && /\.json$/i.test(rel) && !r.truncated) { try { content = JSON.stringify(JSON.parse(content), null, 2); pretty = true; } catch { } }
    const body = h('div', {},
      h('dl', { class: 'kv small' },
        h('dt', {}, 'SHA-256'), h('dd', { class: 'mono' }, m.sha256),
        h('dt', {}, 'Size'), h('dd', {}, `${fmtBytes(m.size)} (${fmtNum(m.size)} bytes)`),
        h('dt', {}, 'Modified'), h('dd', {}, `${fmtTs(m.mtime) || '—'} ${m.mtime_note ? '(' + m.mtime_note + ')' : ''}`),
        m.ctime ? [h('dt', {}, 'Created'), h('dd', {}, fmtTs(m.ctime))] : '',
        h('dt', {}, 'Archive path'), h('dd', { class: 'mono' }, m.archive_path),
        h('dt', {}, 'Category'), h('dd', {}, m.category || '')),
      r.truncated ? h('div', { class: 'notice' }, r.binary ? 'Binary file: hex dump of the first 64 KB.' : 'Large file: only the first 4 MB are shown. Download for the full content.') : r.binary ? h('div', { class: 'notice' }, 'Binary file (hex dump).') : '',
      pretty ? h('div', { class: 'muted small' }, 'JSON pretty-printed for display.') : '',
      h('hr'),
      h('pre', {}, content));
    const dl = h('a', { class: 'btn small', href: `/api/cases/${encodeURIComponent(state.caseId)}/file?path=${encodeURIComponent(rel)}&download=1` }, 'Download');
    openModal(rel, body, [copyBtn(() => content), dl]);
  } catch (e) { openModal(rel, h('div', { class: 'err' }, e.message)); }
}

async function reveal(table, id) {
  if (!confirm('Reveal this secret? The action is recorded in the case audit log.')) return;
  try {
    const r = await api(`/cases/${encodeURIComponent(state.caseId)}/reveal/${table}/${id}`, { method: 'POST' });
    const v = r.value ?? '(no plaintext value stored — encrypted)';
    openModal(`Secret #${id}`, h('pre', {}, v), [copyBtn(() => v)]);
  } catch (e) { toast(e.message, true); }
}

// ------------------------------------------------------------------ sessions
async function resolveSid(sid) {
  const r = await api(`/cases/${encodeURIComponent(state.caseId)}/table/sessions?f_session_id=${encodeURIComponent(sid)}&limit=1`);
  if (r.rows.length) { location.replace(caseHref('session/' + r.rows[0][0])); return; }
  // Session known only from prompt history or registry.
  location.replace(caseHref('timeline', 'f_session_id=' + encodeURIComponent(sid)));
}

function splitBlocks(text) {
  // Text was stored as blocks joined by newlines; markers start new blocks.
  const re = /^\[(thinking|tool_use [^\]]*|tool_result [^\]]*|redacted_thinking|image|document|attachment [^\]]*|file-history-snapshot)\]/;
  const blocks = []; let cur = null;
  for (const line of (text || '').split('\n')) {
    const m = line.match(re);
    if (m) { cur = { kind: m[1].split(' ')[0], label: m[1], text: line.slice(m[0].length).replace(/^ /, '') }; blocks.push(cur); }
    else if (cur) cur.text += '\n' + line;
    else { cur = { kind: 'text', text: line }; blocks.push(cur); }
  }
  return blocks;
}

function highlight(text, term) {
  if (!term) return [text];
  const out = []; const lower = text.toLowerCase(); const t = term.toLowerCase(); let i = 0, j;
  while ((j = lower.indexOf(t, i)) !== -1) { out.push(text.slice(i, j), h('mark', {}, text.slice(j, j + t.length))); i = j + t.length; }
  out.push(text.slice(i));
  return out;
}

async function renderSession(rowid, params) {
  const d = await api(`/cases/${encodeURIComponent(state.caseId)}/sessions/${encodeURIComponent(rowid)}`);
  const s = d.session;
  setCrumbs({ label: 'Cases', href: '#/' }, { label: state.caseOverview.meta.name || state.caseId, href: caseHref('overview') },
    { label: 'Sessions', href: caseHref('sessions') }, { label: s.title || s.session_id });
  const tab = params.get('tab') || 'conversation';
  const kv = rows => h('dl', { class: 'kv' }, rows.filter(r => r[1] !== null && r[1] !== undefined && r[1] !== '').flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]));
  const header = h('div', {},
    h('h1', {}, s.title || '(untitled session)', ' ', Number(s.is_subagent) ? h('span', { class: 'badge tool' }, 'sub-agent') : ''),
    h('div', { class: 'grid two' },
      h('div', { class: 'card' }, kv([
        ['Session ID', h('span', { class: 'mono' }, s.session_id)],
        ['Parent session', s.parent_session ? h('a', { href: caseHref('sid/' + encodeURIComponent(s.parent_session)) }, s.parent_session) : ''],
        ['Profile', s.profile], ['Project', s.project],
        ['Start (UTC)', fmtTs(s.first_ts)], ['End (UTC)', fmtTs(s.last_ts)], ['Duration', fmtDuration(s.duration_s)],
        ['Transcript', h('a', { onclick: () => viewFile(s.file_rel) }, s.file_rel)],
      ])),
      h('div', { class: 'card' }, kv([
        ['Models', s.models], ['Claude Code versions', s.versions], ['Entrypoints', s.entrypoints], ['Permission modes', s.permission_modes],
        ['Git branches', s.git_branches], ['Messages', `${fmtNum(s.user_msgs)} user / ${fmtNum(s.assistant_msgs)} assistant`],
        ['Tool calls', fmtNum(s.tool_calls)], ['Tokens', `${fmtNum(s.input_tokens)} in / ${fmtNum(s.output_tokens)} out / ${fmtNum(s.cache_read_tokens)} cache read`],
        ['Cost', s.cost_usd ? '$' + Number(s.cost_usd).toFixed(2) : ''], ['Parse errors', s.parse_errors ? String(s.parse_errors) : ''],
      ]))));
  const tabs = [['conversation', `Conversation (${d.messages.length})`], ['tools', `Tool calls (${d.tool_calls.length})`], ['files', `Files touched (${d.file_history.length})`],
    ['todos', `Todos (${d.todos.length})`], ['subagents', `Sub-agents (${d.subagents.length})`], ['prompts', `Typed prompts (${d.history.length})`]];
  const tabBar = h('div', { class: 'tabs' }, tabs.map(([k, label]) => h('a', { class: k === tab ? 'active' : '', href: caseHref('session/' + rowid, 'tab=' + k) }, label)));
  const body = h('div');
  main().replaceChildren(header, tabBar, body);

  if (tab === 'conversation') renderConversation(body, d.messages, params);
  else if (tab === 'tools') body.append(simpleTable(d.tool_calls, ['ts', 'tool_name', 'summary', 'is_error', 'result_excerpt']));
  else if (tab === 'files') body.append(d.file_history.length ? simpleTable(d.file_history, ['backup_ts', 'original_path', 'version', 'backup_file', 'backup_rel']) : h('div', { class: 'empty' }, 'No file backups for this session.'));
  else if (tab === 'todos') body.append(d.todos.length ? simpleTable(d.todos.map(t => t), ['status', 'content', 'active_form']) : h('div', { class: 'empty' }, 'No todos.'));
  else if (tab === 'subagents') body.append(d.subagents.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
    h('thead', {}, h('tr', {}, ['first_ts', 'title', 'first_prompt', 'tool_calls'].map(c => h('th', {}, c)))),
    h('tbody', {}, d.subagents.map(r => { const tr = h('tr', {}, ['first_ts', 'title', 'first_prompt', 'tool_calls'].map(c => renderCell(c, r[c], r, {}))); tr.style.cursor = 'pointer'; tr.onclick = () => go(`/case/${state.caseId}/session/${r.id}`); return tr; }))))
    : h('div', { class: 'empty' }, 'No sub-agent transcripts.'));
  else if (tab === 'prompts') body.append(d.history.length ? simpleTable(d.history, ['ts', 'display']) : h('div', { class: 'empty' }, 'No entries in history.jsonl for this session.'));
}

function renderConversation(container, messages, params) {
  const opts = { meta: false, thinking: true, results: true, find: '' };
  const target = Number(params.get('line')) || null;
  const find = h('input', { type: 'search', placeholder: 'Highlight text…' });
  const mk = (key, label) => h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: opts[key], onchange: e => { opts[key] = e.target.checked; draw(); } }), label);
  const counter = h('span', { class: 'muted small' });
  const controls = h('div', { class: 'convo-controls row' }, find, mk('thinking', 'Thinking'), mk('results', 'Tool results'), mk('meta', 'Meta / system records'), h('span', { class: 'spacer' }), counter);
  let t; find.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { opts.find = find.value.trim(); draw(); }, 250); });
  const list = h('div');
  container.replaceChildren(controls, list);

  function draw() {
    const shown = messages.filter(m => {
      if (m.line_no === target) return true;
      const isMain = (m.type === 'user' || m.type === 'assistant') && !Number(m.is_meta);
      if (!isMain && !opts.meta) return false;
      if (!opts.results && m.type === 'user' && /^\[tool_result/.test(m.text || '') && !/\n(?!\[tool_result)/.test(m.text)) return false;
      if (opts.find && !(m.text || '').toLowerCase().includes(opts.find.toLowerCase())) return false;
      return true;
    });
    counter.textContent = `${shown.length} of ${messages.length} records`;
    list.replaceChildren(...shown.map(renderMsg));
    if (target) { const el = document.getElementById('line-' + target); if (el) el.scrollIntoView({ block: 'center' }); }
  }

  function renderMsg(m) {
    const blocks = splitBlocks(m.text);
    const isToolRes = m.type === 'user' && blocks.length && blocks.every(b => b.kind === 'tool_result');
    const cls = ['msg', m.type === 'assistant' ? 'assistant' : isToolRes ? 'toolres' : m.type === 'user' && !Number(m.is_meta) ? 'user' : 'meta',
      Number(m.is_sidechain) ? 'sidechain' : '', m.line_no === target ? 'target' : ''].join(' ');
    const role = m.type === 'assistant' ? h('span', { class: 'badge assistant' }, 'assistant') : isToolRes ? h('span', { class: 'badge tool' }, 'tool result')
      : m.type === 'user' ? h('span', { class: 'badge user' }, Number(m.is_meta) ? 'user (meta)' : 'user') : h('span', { class: 'badge' }, m.type + (m.subtype ? ':' + m.subtype : ''));
    const head = h('div', { class: 'msg-head' }, role, h('span', { class: 'mono' }, fmtTs(m.ts)), m.model ? h('span', {}, m.model) : '', Number(m.is_sidechain) ? h('span', { class: 'badge' }, 'sidechain') : '',
      h('span', { class: 'spacer' }), h('a', { href: caseHref(`session/${parseHash().parts[3]}`, 'line=' + m.line_no), title: 'Permalink' }, `line ${m.line_no}`),
      h('button', { class: 'btn small ghost', onclick: () => showRaw(m) }, 'raw'));
    const body = h('div', { class: 'msg-body' }, blocks.filter(b => opts.thinking || b.kind !== 'thinking').filter(b => opts.results || b.kind !== 'tool_result').map(b => {
      const txt = highlight(b.text, opts.find);
      if (b.kind === 'thinking') return h('pre', { class: 'thinking' }, b.text.trim() ? txt : 'thinking (content not stored in transcript)');
      if (b.kind === 'tool_use') return h('div', { class: 'tooluse' }, h('span', { class: 'badge tool' }, b.label.replace('tool_use ', '')), ' ', h('pre', {}, txt));
      if (b.kind === 'tool_result') return h('div', { class: 'toolresult' + (/ERROR$/.test(b.label) ? ' error' : '') }, h('div', { class: 'muted small' }, b.label), h('pre', {}, txt));
      if (b.kind !== 'text') return h('div', {}, h('span', { class: 'badge' }, b.label), ' ', h('pre', {}, txt));
      return h('pre', {}, txt);
    }));
    return h('div', { class: cls, id: 'line-' + m.line_no }, head, body);
  }
  draw();
}

async function showRaw(m) {
  try {
    const raw = await api(`/cases/${encodeURIComponent(state.caseId)}/messages/${m.id}/raw`);
    const txt = JSON.stringify(raw, null, 2);
    openModal(`Raw JSONL record — line ${m.line_no}`, h('pre', {}, txt), [copyBtn(() => txt)]);
  } catch (e) { toast(e.message, true); }
}

// ------------------------------------------------------------------ search
async function renderSearch(params) {
  const q = h('input', { type: 'search', placeholder: 'Search all conversation records…', value: params.get('q') || '', autofocus: true });
  const type = h('select', {}, [['', 'Conversation records'], ['user', 'User (prompts & tool results)'], ['assistant', 'Assistant (text, thinking, tool use)'], ['system', 'System'], ['attachment', 'Attachments']]
    .map(([v, l]) => h('option', { value: v, selected: params.get('type') === v }, l)));
  const raw = h('label', { class: 'check', title: 'Use SQLite FTS5 syntax: AND/OR/NOT, "phrases", prefix*, NEAR()' }, h('input', { type: 'checkbox', checked: params.get('raw') === '1' }), 'FTS5 syntax');
  const results = h('div');
  const form = h('form', { class: 'toolbar', onsubmit: e => { e.preventDefault(); run(); } }, q, type, raw, h('button', { class: 'btn primary', type: 'submit' }, 'Search'));
  main().replaceChildren(h('h1', {}, 'Full-text search'), h('p', { class: 'muted' }, 'Searches the text of every transcript record (prompts, answers, thinking, tool inputs and outputs). Terms are AND-ed.'), form, results);
  async function run() {
    const qs = new URLSearchParams({ q: q.value });
    if (type.value) qs.set('type', type.value);
    if (raw.querySelector('input').checked) qs.set('raw', '1');
    setHashParams(qs);
    if (!q.value.trim()) { results.replaceChildren(); return; }
    results.replaceChildren(h('div', { class: 'empty' }, 'Searching…'));
    try {
      const r = await api(`/cases/${encodeURIComponent(state.caseId)}/search?${qs}`);
      results.replaceChildren(h('p', { class: 'muted' }, `${fmtNum(r.total)} matching record(s)${r.total > r.rows.length ? `, showing first ${r.rows.length}` : ''}`),
        ...r.rows.map(row => h('div', { class: 'msg ' + (row.type === 'assistant' ? 'assistant' : row.type === 'user' ? 'user' : 'meta') },
          h('div', { class: 'msg-head' }, h('span', { class: 'badge' }, row.type), h('span', { class: 'mono' }, fmtTs(row.ts)), h('span', {}, row.profile || ''), h('span', {}, row.project || ''),
            h('span', { class: 'spacer' }), h('a', { href: caseHref('session/' + row.session_rowid, 'line=' + row.line_no) }, (row.title || row.session_id) + ` — line ${row.line_no}`)),
          h('div', { class: 'msg-body' }, h('pre', {}, snippet(row.snippet))))));
    } catch (e) { results.replaceChildren(h('div', { class: 'err' }, e.message)); }
  }
  if (q.value) run();
}

function snippet(s) {
  // FTS snippet markers \u0001 … \u0002 become <mark>.
  const out = []; let rest = s || '';
  for (;;) {
    const a = rest.indexOf('\u0001'); if (a === -1) { out.push(rest); break; }
    const b = rest.indexOf('\u0002', a); if (b === -1) { out.push(rest); break; }
    out.push(rest.slice(0, a), h('mark', {}, rest.slice(a + 1, b))); rest = rest.slice(b + 1);
  }
  return out;
}
