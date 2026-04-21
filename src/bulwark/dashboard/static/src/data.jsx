// Store wired to real Bulwark HTTP API.
// The store shape (fields, action names, pub/sub contract) is preserved from
// the handoff reference so the view layer does not change — only the
// implementation below swaps mock data for live fetches. See ADR-020.

// -----------------------------------------------------------------------------
// Static metadata — display names for the 7 logical layers the dashboard shows.
// Backend emits events with a richer layer vocabulary (trust_boundary,
// analysis_guard, detection:protectai, …); those are normalized by
// `_normalizeEventLayer` before landing in state.events.
// -----------------------------------------------------------------------------
const LAYERS = [
  { id: 'sanitizer', name: 'Sanitizer',        desc: 'Strips hidden chars, steganography, control sequences',   events: 'events', stage: 'input' },
  { id: 'boundary',  name: 'Trust Boundary',   desc: 'Wraps untrusted content in XML boundary tags',             events: 'events', stage: 'input' },
  { id: 'detection', name: 'Detection',        desc: 'ProtectAI DeBERTa / PromptGuard classify injection',       events: 'events', stage: 'detect' },
  { id: 'analyze',   name: 'Phase 1: Analyze', desc: 'LLM reads content — no tools available',                   events: 'calls',  stage: 'llm' },
  { id: 'bridge',    name: 'Bridge Guard',     desc: 'Sanitize + guard analysis output between phases',          events: 'events', stage: 'bridge' },
  { id: 'canary',    name: 'Canary Tokens',    desc: 'Embedded tripwires for exfiltration detection',            events: 'checks', stage: 'bridge' },
  { id: 'execute',   name: 'Phase 2: Execute', desc: 'LLM acts on analysis — never sees raw content',            events: 'calls',  stage: 'llm' },
];

const SOURCES = ['api:clean:email', 'api:clean:dashboard', 'api:clean:mcp', 'api:clean:webhook', 'api:guard', 'cli:test'];

// Map dashboard layer id → backend BulwarkConfig field.
const _LAYER_TO_CONFIG = {
  sanitizer:         'sanitizer_enabled',
  boundary:          'trust_boundary_enabled',
  bridge:            'guard_bridge_enabled',
  canary:            'canary_enabled',
  // sub-toggles (rendered by Configure pane; same contract — same handler):
  require_json:      'require_json',
  encoding_canaries: 'encoding_resistant',
  emoji_smuggling:   'strip_emoji_smuggling',
  bidi_override:     'strip_bidi',
  nfkc:              'normalize_unicode',
};

// Backend event.layer → dashboard layer id.
function _normalizeEventLayer(raw) {
  if (!raw) return 'sanitizer';
  if (raw.startsWith('detection:')) return 'detection';
  const direct = {
    sanitizer: 'sanitizer',
    trust_boundary: 'boundary',
    analysis_guard: 'bridge',
    canary: 'canary',
    analyze: 'analyze',
    execute: 'execute',
    executor: 'analyze',
    guard: 'bridge',
  };
  return direct[raw] || raw;
}

function _transformEvent(raw) {
  return {
    id: String(raw.id ?? ('e_' + Math.random().toString(36).slice(2, 9))),
    ts: Math.round((raw.timestamp ?? raw.ts ?? Date.now() / 1000) * 1000),
    layer: _normalizeEventLayer(raw.layer),
    verdict: raw.verdict || 'passed',
    source: raw.source_id || raw.source || 'api:clean',
    detail: raw.detail || '',
    duration_ms: Math.round(raw.duration_ms || 0),
    metadata: raw.metadata || {},
    _raw_layer: raw.layer || '',
  };
}

function _layerConfigFromBackend(cfg) {
  return {
    sanitizer: !!cfg.sanitizer_enabled,
    boundary:  !!cfg.trust_boundary_enabled,
    detection: false, // overlaid from /api/integrations
    analyze:   !!(cfg.llm_backend && cfg.llm_backend.mode && cfg.llm_backend.mode !== 'none'),
    bridge:    !!cfg.guard_bridge_enabled,
    canary:    !!cfg.canary_enabled,
    execute:   !!(cfg.llm_backend && cfg.llm_backend.mode && cfg.llm_backend.mode !== 'none'),
    require_json:      !!cfg.require_json,
    encoding_canaries: !!cfg.encoding_resistant,
    emoji_smuggling:   !!cfg.strip_emoji_smuggling,
    bidi_override:     !!cfg.strip_bidi,
    nfkc:              !!cfg.normalize_unicode,
  };
}

function _integrationsFromBackend(raw) {
  const result = {};
  Object.keys(raw || {}).forEach((k) => {
    const info = raw[k] || {};
    result[k] = info.enabled ? 'active' : 'available';
  });
  return result;
}

function _llmFromBackend(cfg) {
  const b = cfg.llm_backend || {};
  const envOverrides = cfg.env_overrides || {};
  return {
    mode: b.mode || 'none',
    status: 'loading',
    apiKeySet: !!(b.api_key || envOverrides.api_key),
    envOverrides,
    apiKeyPreview: b.api_key ? ('•••' + String(b.api_key).slice(-4)) : '',
    baseUrl: b.base_url || '',
    analyzeModel: b.analyze_model || '',
    executeModel: b.execute_model || b.analyze_model || '',
  };
}

function fmtTime(ts) {
  const d = new Date(ts);
  const p = (n) => (n < 10 ? '0' + n : '' + n);
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}
function fmtRelative(ts) {
  const diff = (Date.now() - ts) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}
function rand(lo, hi) { return Math.floor(lo + Math.random() * (hi - lo)); }
function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }


// -----------------------------------------------------------------------------
// Store singleton. Same pub/sub contract as the reference mock.
// -----------------------------------------------------------------------------
const BulwarkStore = (() => {
  const state = {
    events: [],
    layerConfig: {
      sanitizer: true, boundary: true, detection: false, analyze: false,
      bridge: true, canary: true, execute: false,
      require_json: false, encoding_canaries: true, emoji_smuggling: true,
      bidi_override: true, nfkc: false,
    },
    llm: { mode: 'none', status: 'loading', apiKeySet: false, envOverrides: {}, apiKeyPreview: '', baseUrl: '', analyzeModel: '', executeModel: '' },
    integrations: {},
    presets: [],
    version: '',
    stats24h: { processed: 0, blocked: 0, canary: 0, bridge: 0 },
    sparks: Object.fromEntries(LAYERS.map(l => [l.id, new Array(14).fill(0)])),
    running: null,
    // Configure-page state (Stage 7) — filled by _loadInitial + explicit fetchers.
    guardPatterns: [],   // regex list from config.guard_patterns
    canaryTokens: {},    // {source: token} from config.canary_tokens
    models: [],          // populated by fetchModels() when LLMBackendPane mounts
    modelsLoading: false,
    llmTestResult: null, // last result from testConnection()
    // Test-page state (Stage 8).
    redteamTiers: null,   // {garak_installed, garak_version, tiers: [...]}
    redteamReports: [],   // past reports from /api/redteam/reports
  };

  const subs = new Set();
  const listeners = new Set();
  let _sse = null;
  let _runningPoll = null;

  function emit() { subs.forEach(f => f()); }
  function fireEvent(ev) { listeners.forEach(f => f(ev)); }

  async function _fetchJson(url, options) {
    const res = await fetch(url, options);
    if (!res.ok) throw new Error(`${url} → ${res.status}`);
    return res.json();
  }

  async function _loadInitial() {
    const [healthzR, configR, integrationsR, presetsR, eventsR, metricsR] = await Promise.allSettled([
      _fetchJson('/healthz'),
      _fetchJson('/api/config'),
      _fetchJson('/api/integrations'),
      _fetchJson('/api/presets'),
      _fetchJson('/api/events?limit=200'),
      _fetchJson('/api/metrics?hours=24'),
    ]);

    if (healthzR.status === 'fulfilled') {
      state.version = healthzR.value.version || '';
    }

    if (configR.status === 'fulfilled') {
      state.layerConfig = _layerConfigFromBackend(configR.value);
      state.llm = _llmFromBackend(configR.value);
      state.guardPatterns = Array.isArray(configR.value.guard_patterns) ? configR.value.guard_patterns : [];
      state.canaryTokens = (configR.value.canary_tokens && typeof configR.value.canary_tokens === 'object') ? configR.value.canary_tokens : {};
    }

    if (integrationsR.status === 'fulfilled') {
      state.integrations = _integrationsFromBackend(integrationsR.value);
      const anyDetection = ['protectai', 'promptguard'].some(k => state.integrations[k] === 'active');
      state.layerConfig = { ...state.layerConfig, detection: anyDetection };
    }

    if (presetsR.status === 'fulfilled') {
      state.presets = (presetsR.value.presets || []).map(p => ({ ...p, family: p.family || 'boundary' }));
    }

    if (eventsR.status === 'fulfilled') {
      const raw = Array.isArray(eventsR.value) ? eventsR.value : (eventsR.value.events || []);
      state.events = raw.map(_transformEvent).sort((a, b) => b.ts - a.ts);
    }

    if (metricsR.status === 'fulfilled') {
      const m = metricsR.value || {};
      state.stats24h = {
        processed: m.total || m.processed || state.events.length,
        blocked:   m.blocked   || state.events.filter(e => e.verdict === 'blocked').length,
        canary:    m.canary    || state.events.filter(e => e.layer === 'canary' && e.verdict === 'blocked').length,
        bridge:    m.bridge    || state.events.filter(e => e.layer === 'bridge' && e.verdict === 'blocked').length,
      };
    }

    // LLM status — `none` is a valid connected state. For other modes we assume
    // connected after a successful config fetch; Stage 4 replaces this with a
    // real probe endpoint.
    if (state.llm.mode === 'none') {
      state.llm = { ...state.llm, status: 'connected' };
    } else if (configR.status === 'fulfilled') {
      state.llm = { ...state.llm, status: 'connected' };
    } else {
      state.llm = { ...state.llm, status: 'error' };
    }

    _recomputeSparks();
    emit();
  }

  function _recomputeSparks() {
    const now = Date.now();
    const windowMs = 14 * 60 * 1000;
    const bucketMs = 60 * 1000;
    const fresh = Object.fromEntries(LAYERS.map(l => [l.id, new Array(14).fill(0)]));
    state.events.forEach((e) => {
      const age = now - e.ts;
      if (age < 0 || age >= windowMs) return;
      const bucketIdx = 13 - Math.floor(age / bucketMs);
      if (bucketIdx < 0 || bucketIdx > 13) return;
      if (fresh[e.layer]) fresh[e.layer][bucketIdx]++;
    });
    state.sparks = fresh;
  }

  function _connectSSE() {
    if (typeof EventSource === 'undefined') return;
    try {
      _sse = new EventSource('/api/stream');
      _sse.onmessage = (msg) => {
        try {
          const raw = JSON.parse(msg.data);
          const ev = _transformEvent(raw);
          state.events = [ev, ...state.events].slice(0, 500);
          state.stats24h = {
            ...state.stats24h,
            processed: state.stats24h.processed + 1,
            blocked: state.stats24h.blocked + (ev.verdict === 'blocked' ? 1 : 0),
            canary:  state.stats24h.canary  + (ev.layer === 'canary' && ev.verdict === 'blocked' ? 1 : 0),
            bridge:  state.stats24h.bridge  + (ev.layer === 'bridge' && ev.verdict === 'blocked' ? 1 : 0),
          };
          _recomputeSparks();
          fireEvent(ev);
          emit();
        } catch { /* malformed — skip */ }
      };
      // EventSource auto-retries on errors; no manual handler needed.
    } catch {
      // SSE unavailable — UI keeps snapshot.
    }
  }

  function _startRunningPoll() {
    if (_runningPoll) return;
    _runningPoll = setInterval(async () => {
      try {
        const r = await _fetchJson('/api/redteam/status');
        if (r.status === 'running') {
          state.running = {
            kind: r.tier || state.running?.kind || 'quick',
            progress: r.completed || 0,
            total: r.total || 0,
            startedAt: state.running?.startedAt || Date.now(),
          };
        } else {
          state.running = null;
          clearInterval(_runningPoll);
          _runningPoll = null;
        }
        emit();
      } catch { /* keep polling */ }
    }, 750);
  }

  async function _putConfig(patch) {
    try {
      const updated = await _fetchJson('/api/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      const prevStatus = state.llm.status;
      state.layerConfig = _layerConfigFromBackend(updated);
      state.llm = { ..._llmFromBackend(updated), status: prevStatus };
      state.guardPatterns = Array.isArray(updated.guard_patterns) ? updated.guard_patterns : state.guardPatterns;
      state.canaryTokens = (updated.canary_tokens && typeof updated.canary_tokens === 'object') ? updated.canary_tokens : state.canaryTokens;
      const anyDetection = ['protectai', 'promptguard'].some(k => state.integrations[k] === 'active');
      state.layerConfig.detection = anyDetection;
      emit();
    } catch (e) {
      console.error('config update failed', e);
    }
  }

  return {
    get: () => state,
    subscribe: (fn) => { subs.add(fn); return () => subs.delete(fn); },
    onEvent: (fn) => { listeners.add(fn); return () => listeners.delete(fn); },

    async init() {
      await _loadInitial();
      _connectSSE();
    },

    // G-CANARY-011: Canary pane calls this after POST/DELETE /api/canaries
    // to re-pull the live config and re-render.
    async refreshConfig() {
      try {
        const cfg = await _fetchJson('/api/config');
        state.layerConfig = _layerConfigFromBackend(cfg);
        state.llm = _llmFromBackend(cfg);
        state.guardPatterns = Array.isArray(cfg.guard_patterns) ? cfg.guard_patterns : [];
        state.canaryTokens = (cfg.canary_tokens && typeof cfg.canary_tokens === 'object') ? cfg.canary_tokens : {};
        emit();
      } catch (e) { /* leave state as-is on failure */ }
    },

    toggleLayer(id) {
      const current = !!state.layerConfig[id];
      if (id === 'detection') return; // aggregate — managed via Detection pane
      if (id === 'analyze' || id === 'execute') {
        if (current) {
          _putConfig({ llm_backend: { mode: 'none' } });
        }
        return;
      }
      const field = _LAYER_TO_CONFIG[id];
      if (!field) return;
      _putConfig({ [field]: !current });
    },

    setLlm(patch) {
      const backendPatch = { llm_backend: {
        mode:          patch.mode          ?? state.llm.mode,
        api_key:       patch.apiKey        ?? undefined,
        base_url:      patch.baseUrl       ?? state.llm.baseUrl,
        analyze_model: patch.analyzeModel  ?? state.llm.analyzeModel,
        execute_model: patch.executeModel  ?? state.llm.executeModel,
      }};
      if (backendPatch.llm_backend.api_key === undefined) delete backendPatch.llm_backend.api_key;
      _putConfig(backendPatch);
    },

    async setIntegration(id, desired) {
      try {
        if (desired === 'active') {
          await _fetchJson(`/api/integrations/${id}/activate`, { method: 'POST' });
        } else {
          await _fetchJson(`/api/integrations/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: false }),
          });
        }
        const raw = await _fetchJson('/api/integrations');
        state.integrations = _integrationsFromBackend(raw);
        const anyDetection = ['protectai', 'promptguard'].some(k => state.integrations[k] === 'active');
        state.layerConfig = { ...state.layerConfig, detection: anyDetection };
        emit();
      } catch (e) {
        console.error('integration toggle failed', e);
      }
    },

    async startRun(kind) {
      try {
        const r = await _fetchJson('/api/redteam/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ tier: kind }),
        });
        state.running = { kind, progress: 0, total: 0, startedAt: Date.now() };
        emit();
        _startRunningPoll();
        return r;
      } catch (e) {
        console.error('start run failed', e);
      }
    },

    stepRun() { /* no-op; backend drives progress via poll */ },

    async stopRun() {
      try {
        await _fetchJson('/api/redteam/stop', { method: 'POST' });
      } catch (e) {
        console.error('stop run failed', e);
      }
    },

    // Stage 7: populate state.models from the backend. Safe to call repeatedly;
    // callers typically fire it on mount + when mode/baseUrl change.
    async fetchModels() {
      state.modelsLoading = true;
      emit();
      try {
        const body = {
          mode: state.llm.mode,
          // Don't forward an api_key — the backend resolves it from config/env.
          base_url: state.llm.baseUrl || '',
        };
        const res = await _fetchJson('/v1/llm/models', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        state.models = Array.isArray(res.models) ? res.models : [];
      } catch (e) {
        state.models = [];
      } finally {
        state.modelsLoading = false;
        emit();
      }
    },

    // Stage 8: fetch dynamic red-team tier definitions from the backend.
    // Fires once on mount; results include garak version + per-tier probe counts.
    async fetchRedteamTiers() {
      try {
        const res = await _fetchJson('/api/redteam/tiers');
        state.redteamTiers = res;
        emit();
        return res;
      } catch (e) {
        state.redteamTiers = { garak_installed: false, tiers: [] };
        emit();
      }
    },

    // Stage 8: fetch past red-team reports. Called on Test page mount and after
    // a run completes to pick up the newly saved report.
    async fetchRedteamReports() {
      try {
        const res = await _fetchJson('/api/redteam/reports');
        state.redteamReports = Array.isArray(res.reports) ? res.reports : (Array.isArray(res) ? res : []);
        emit();
        return state.redteamReports;
      } catch (e) {
        state.redteamReports = [];
        emit();
      }
    },

    // Stage 8: retest the failed probes from a previous report.
    async retestReport(filename) {
      try {
        const res = await _fetchJson('/api/redteam/retest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename }),
        });
        if (res && res.status === 'running') {
          state.running = { kind: 'retest', progress: 0, total: 0, startedAt: Date.now() };
          emit();
          _startRunningPoll();
        }
        return res;
      } catch (e) {
        console.error('retest failed', e);
        return { status: 'error', message: String(e && e.message || e) };
      }
    },

    // Stage 8: run a single payload through the real defense stack.
    // Returns the full CleanResponse (or a normalized {blocked:true, trace} on 422).
    async runClean(content, source = 'dashboard') {
      try {
        const res = await fetch('/v1/clean', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content, source }),
        });
        // 422 on block — body has the same shape as the 200 response but with blocked=true.
        const body = await res.json().catch(() => ({}));
        return { httpStatus: res.status, ...body };
      } catch (e) {
        return { httpStatus: 0, blocked: false, error: String(e && e.message || e), trace: [] };
      }
    },

    // Stage 7: live LLM connectivity probe used by the "Test connection" button.
    //
    // Accepts an optional overrides object so the caller (LLMBackendPane) can
    // test the current *in-form* values rather than only the last-saved config
    // (G-UI-CONFIG-TEST-CONNECTION). Fields not provided fall back to the
    // backend's saved values via /v1/llm/test's own defaulting.
    async testConnection(overrides = {}) {
      state.llm = { ...state.llm, status: 'loading' };
      state.llmTestResult = null;
      emit();
      const body = {
        mode: overrides.mode !== undefined ? overrides.mode : state.llm.mode,
      };
      if (overrides.base_url !== undefined) body.base_url = overrides.base_url;
      if (overrides.analyze_model !== undefined) body.analyze_model = overrides.analyze_model;
      if (overrides.execute_model !== undefined) body.execute_model = overrides.execute_model;
      if (overrides.api_key) body.api_key = overrides.api_key;
      try {
        const res = await _fetchJson('/v1/llm/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        const ok = res && (res.ok === true || res.connected === true || res.status === 'ok');
        state.llm = { ...state.llm, status: ok ? 'connected' : 'error' };
        state.llmTestResult = res;
      } catch (e) {
        state.llm = { ...state.llm, status: 'error' };
        state.llmTestResult = { ok: false, message: String(e && e.message || e) };
      } finally {
        emit();
      }
      return state.llmTestResult;
    },

    injectEvent(layer, verdict) {
      const ev = _transformEvent({
        id: 'local_' + Math.random().toString(36).slice(2, 9),
        timestamp: Date.now() / 1000,
        layer, verdict: verdict || 'passed',
        source_id: pick(SOURCES),
        detail: '',
        duration_ms: rand(1, 200),
      });
      state.events = [ev, ...state.events].slice(0, 500);
      state.stats24h = {
        ...state.stats24h,
        processed: state.stats24h.processed + 1,
        blocked: state.stats24h.blocked + (verdict === 'blocked' ? 1 : 0),
      };
      _recomputeSparks();
      fireEvent(ev);
      emit();
    },
  };
})();

BulwarkStore.init();

function useStore() {
  const [, force] = React.useReducer(x => x + 1, 0);
  React.useEffect(() => BulwarkStore.subscribe(force), []);
  return BulwarkStore.get();
}

// Shared across shell.jsx + page-shield.jsx. STATES.md §1 / G-UI-STATUS-006:
// analyze + execute count as virtually "on" when the user chose sanitize-only.
function activeLayerCount(layerConfig, llmMode) {
  const noneMode = llmMode === 'none';
  return LAYERS.filter(l => {
    if (noneMode && (l.id === 'analyze' || l.id === 'execute')) return true;
    return !!layerConfig[l.id];
  }).length;
}

Object.assign(window, { LAYERS, SOURCES, BulwarkStore, useStore, fmtTime, fmtRelative, rand, pick, activeLayerCount });
