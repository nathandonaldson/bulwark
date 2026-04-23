// Store wired to the real Bulwark v2 HTTP API.
//
// v2.0.0 (ADR-031): Bulwark never calls an LLM. The store no longer tracks
// analyze/execute/bridge layers, llm.mode/api_key/models, or the
// testConnection/fetchModels helpers.
//
// Four logical layers remain: sanitizer → detection → boundary → canary.
// Canary is output-side only; the Leak Detection page surfaces it. See ADR-031.

const LAYERS = [
  { id: 'sanitizer', name: 'Sanitizer',      desc: 'Strips hidden chars, steganography, control sequences',   events: 'events', stage: 'input'  },
  { id: 'detection', name: 'Detection',      desc: 'DeBERTa classifies injection; chunked across windows',     events: 'events', stage: 'detect' },
  { id: 'boundary',  name: 'Trust Boundary', desc: 'Wraps untrusted content in XML boundary tags',             events: 'events', stage: 'input'  },
  { id: 'canary',    name: 'Canary Tokens',  desc: 'Output-side tripwires — checked via /v1/guard',            events: 'checks', stage: 'output' },
];

const SOURCES = ['api:clean:email', 'api:clean:dashboard', 'api:clean:mcp', 'api:clean:webhook', 'api:guard', 'cli:test'];

// Map dashboard layer id → backend BulwarkConfig field.
const _LAYER_TO_CONFIG = {
  sanitizer:         'sanitizer_enabled',
  boundary:          'trust_boundary_enabled',
  canary:            'canary_enabled',
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
    analysis_guard: 'canary',
    canary: 'canary',
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
    canary:    !!cfg.canary_enabled,
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


const BulwarkStore = (() => {
  const state = {
    events: [],
    layerConfig: {
      sanitizer: true, boundary: true, detection: false, canary: true,
      encoding_canaries: true, emoji_smuggling: true, bidi_override: true, nfkc: false,
    },
    // detector: { protectai: {status: 'ready'|'loading'|'error', latency_ms, score}, promptguard: {...} }
    detectorStatus: {
      protectai: { status: 'loading' },
      promptguard: { status: 'available' },
    },
    integrations: {},
    presets: [],
    version: '',
    stats24h: { processed: 0, blocked: 0, canary: 0, detection: 0 },
    sparks: Object.fromEntries(LAYERS.map(l => [l.id, new Array(14).fill(0)])),
    running: null,
    guardPatterns: [],
    canaryTokens: {},
    judge: {            // ADR-033 — opt-in LLM judge config
      enabled: false, mode: 'openai_compatible', base_url: '',
      api_key: '', model: '', threshold: 0.85, fail_open: true,
    },
    redteamTiers: null,
    redteamReports: [],
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

    if (healthzR.status === 'fulfilled') state.version = healthzR.value.version || '';

    if (configR.status === 'fulfilled') {
      state.layerConfig = _layerConfigFromBackend(configR.value);
      state.guardPatterns = Array.isArray(configR.value.guard_patterns) ? configR.value.guard_patterns : [];
      state.canaryTokens = (configR.value.canary_tokens && typeof configR.value.canary_tokens === 'object') ? configR.value.canary_tokens : {};
      if (configR.value.judge_backend && typeof configR.value.judge_backend === 'object') {
        state.judge = { ...state.judge, ...configR.value.judge_backend };
      }
    }

    if (integrationsR.status === 'fulfilled') {
      state.integrations = _integrationsFromBackend(integrationsR.value);
      const anyDetection = ['protectai', 'promptguard'].some(k => state.integrations[k] === 'active');
      state.layerConfig = { ...state.layerConfig, detection: anyDetection };
      // Seed detectorStatus from integrations.
      state.detectorStatus = {
        protectai:   { status: state.integrations.protectai   === 'active' ? 'ready' : 'loading' },
        promptguard: { status: state.integrations.promptguard === 'active' ? 'ready' : 'available' },
      };
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
        detection: m.detection || state.events.filter(e => e.layer === 'detection' && e.verdict === 'blocked').length,
      };
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
            canary:  state.stats24h.canary  + (ev.layer === 'canary'    && ev.verdict === 'blocked' ? 1 : 0),
            detection: state.stats24h.detection + (ev.layer === 'detection' && ev.verdict === 'blocked' ? 1 : 0),
          };
          _recomputeSparks();
          fireEvent(ev);
          emit();
        } catch { /* malformed — skip */ }
      };
    } catch { /* SSE unavailable */ }
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
      state.layerConfig = _layerConfigFromBackend(updated);
      state.guardPatterns = Array.isArray(updated.guard_patterns) ? updated.guard_patterns : state.guardPatterns;
      state.canaryTokens = (updated.canary_tokens && typeof updated.canary_tokens === 'object') ? updated.canary_tokens : state.canaryTokens;
      if (updated.judge_backend && typeof updated.judge_backend === 'object') {
        state.judge = { ...state.judge, ...updated.judge_backend };
      }
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

    async refreshConfig() {
      try {
        const cfg = await _fetchJson('/api/config');
        state.layerConfig = _layerConfigFromBackend(cfg);
        state.guardPatterns = Array.isArray(cfg.guard_patterns) ? cfg.guard_patterns : [];
        state.canaryTokens = (cfg.canary_tokens && typeof cfg.canary_tokens === 'object') ? cfg.canary_tokens : {};
        if (cfg.judge_backend && typeof cfg.judge_backend === 'object') {
          state.judge = { ...state.judge, ...cfg.judge_backend };
        }
        emit();
      } catch { /* leave state as-is */ }
    },

    // ADR-033 — judge config setters routed through PUT /api/config.
    async setJudgeEnabled(enabled) {
      await _putConfig({ judge_backend: { enabled: !!enabled } });
    },
    async setJudgeConfig(patch) {
      await _putConfig({ judge_backend: patch });
    },

    toggleLayer(id) {
      if (id === 'detection') return; // aggregate — managed via Detection pane
      const field = _LAYER_TO_CONFIG[id];
      if (!field) return;
      const current = !!state.layerConfig[id];
      _putConfig({ [field]: !current });
    },

    async setIntegration(id, desired) {
      try {
        state.detectorStatus = { ...state.detectorStatus, [id]: { ...(state.detectorStatus[id] || {}), status: desired === 'active' ? 'loading' : 'available' } };
        emit();
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
        state.detectorStatus = {
          protectai:   { status: state.integrations.protectai   === 'active' ? 'ready' : 'available' },
          promptguard: { status: state.integrations.promptguard === 'active' ? 'ready' : 'available' },
        };
        emit();
      } catch (e) {
        state.detectorStatus = { ...state.detectorStatus, [id]: { status: 'error', message: String(e && e.message || e) } };
        emit();
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
      } catch (e) { console.error('start run failed', e); }
    },

    stepRun() { /* backend-driven */ },

    async stopRun() {
      try { await _fetchJson('/api/redteam/stop', { method: 'POST' }); }
      catch (e) { console.error('stop run failed', e); }
    },

    async fetchRedteamTiers() {
      try {
        const res = await _fetchJson('/api/redteam/tiers');
        state.redteamTiers = res;
        emit();
        return res;
      } catch {
        state.redteamTiers = { garak_installed: false, tiers: [] };
        emit();
      }
    },

    async fetchRedteamReports() {
      try {
        const res = await _fetchJson('/api/redteam/reports');
        state.redteamReports = Array.isArray(res.reports) ? res.reports : (Array.isArray(res) ? res : []);
        emit();
        return state.redteamReports;
      } catch {
        state.redteamReports = [];
        emit();
      }
    },

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

    async runClean(content, source = 'dashboard') {
      try {
        const res = await fetch('/v1/clean', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content, source }),
        });
        const body = await res.json().catch(() => ({}));
        return { httpStatus: res.status, ...body };
      } catch (e) {
        return { httpStatus: 0, blocked: false, error: String(e && e.message || e), trace: [] };
      }
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

// activeLayerCount: how many user-controllable layers are enabled.
function activeLayerCount(layerConfig) {
  return LAYERS.filter(l => !!layerConfig[l.id]).length;
}

Object.assign(window, { LAYERS, SOURCES, BulwarkStore, useStore, fmtTime, fmtRelative, rand, pick, activeLayerCount });
