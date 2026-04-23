// Configure page — v2 layout (ADR-031).
//
// Three sections: (1) Pipeline layers, (2) Detectors, (3) Guard patterns.
// Canary management has moved to its own Leak Detection page. No LLM
// backend configuration — Bulwark doesn't call an LLM.

function PageConfigure({ store }) {
  return (
    <div style={{padding: '28px 28px 60px', maxWidth: 1100, margin: '0 auto'}}>
      <div style={{marginBottom: 24}}>
        <div className="label">System</div>
        <h2 className="display" style={{fontSize: 28, fontWeight: 600, letterSpacing: '-0.01em', marginTop: 4}}>Configure</h2>
        <div className="dim" style={{fontSize: 13, marginTop: 4, maxWidth: 640}}>
          Bulwark sanitizes untrusted content, runs it through a prompt-injection detector,
          and wraps the result in trust-boundary tags. Your LLM never sees Bulwark —
          you call <span className="mono">/v1/clean</span>, feed the result into your own LLM,
          and call <span className="mono">/v1/guard</span> on the LLM's output.
        </div>
      </div>

      <div style={{display: 'grid', gridTemplateColumns: '1fr', gap: 24}}>
        <PipelineLayersCard store={store} />
        <DetectorCard store={store} id="protectai"
          title="DeBERTa (mandatory)"
          subtitle="ProtectAI deberta-v3 — ungated classifier, loads on first use."
          mandatory={true} />
        <DetectorCard store={store} id="promptguard"
          title="PromptGuard (optional — second opinion)"
          subtitle="Meta mDeBERTa. Requires HuggingFace approval. Enable only if you want a second detector."
          mandatory={false} />
        <GuardPatternsCard store={store} />
      </div>
    </div>
  );
}

function PipelineLayersCard({ store }) {
  const cfg = store.layerConfig;
  const layers = [
    { id: 'sanitizer', name: 'Sanitizer',       desc: 'Strip zero-width chars, bidi overrides, emoji smuggling' },
    { id: 'boundary',  name: 'Trust Boundary',  desc: 'Wrap cleaned content in XML boundary tags' },
  ];
  const subConfigToggles = [
    { id: 'encoding_canaries', name: 'Encoding-resistant canary variants', desc: 'Also match base64, hex, reversed forms (applies to /v1/guard)' },
    { id: 'emoji_smuggling',   name: 'Strip emoji smuggling',              desc: 'Remove variation selectors that hide payload bytes' },
    { id: 'bidi_override',     name: 'Strip bidi overrides',               desc: 'Remove U+202E/U+202D direction overrides' },
    { id: 'nfkc',              name: 'Unicode NFKC normalisation',         desc: 'Collapse look-alike characters to canonical forms' },
  ];
  return (
    <div className="card" style={{padding: 0}}>
      <div style={{padding: '16px 20px', borderBottom: '1px solid var(--hairline)'}}>
        <div className="label">Step 1</div>
        <div style={{fontSize: 17, fontWeight: 600, marginTop: 2}}>Pipeline layers</div>
        <div className="dim" style={{fontSize: 12, marginTop: 4}}>
          Deterministic, always-on preprocessing. Toggle a layer off only to diagnose — there is no reason to ship with them disabled.
        </div>
      </div>
      <div style={{padding: '8px 20px 18px'}}>
        {layers.map(l => (
          <ConfigConfigToggleRow key={l.id} name={l.name} desc={l.desc} on={!!cfg[l.id]}
            onConfigToggle={() => BulwarkStore.toggleLayer(l.id)} />
        ))}
        <div className="label" style={{marginTop: 14, marginBottom: 6, fontSize: 10}}>Sanitizer sub-options</div>
        {subConfigToggles.map(t => (
          <ConfigConfigToggleRow key={t.id} name={t.name} desc={t.desc} on={!!cfg[t.id]}
            onConfigToggle={() => BulwarkStore.toggleLayer(t.id)} compact />
        ))}
      </div>
    </div>
  );
}

function ConfigConfigToggleRow({ name, desc, on, onConfigToggle, compact }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 16,
      padding: compact ? '8px 0' : '12px 0',
      borderBottom: '1px solid var(--hairline)',
    }}>
      <div style={{flex: 1}}>
        <div style={{fontSize: compact ? 12.5 : 13.5, fontWeight: 500}}>{name}</div>
        <div className="dim" style={{fontSize: 11.5, marginTop: 2}}>{desc}</div>
      </div>
      <ConfigToggle on={on} onConfigToggle={onConfigToggle} />
    </div>
  );
}

function ConfigToggle({ on, onConfigToggle, disabled }) {
  return (
    <button onClick={onConfigToggle} disabled={disabled} aria-pressed={on} style={{
      width: 36, height: 20, padding: 2, borderRadius: 999, border: 0,
      background: on ? 'var(--accent)' : 'var(--surface-2)',
      opacity: disabled ? 0.5 : 1,
      cursor: disabled ? 'not-allowed' : 'pointer',
      transition: 'background 0.15s',
      position: 'relative',
    }}>
      <span style={{
        position: 'absolute', top: 2, left: on ? 18 : 2,
        width: 16, height: 16, borderRadius: '50%', background: 'white',
        transition: 'left 0.15s',
      }}/>
    </button>
  );
}

// G-UI-CONFIG-DEBERTA-001 / G-UI-CONFIG-PROMPTGUARD-001.
function DetectorCard({ store, id, title, subtitle, mandatory }) {
  const det = (store.detectorStatus && store.detectorStatus[id]) || { status: 'available' };
  const isActive = store.integrations[id] === 'active';
  const loading = det.status === 'loading';
  const error = det.status === 'error';
  const ready = det.status === 'ready' || isActive;

  let pill, pillColor;
  if (loading) { pill = 'Loading weights…'; pillColor = 'warn'; }
  else if (error) { pill = 'Error'; pillColor = 'bad'; }
  else if (ready) { pill = 'Ready'; pillColor = 'ok'; }
  else { pill = 'Disabled'; pillColor = 'dim'; }

  return (
    <div className="card" style={{padding: 0}}>
      <div style={{padding: '16px 20px', borderBottom: '1px solid var(--hairline)'}}>
        <div style={{display: 'flex', alignItems: 'flex-start', gap: 12}}>
          <div style={{flex: 1}}>
            <div className="label">Step 2{mandatory ? '' : ' (optional)'}</div>
            <div style={{fontSize: 17, fontWeight: 600, marginTop: 2}}>{title}</div>
            <div className="dim" style={{fontSize: 12, marginTop: 4}}>{subtitle}</div>
          </div>
          <StatusPill kind={pillColor === 'dim' ? 'warn' : pillColor} label={pill} compact />
        </div>
      </div>
      <div style={{padding: '14px 20px'}}>
        {error && (
          <div style={{padding: 10, background: 'var(--red-soft)', color: 'var(--red)', borderRadius: 6, fontSize: 12, marginBottom: 10}}>
            {det.message || 'The detector failed to load. Check the server log.'}
          </div>
        )}
        <div style={{display: 'flex', alignItems: 'center', gap: 12}}>
          <div className="dim" style={{fontSize: 12, flex: 1}}>
            {mandatory
              ? 'DeBERTa runs on every /v1/clean request. Inputs over 512 tokens are chunked across the model window (ADR-032).'
              : 'When enabled, PromptGuard runs alongside DeBERTa and can independently block the request.'}
          </div>
          {!mandatory && (
            <button className="btn"
              onClick={() => BulwarkStore.setIntegration(id, isActive ? 'available' : 'active')}
              disabled={loading}>
              {loading ? 'Loading…' : (isActive ? 'Disable' : 'Enable')}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function GuardPatternsCard({ store }) {
  const patterns = Array.isArray(store.guardPatterns) ? store.guardPatterns : [];
  return (
    <div className="card" style={{padding: 0}}>
      <div style={{padding: '16px 20px', borderBottom: '1px solid var(--hairline)'}}>
        <div className="label">Reference</div>
        <div style={{fontSize: 17, fontWeight: 600, marginTop: 2}}>
          Guard patterns <span className="mono dim" style={{marginLeft: 8, fontSize: 12}}>{patterns.length}</span>
        </div>
        <div className="dim" style={{fontSize: 12, marginTop: 4}}>
          Regex patterns applied by <span className="mono">/v1/guard</span> to caller-produced LLM output.
          Edit via <span className="mono">bulwark-config.yaml</span>.
        </div>
      </div>
      <div style={{padding: '14px 20px'}}>
        {patterns.length === 0 ? (
          <div className="empty-slate" style={{padding: 20, border: '1px dashed var(--border)', borderRadius: 8, fontSize: 12}}>
            No guard patterns configured.
          </div>
        ) : (
          <div style={{background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 8, padding: 4, fontFamily: 'var(--font-mono)', fontSize: 11.5, maxHeight: 240, overflow: 'auto'}}>
            {patterns.map((p, i) => (
              <div key={i} style={{display: 'flex', alignItems: 'center', gap: 10, padding: '7px 10px', borderBottom: i < patterns.length - 1 ? '1px solid var(--hairline)' : 'none'}}>
                <span style={{flex: 1, color: 'var(--amber)', wordBreak: 'break-all'}}>{p}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

Object.assign(window, { PageConfigure });
