// Leak Detection page (v2.0.0, ADR-031).
//
// Canaries are output-side only. Place one in your LLM's system prompt or
// tool context, run the LLM, then POST /v1/guard on its output. Bulwark
// matches the canary string and flags exfiltration.

function PageLeakDetection({ store }) {
  return (
    <div data-page="leak-detection" style={{padding: '28px 28px 60px', maxWidth: 1100, margin: '0 auto'}}>
      <div style={{marginBottom: 24}}>
        <div className="label">Output side</div>
        <h2 className="display" style={{fontSize: 28, fontWeight: 600, letterSpacing: '-0.01em', marginTop: 4}}>Leak detection</h2>
        <div className="dim" style={{fontSize: 13, marginTop: 4, maxWidth: 680}}>
          Canaries are sentinel strings you embed in your LLM's system prompt or tool context.
          After running your LLM, call <span className="mono">POST /v1/guard</span> with the LLM's
          output — if a canary appears, Bulwark flags it as exfiltration. These tokens are
          never checked on input to <span className="mono">/v1/clean</span>.
        </div>
      </div>

      <div style={{display: 'flex', flexDirection: 'column', gap: 24}}>
        <CanaryPane store={store} />
        <GuardPatternsCard store={store} />
      </div>
    </div>
  );
}

function GuardPatternsCard({ store }) {
  const patterns = Array.isArray(store.guardPatterns) ? store.guardPatterns : [];
  return (
    <div className="card" style={{padding: 0}}>
      <div style={{padding: '16px 20px', borderBottom: '1px solid var(--hairline)'}}>
        <div className="label">Output checks</div>
        <div style={{fontSize: 17, fontWeight: 600, marginTop: 2}}>
          Guard patterns <span className="mono dim" style={{marginLeft: 8, fontSize: 12}}>{patterns.length}</span>
        </div>
        <div className="dim" style={{fontSize: 12, marginTop: 4}}>
          Regex patterns applied by <span className="mono">/v1/guard</span> alongside canary checks.
          Edit via <span className="mono">bulwark-config.yaml</span>.
        </div>
      </div>
      <div style={{padding: '14px 20px'}}>
        {patterns.length === 0 ? (
          <div className="empty-slate" style={{padding: 20, border: '1px dashed var(--border)', borderRadius: 8, fontSize: 12}}>
            No guard patterns configured.
          </div>
        ) : (
          <div style={{background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 8, padding: 4, fontFamily: 'var(--font-mono)', fontSize: 11.5, maxHeight: 280, overflow: 'auto'}}>
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

// G-CANARY-011: add/remove form + live list via POST/DELETE /api/canaries.
function CanaryPane({ store }) {
  const tokens = store.canaryTokens && typeof store.canaryTokens === 'object' ? store.canaryTokens : {};
  const entries = Object.entries(tokens);
  const [label, setLabel] = React.useState('');
  const [shape, setShape] = React.useState('aws');
  const [token, setToken] = React.useState('');
  const [useLiteral, setUseLiteral] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState('');

  async function addCanary(e) {
    if (e) e.preventDefault();
    setError('');
    if (!label.trim()) { setError('Label is required.'); return; }
    const body = { label: label.trim() };
    if (useLiteral) {
      if (token.length < 8) { setError('Token must be at least 8 characters.'); return; }
      body.token = token;
    } else {
      body.shape = shape;
    }
    setBusy(true);
    try {
      const resp = await fetch('/api/canaries', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!resp.ok) {
        const j = await resp.json().catch(() => ({}));
        setError(j.error || `${resp.status} ${resp.statusText}`);
        return;
      }
      setLabel(''); setToken(''); setUseLiteral(false);
      BulwarkStore.refreshConfig();
    } finally { setBusy(false); }
  }

  async function removeCanary(key) {
    setBusy(true);
    try {
      await fetch('/api/canaries/' + encodeURIComponent(key), { method: 'DELETE' });
      BulwarkStore.refreshConfig();
    } finally { setBusy(false); }
  }

  const shapeHints = {
    aws: 'AKIA + 16 uppercase alphanumeric',
    bearer: 'tk_live_ + 32 hex chars',
    password: '18+ chars, upper + lower + digit + symbol',
    url: 'https://admin-xxx.infra.internal/v1/keys/…',
    mongo: 'mongodb+srv://svc_xxx:pw@cluster…',
  };

  return (
    <div className="card" style={{padding: 0}}>
      <div style={{padding: '16px 20px', borderBottom: '1px solid var(--hairline)'}}>
        <div style={{display: 'flex', alignItems: 'center', gap: 16}}>
          <div style={{flex: 1}}>
            <div className="label">Canary tokens</div>
            <div style={{fontSize: 17, fontWeight: 600, marginTop: 2}}>
              Active tokens <span className="mono dim" style={{marginLeft: 8, fontSize: 12}}>{entries.length}</span>
            </div>
          </div>
        </div>
      </div>
      <div style={{padding: '14px 20px 20px'}}>
        {entries.length === 0 ? (
          <div className="empty-slate" style={{padding: 24, border: '1px dashed var(--border)', borderRadius: 8, fontSize: 12, marginBottom: 16, textAlign: 'center'}}>
            No canaries yet. Add one below — Bulwark will generate a value matching the shape you pick, or you can paste a literal string.
          </div>
        ) : (
          <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 8, marginBottom: 16}}>
            {entries.map(([src, tok]) => (
              <div key={src} style={{padding: 12, background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 8, position: 'relative'}}>
                <button type="button" onClick={() => removeCanary(src)} disabled={busy}
                  aria-label={`Remove canary ${src}`}
                  style={{position: 'absolute', top: 6, right: 8, background: 'transparent', border: 0, color: 'var(--text-2)', cursor: 'pointer', fontSize: 14}}>×</button>
                <div className="label" style={{marginBottom: 4}}>{src}</div>
                <div className="mono" style={{fontSize: 11, color: 'var(--amber)', wordBreak: 'break-all', paddingRight: 16}}>{tok}</div>
              </div>
            ))}
          </div>
        )}

        <form onSubmit={addCanary} style={{padding: 14, border: '1px solid var(--border)', borderRadius: 8, background: 'var(--bg-1)'}}>
          <div className="label" style={{marginBottom: 10}}>Add canary</div>
          <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10}}>
            <label style={{display: 'flex', flexDirection: 'column', gap: 4}}>
              <span className="dim" style={{fontSize: 11}}>Label</span>
              <input type="text" value={label} onChange={(e) => setLabel(e.target.value)}
                placeholder="e.g. prod_admin_url" maxLength={64}
                style={{padding: '6px 8px', background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-1)', fontSize: 12}}/>
            </label>
            <label style={{display: 'flex', flexDirection: 'column', gap: 4}}>
              <span className="dim" style={{fontSize: 11}}>
                Source <button type="button" onClick={() => setUseLiteral(v => !v)}
                  style={{marginLeft: 6, background: 'transparent', border: 0, color: 'var(--accent-ink)', cursor: 'pointer', fontSize: 11, textDecoration: 'underline'}}>
                  {useLiteral ? 'use generator' : 'paste literal'}
                </button>
              </span>
              {useLiteral ? (
                <input type="text" value={token} onChange={(e) => setToken(e.target.value)}
                  placeholder="Paste a canary string (≥ 8 chars)"
                  style={{padding: '6px 8px', background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-1)', fontSize: 12}}/>
              ) : (
                <select value={shape} onChange={(e) => setShape(e.target.value)}
                  style={{padding: '6px 8px', background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-1)', fontSize: 12}}>
                  {Object.keys(shapeHints).map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              )}
            </label>
          </div>
          {!useLiteral && (
            <div className="dim" style={{fontSize: 11, marginBottom: 10}}>
              Generates: {shapeHints[shape]}
            </div>
          )}
          {error && (
            <div style={{fontSize: 11, color: 'var(--red)', marginBottom: 10}}>{error}</div>
          )}
          <button type="submit" disabled={busy}
            style={{padding: '6px 14px', background: 'var(--accent-ink)', color: 'var(--bg-0)', border: 0, borderRadius: 6, cursor: busy ? 'wait' : 'pointer', fontSize: 12, fontWeight: 600}}>
            {busy ? 'Saving…' : 'Add canary'}
          </button>
        </form>
      </div>
    </div>
  );
}

Object.assign(window, { PageLeakDetection });
