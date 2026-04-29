// Test page — split view: payload library, runner, live trace. Red team below.
// Wired to real endpoints (Stage 8).

function PageTest({ store }) {
  const [payload, setPayload] = React.useState('');
  const [category, setCategory] = React.useState('all');
  const [trace, setTrace] = React.useState(null);
  const [running, setRunning] = React.useState(false);

  // Events page's "Replay in Test" dispatches bulwark:goto with {payload}.
  // Capture it and pre-fill the editor.
  React.useEffect(() => {
    const onFocus = (e) => {
      const p = e.detail && e.detail.payload;
      if (typeof p === 'string' && p) setPayload(p);
    };
    window.addEventListener('bulwark:focus', onFocus);
    // Also catch the direct goto event since Events dispatches on that channel.
    const onGoto = (e) => {
      const p = e.detail && e.detail.payload;
      if (typeof p === 'string' && p) setPayload(p);
    };
    window.addEventListener('bulwark:goto', onGoto);
    return () => {
      window.removeEventListener('bulwark:focus', onFocus);
      window.removeEventListener('bulwark:goto', onGoto);
    };
  }, []);

  const categories = [
    { id: 'all', label: 'All' },
    { id: 'sanitizer', label: 'Sanitizer' },
    { id: 'boundary', label: 'Boundary' },
    { id: 'bridge', label: 'Bridge' },
  ];
  const presets = category === 'all' ? store.presets : store.presets.filter(p => p.family === category);

  async function runPipeline() {
    if (!payload.trim() || running) return;
    setRunning(true);
    setTrace({ steps: [], status: 'running' });
    const res = await BulwarkStore.runClean(payload, 'dashboard');
    const rawTrace = Array.isArray(res.trace) ? res.trace : [];
    const steps = rawTrace.map((t) => ({
      id: _normalizeTraceLayer(t.layer || t.id || ''),
      verdict: t.verdict || 'passed',
      detail: t.detail || '',
      duration_ms: t.duration_ms,
    }));
    // Blocked pipelines return 422 with blocked=true in the body.
    const blocked = res.blocked === true || res.httpStatus === 422;
    const blockAt = blocked
      ? (steps.find(s => s.verdict === 'blocked')?.id || (res.error ? 'error' : null))
      : null;
    const status = res.error && !blocked ? 'error'
                 : blocked ? 'blocked'
                 : 'passed';
    setTrace({
      steps,
      status,
      blockAt,
      llm_mode: res.llm_mode || '',
      error: res.error || null,
    });
    setRunning(false);
  }

  return (
    <div style={{padding: '28px 28px 60px', maxWidth: 1320, margin: '0 auto'}}>
      <SectionTitle eyebrow="Red team" title="Test your defenses" size="lg"
        action={<span className="dim" style={{fontSize: 12.5}}>Paste untrusted content, select a preset, or generate payloads</span>} />

      <div style={{display: 'grid', gridTemplateColumns: '260px 1fr 1fr', gap: 18, alignItems: 'start', marginBottom: 28}}>
        {/* Payload library */}
        <div>
          <div className="label" style={{marginBottom: 10}}>Payload library</div>
          <div style={{display: 'flex', gap: 4, marginBottom: 10, flexWrap: 'wrap'}}>
            {categories.map(c => (
              <button key={c.id} onClick={() => setCategory(c.id)} style={{
                fontSize: 11.5, padding: '4px 9px', borderRadius: 6,
                background: category === c.id ? 'var(--accent-soft)' : 'var(--surface-2)',
                color: category === c.id ? 'var(--accent)' : 'var(--text-dim)',
                border: '1px solid ' + (category === c.id ? 'var(--accent-line)' : 'var(--border)'),
                fontWeight: 500,
              }}>{c.label}</button>
            ))}
          </div>
          <div className="card" style={{padding: 0, overflow: 'hidden'}}>
            {presets.length === 0 ? (
              <div className="empty-slate" style={{padding: 20, fontSize: 12}}>
                {store.presets.length === 0 ? 'Loading presets…' : 'No presets in this category.'}
              </div>
            ) : presets.map((p, i) => (
              <button key={p.id} onClick={() => setPayload(p.payload)} style={{
                width: '100%', textAlign: 'left', padding: '12px 14px',
                borderBottom: i < presets.length - 1 ? '1px solid var(--hairline)' : 'none',
                background: 'transparent',
              }}
              onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-2)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}>
                <div style={{fontSize: 12.5, fontWeight: 500, marginBottom: 2}}>{p.name}</div>
                <div className="dim mono" style={{fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>{p.payload.slice(0, 48)}…</div>
              </button>
            ))}
          </div>
        </div>

        {/* Payload editor */}
        <div>
          <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10}}>
            <div className="label">Untrusted content</div>
            <div className="dim mono" style={{fontSize: 11}}>{payload.length} chars</div>
          </div>
          <div className="card" style={{padding: 0, overflow: 'hidden', borderColor: payload ? 'var(--border-2)' : 'var(--border)'}}>
            <textarea value={payload} onChange={e => setPayload(e.target.value)}
              placeholder="Paste untrusted content here, or select a preset →"
              style={{
                width: '100%', minHeight: 220, padding: 16, background: 'transparent',
                border: 'none', color: 'var(--text)', fontFamily: 'var(--font-mono)',
                fontSize: 12.5, resize: 'vertical', outline: 'none',
              }}/>
            <div style={{padding: '10px 14px', borderTop: '1px solid var(--hairline)', background: 'var(--bg-2)', display: 'flex', alignItems: 'center', gap: 8}}>
              <button className="btn btn-primary" onClick={runPipeline} disabled={!payload.trim() || running}>
                {running ? <><span style={{
                  width: 10, height: 10, border: '1.5px solid var(--accent-ink-soft)',
                  borderTopColor: 'var(--accent-ink)', borderRadius: '50%',
                  display: 'inline-block', animation: 'spin 0.8s linear infinite',
                }}/> Running…</> : <>▶ Run through pipeline</>}
              </button>
              <button className="btn" onClick={() => { setPayload(''); setTrace(null); }}>Clear</button>
            </div>
          </div>
        </div>

        {/* Live trace */}
        <div>
          <div className="label" style={{marginBottom: 10}}>Pipeline trace</div>
          <div className="card" style={{padding: 18, minHeight: 260}}>
            {!trace && <div className="empty-slate" style={{padding: '40px 0'}}>Run a test to see the pipeline trace.</div>}
            {trace && <TraceView trace={trace}/>}
          </div>
        </div>
      </div>

      {/* Red team */}
      <RedTeam store={store}/>
    </div>
  );
}

// Map backend trace .layer values to the display layer ids used by LAYERS.
// Mirrors _normalizeEventLayer in data.jsx — kept local to avoid coupling.
function _normalizeTraceLayer(raw) {
  if (!raw) return 'sanitizer';
  if (raw.startsWith && raw.startsWith('detection:')) return 'detection';
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

function TraceView({ trace }) {
  return (
    <div>
      {trace.steps.length === 0 && trace.status === 'running' && (
        <div className="dim" style={{fontSize: 12, padding: 20}}>Running…</div>
      )}
      {trace.steps.map((step, i) => {
        const layer = LAYERS.find(l => l.id === step.id) || { name: step.id };
        const dotColor = step.verdict === 'blocked' ? 'var(--red)' : (step.verdict === 'modified' ? 'var(--amber)' : 'var(--green)');
        return (
          <div key={step.id + i} style={{display: 'flex', gap: 12, paddingBottom: 12}}>
            <div style={{display: 'flex', flexDirection: 'column', alignItems: 'center'}}>
              <div style={{
                width: 14, height: 14, borderRadius: '50%',
                background: dotColor, marginTop: 2,
                boxShadow: `0 0 0 3px color-mix(in srgb, ${dotColor} 13%, transparent)`,
              }}/>
              {i < trace.steps.length - 1 && <div style={{width: 1.5, flex: 1, background: 'var(--border)', marginTop: 4}}/>}
            </div>
            <div style={{flex: 1, paddingBottom: 4}}>
              <div style={{display: 'flex', alignItems: 'center', gap: 8}}>
                <span style={{fontSize: 13, fontWeight: 600}}>{layer.name}</span>
                <Verdict v={step.verdict}/>
              </div>
              <div className="dim" style={{fontSize: 12, marginTop: 2}}>{step.detail}</div>
            </div>
          </div>
        );
      })}
      {trace.status === 'running' && trace.steps.length > 0 && (
        <div className="dim" style={{fontSize: 12, paddingLeft: 26}}>…</div>
      )}
      {trace.status === 'error' && (
        <div style={{marginTop: 10, padding: '10px 12px', borderRadius: 8,
          background: 'var(--red-soft)', border: '1px solid var(--red-line)',
          color: 'var(--red)', fontSize: 12.5, fontWeight: 600}}>
          ✗ Error: {trace.error || 'Pipeline call failed'}
        </div>
      )}
      {(trace.status === 'blocked' || trace.status === 'passed') && (
        <div style={{marginTop: 10, padding: '10px 12px', borderRadius: 8,
          background: trace.status === 'blocked' ? 'var(--red-soft)' : 'var(--green-soft)',
          border: '1px solid ' + (trace.status === 'blocked' ? 'var(--red-line)' : 'var(--green-line)'),
          color: trace.status === 'blocked' ? 'var(--red)' : 'var(--green)',
          fontSize: 12.5, fontWeight: 600}}>
          {trace.status === 'blocked' ? `✗ Blocked${trace.blockAt ? ' at ' + trace.blockAt : ''}` : '✓ Passed all checks'}
        </div>
      )}
    </div>
  );
}

function RedTeam({ store }) {
  // Load real tiers + reports on mount.
  React.useEffect(() => {
    BulwarkStore.fetchRedteamTiers();
    BulwarkStore.fetchRedteamReports();
  }, []);

  // When a run completes (state.running goes from truthy → null), refresh the
  // reports list so the new entry appears.
  const wasRunning = React.useRef(!!store.running);
  React.useEffect(() => {
    if (wasRunning.current && !store.running) {
      BulwarkStore.fetchRedteamReports();
    }
    wasRunning.current = !!store.running;
  }, [store.running]);

  const tiersData = store.redteamTiers || { garak_installed: false, tiers: [] };
  const tiers = Array.isArray(tiersData.tiers) ? tiersData.tiers : [];
  const [tier, setTier] = React.useState('');

  // Default to the first tier once they load.
  React.useEffect(() => {
    if (!tier && tiers.length > 0) setTier(tiers[0].id);
  }, [tiers.length]);

  const reports = Array.isArray(store.redteamReports) ? store.redteamReports : [];

  return (
    <div>
      <div style={{margin: '24px 0 16px', display: 'flex', alignItems: 'center', gap: 14}}>
        <div style={{flex: 1, height: 1, background: 'var(--border)'}}/>
        <div className="label" style={{margin: 0}}>Automated red-teaming</div>
        <div style={{flex: 1, height: 1, background: 'var(--border)'}}/>
      </div>

      <div className="card" style={{padding: 24}}>
        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16}}>
          <div>
            <div style={{fontSize: 16, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 8}}>
              Production Red Team
              {tiersData.garak_installed ? (
                <span className="pill" style={{fontSize: 10.5}}>Garak{tiersData.garak_version ? ` v${tiersData.garak_version}` : ''}</span>
              ) : (
                <span className="pill warn" style={{fontSize: 10.5}}>Garak not installed</span>
              )}
            </div>
            <div className="dim" style={{fontSize: 12.5, marginTop: 4, maxWidth: 540}}>
              Sends Garak's attack payloads through your real Bulwark pipeline with the configured LLM backend.
            </div>
          </div>
          {store.running && <button className="btn btn-danger" onClick={() => BulwarkStore.stopRun()}>⬛ Stop</button>}
        </div>

        {tiers.length === 0 ? (
          <div className="empty-slate" style={{padding: 20, border: '1px dashed var(--border)', borderRadius: 8, fontSize: 12, marginBottom: 16}}>
            {tiersData.garak_installed
              ? 'Loading tiers…'
              : 'Install garak to enable red-team scans. See the integration docs.'}
          </div>
        ) : (
          <div style={{display: 'grid', gridTemplateColumns: `repeat(${Math.min(tiers.length, 5)}, 1fr)`, gap: 10, marginBottom: 16}}>
            {tiers.map(t => {
              const selected = tier === t.id;
              const count = t.probe_count || 0;
              return (
                <button key={t.id} onClick={() => setTier(t.id)} style={{
                  padding: 14, borderRadius: 10, textAlign: 'left',
                  background: selected ? 'var(--accent-soft)' : 'var(--bg-2)',
                  border: '1px solid ' + (selected ? 'var(--accent-line)' : 'var(--border)'),
                  transition: 'all 0.15s',
                }}>
                  <div style={{fontSize: 12.5, fontWeight: 600, color: selected ? 'var(--accent)' : 'var(--text)'}}>{t.name}</div>
                  <div className="tabular" style={{fontSize: 22, fontWeight: 700, marginTop: 4, color: selected ? 'var(--accent)' : 'var(--text)', letterSpacing: '-0.02em'}}>
                    {count.toLocaleString()} <span className="dim" style={{fontSize: 11, fontWeight: 500}}>probes</span>
                  </div>
                  <div className="dim" style={{fontSize: 11, marginTop: 6, lineHeight: 1.4}}>{t.description}</div>
                </button>
              );
            })}
          </div>
        )}

        {store.running ? (
          <RunProgress running={store.running} />
        ) : (
          <button className="btn btn-primary" style={{width: '100%', justifyContent: 'center', padding: '10px'}}
            disabled={!tier || !tiersData.garak_installed}
            onClick={() => BulwarkStore.startRun(tier)}>
            ▶ Run {tiers.find(t => t.id === tier)?.name || 'scan'}
          </button>
        )}

        <div style={{marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border)'}}>
          <div className="label" style={{marginBottom: 10}}>Past reports</div>
          <ReportsList reports={reports} />
        </div>
      </div>
    </div>
  );
}

function RunProgress({ running }) {
  const pct = running.total > 0 ? Math.floor((running.progress / running.total) * 100) : 0;
  return (
    <div style={{padding: 14, background: 'var(--bg-2)', borderRadius: 10, border: '1px solid var(--blue-line)'}}>
      <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8}}>
        <span className="mono tabular" style={{fontSize: 13, color: 'var(--blue)'}}>
          {Number(running.progress || 0).toLocaleString()} / {Number(running.total || 0).toLocaleString()} probes
        </span>
        <span className="dim" style={{fontSize: 12}}>
          {running.total > 0 ? `${pct}%` : 'Starting…'}
        </span>
      </div>
      <div style={{height: 6, background: 'var(--surface-3)', borderRadius: 3, overflow: 'hidden'}}>
        <div style={{
          height: '100%', width: (running.total > 0 ? pct : 0) + '%',
          background: 'var(--accent)', borderRadius: 3, transition: 'width 0.3s',
        }}/>
      </div>
    </div>
  );
}

function ReportsList({ reports }) {
  if (reports.length === 0) {
    return (
      <div className="empty-slate" style={{padding: 16, fontSize: 12, border: '1px dashed var(--border)', borderRadius: 8}}>
        No reports yet. Run a scan above to generate one.
      </div>
    );
  }
  return (
    <div style={{display: 'flex', flexDirection: 'column'}}>
      {reports.map((r, i) => (
        <ReportRow key={r.filename || i} report={r} last={i === reports.length - 1} />
      ))}
    </div>
  );
}

function ReportRow({ report, last }) {
  // defense_rate from the backend is a decimal (0.0–1.0). Round to 2 decimals
  // for display. Guard against the "100% but there was a hijack" mirage —
  // cap at 99.99% when any probe hijacked the LLM (matches G-REDTEAM-SCORE-007).
  let score = null;
  if (typeof report.defense_rate === 'number') {
    const hijacked = report.hijacked || 0;
    const raw = report.defense_rate * 100;
    score = hijacked > 0 && raw >= 100 ? 99.99 : Math.round(raw * 100) / 100;
  }
  const scoreColor = score === null ? 'var(--text-dim)'
                   : score >= 95 ? 'var(--green)'
                   : score >= 50 ? 'var(--amber)'
                                 : 'var(--red)';
  const tier = report.tier || 'scan';
  const probeCount = report.total || report.probe_count || '?';
  const errorCount = report.errors || 0;
  const duration = report.duration_s ? _fmtDuration(report.duration_s) : '';
  // ADR-038: surface error count when present so an inflated defense_rate
  // from network failures or 5xxs is visible at a glance.
  const errorSuffix = errorCount > 0 ? `, ${errorCount} errors` : '';
  const label = `${tier} — ${probeCount} probes${errorSuffix}${duration ? ', ' + duration : ''}`;
  const when = _fmtDate(report.completed_at || report.saved_at || report.created_at);

  async function onRetest() {
    if (!report.filename) return;
    await BulwarkStore.retestReport(report.filename);
  }
  function onDownload() {
    if (!report.filename) return;
    window.open(`/api/redteam/reports/${encodeURIComponent(report.filename)}`, '_blank');
  }

  return (
    <div style={{
      display: 'grid', gridTemplateColumns: '60px 1fr auto auto', gap: 14,
      padding: '10px 2px', borderBottom: last ? 'none' : '1px solid var(--hairline)',
      alignItems: 'center',
    }}>
      <span className="tabular" style={{fontWeight: 700, fontSize: 14, color: scoreColor}}>
        {score !== null ? `${score}%` : '—'}
      </span>
      <span style={{fontSize: 13, color: 'var(--text-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>{label}</span>
      <span className="dim mono" style={{fontSize: 11.5}}>{when}</span>
      <div style={{display: 'flex', gap: 6}}>
        <button className="btn" style={{fontSize: 11.5, padding: '4px 10px'}} onClick={onRetest}
          disabled={!report.filename}>Retest</button>
        <button className="btn" style={{fontSize: 11.5, padding: '4px 10px'}} onClick={onDownload}
          disabled={!report.filename}>JSON</button>
      </div>
    </div>
  );
}

function _fmtDuration(s) {
  if (s < 60) return `${Math.round(s)}s`;
  const m = Math.floor(s / 60);
  const rem = Math.round(s % 60);
  return `${m}m ${rem}s`;
}

function _fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

Object.assign(window, { PageTest, TraceView, ReportsList, RunProgress });
