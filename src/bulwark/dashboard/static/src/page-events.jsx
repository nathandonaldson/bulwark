// Events page — filter bar, sparkline header, expandable rows.
// Wired to real events from data.jsx / /api/events (Stage 3).

// Pure helpers — exported so tests can drive the filtering + empty-state logic
// without a DOM. Contract: spec/contracts/dashboard_ui.yaml (G-UI-EMPTY-*).

function isAnyFilterActive(filter, layerFilter, search) {
  return filter !== 'all' || layerFilter !== 'all' || Boolean(search && search.trim());
}

function filterEvents(events, { filter, layerFilter, search }) {
  const q = (search || '').trim().toLowerCase();
  return events.filter((e) => {
    if (filter !== 'all' && e.verdict !== filter) return false;
    if (layerFilter !== 'all' && e.layer !== layerFilter) return false;
    if (q && !(
      (e.detail || '').toLowerCase().includes(q) ||
      (e.source || '').toLowerCase().includes(q)
    )) return false;
    return true;
  });
}

function PageEvents({ store }) {
  const [filter, setFilter] = React.useState('all');
  const [layerFilter, setLayerFilter] = React.useState('all');
  const [search, setSearch] = React.useState('');
  const [expanded, setExpanded] = React.useState(null);

  const clearFilters = () => { setFilter('all'); setLayerFilter('all'); setSearch(''); };

  const filters = [
    { id: 'all',      label: 'All',      count: store.events.length },
    { id: 'blocked',  label: 'Blocked',  count: store.events.filter(e => e.verdict === 'blocked').length },
    { id: 'modified', label: 'Modified', count: store.events.filter(e => e.verdict === 'modified').length },
    { id: 'passed',   label: 'Passed',   count: store.events.filter(e => e.verdict === 'passed').length },
  ];
  const layerFilters = [
    { id: 'all', label: 'All layers' },
    ...LAYERS.map(l => ({ id: l.id, label: l.name })),
  ];

  const filtered = filterEvents(store.events, { filter, layerFilter, search });

  // Timeline — event count by 5-min bucket, last 2h
  const now = Date.now();
  const buckets = Array.from({length: 24}, (_, i) => {
    const bStart = now - (24 - i) * 5 * 60 * 1000;
    const bEnd = bStart + 5 * 60 * 1000;
    return store.events.filter(e => e.ts >= bStart && e.ts < bEnd).length;
  });
  const blockedBuckets = Array.from({length: 24}, (_, i) => {
    const bStart = now - (24 - i) * 5 * 60 * 1000;
    const bEnd = bStart + 5 * 60 * 1000;
    return store.events.filter(e => e.ts >= bStart && e.ts < bEnd && e.verdict === 'blocked').length;
  });

  return (
    <div style={{padding: '28px 28px 60px', maxWidth: 1320, margin: '0 auto'}}>
      <SectionTitle eyebrow="Observability" title="Event stream" size="lg" />

      {/* Timeline header */}
      <div className="card" style={{padding: 20, marginBottom: 20, display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 24, alignItems: 'center'}}>
        <div>
          <div className="label">Last 2 hours</div>
          <div className="tabular" style={{fontSize: 28, fontWeight: 600, letterSpacing: '-0.02em', marginTop: 2}}>
            {buckets.reduce((a,b) => a+b, 0)} <span className="dim" style={{fontSize: 13, fontWeight: 500}}>events</span>
          </div>
          <div className="dim" style={{fontSize: 12, marginTop: 2}}>
            <span style={{color: 'var(--red)'}}>{blockedBuckets.reduce((a,b)=>a+b,0)} blocked</span> · <span>{filtered.length} in view</span>
          </div>
        </div>
        <div style={{position: 'relative'}}>
          <svg width="100%" height="60" viewBox="0 0 600 60" preserveAspectRatio="none">
            {buckets.map((v, i) => {
              const max = Math.max(1, ...buckets);
              const h = (v / max) * 50;
              return <rect key={i} x={i * 25 + 2} y={56 - h} width={20} height={h} fill="var(--accent)" opacity="0.75" rx="1"/>;
            })}
            {blockedBuckets.map((v, i) => {
              const max = Math.max(1, ...buckets);
              const h = (v / max) * 50;
              return v > 0 ? <rect key={i} x={i * 25 + 2} y={56 - h} width={20} height={h} fill="var(--red)" rx="1"/> : null;
            })}
          </svg>
        </div>
      </div>

      {/* Filters */}
      <div style={{display: 'flex', gap: 10, marginBottom: 14, alignItems: 'center', flexWrap: 'wrap'}}>
        <div style={{display: 'flex', gap: 4, background: 'var(--surface-2)', padding: 3, borderRadius: 9, border: '1px solid var(--border)'}}>
          {filters.map(f => (
            <button key={f.id} onClick={() => setFilter(f.id)} style={{
              padding: '6px 12px', borderRadius: 7, fontSize: 12.5, fontWeight: 500,
              background: filter === f.id ? 'var(--bg-2)' : 'transparent',
              color: filter === f.id ? 'var(--text)' : 'var(--text-dim)',
              border: filter === f.id ? '1px solid var(--border)' : '1px solid transparent',
              display: 'flex', alignItems: 'center', gap: 7,
            }}>
              {f.label}
              <span className="mono" style={{
                fontSize: 10.5, padding: '1px 5px', borderRadius: 4,
                background: filter === f.id ? 'var(--surface-3)' : 'transparent', color: 'var(--text-dim)',
              }}>{f.count}</span>
            </button>
          ))}
        </div>
        <select className="input" style={{width: 160, padding: '6px 10px', fontSize: 12.5}}
          value={layerFilter} onChange={e => setLayerFilter(e.target.value)}>
          {layerFilters.map(l => <option key={l.id} value={l.id}>{l.label}</option>)}
        </select>
        <div style={{position: 'relative', flex: '1 1 240px', maxWidth: 320}}>
          <svg width="14" height="14" viewBox="0 0 16 16" style={{position: 'absolute', left: 10, top: 9, color: 'var(--text-dim)'}}>
            <circle cx="7" cy="7" r="4.5" fill="none" stroke="currentColor" strokeWidth="1.4"/><path d="M10.5 10.5l3 3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
          </svg>
          <input className="input" placeholder="Search details, source…"
            value={search} onChange={e => setSearch(e.target.value)}
            style={{paddingLeft: 30, fontSize: 12.5, padding: '6px 10px 6px 30px'}}/>
        </div>
      </div>

      {/* Table */}
      <div className="card" style={{padding: 0, overflow: 'hidden'}}>
        <div style={{
          display: 'grid', gridTemplateColumns: '100px 120px 90px 180px 1fr auto',
          padding: '10px 20px', borderBottom: '1px solid var(--border)',
          background: 'var(--bg-2)',
        }}>
          {['Time','Layer','Verdict','Source','Detail','Duration'].map(h =>
            <div key={h} className="label">{h}</div>)}
        </div>
        <div style={{maxHeight: 540, overflow: 'auto'}}>
          {filtered.length === 0 && (
            <EventsEmptyState
              hasAnyEvents={store.events.length > 0}
              anyFilterActive={isAnyFilterActive(filter, layerFilter, search)}
              onClearFilters={clearFilters}
              status={computeStatusPill(store)}
            />
          )}
          {filtered.slice(0, 120).map(e => (
            <EventRow key={e.id}
              event={e}
              expanded={expanded === e.id}
              onToggle={() => setExpanded(expanded === e.id ? null : e.id)}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

// Empty-state panel. Branches per STATES.md §4 / G-UI-EMPTY-001,002 and
// inherits the status-pill state machine so the no-events copy tells the
// truth when /v1/clean is in fail-closed (ADR-040) or sanitize-only
// (ADR-038) mode instead of cheerfully claiming "Your pipeline is running".
// - `no-events`:      fresh install, no filter active → nudge the user to Run a test
// - `filter-miss`:    events exist but current filter matches none → Clear filters
function EventsEmptyState({ hasAnyEvents, anyFilterActive, onClearFilters, status }) {
  const state = (!hasAnyEvents && !anyFilterActive) ? 'no-events' : 'filter-miss';
  const pillKind = status && status.kind;
  return (
    <div data-empty-state={state} style={{padding: '60px 20px', textAlign: 'center'}}>
      <div style={{fontSize: 32, marginBottom: 8, opacity: 0.4}}>◌</div>
      {state === 'no-events' ? (
        pillKind === 'bad' ? (
          <>
            <div style={{fontSize: 14, fontWeight: 600, marginBottom: 4}}>{status.label}</div>
            <div className="dim" style={{fontSize: 12.5, marginBottom: 16}}>
              {status.detail || <>No detectors loaded. <span className="mono">/v1/clean</span> is returning 503 — see ADR-040 / Configure page.</>}
            </div>
            <button className="btn btn-primary"
              onClick={() => window.dispatchEvent(new CustomEvent('bulwark:goto', {detail: {page: 'configure'}}))}>
              Configure detectors
            </button>
          </>
        ) : pillKind === 'warn' && status.label === 'Sanitize-only mode' ? (
          <>
            <div style={{fontSize: 14, fontWeight: 600, marginBottom: 4}}>Sanitize-only mode</div>
            <div className="dim" style={{fontSize: 12.5, marginBottom: 16}}>
              {status.detail || <>BULWARK_ALLOW_NO_DETECTORS=1 — <span className="mono">/v1/clean</span> runs sanitizer only. Sanitizer events still appear here.</>}
            </div>
            <button className="btn btn-primary"
              onClick={() => window.dispatchEvent(new CustomEvent('bulwark:goto', {detail: {page: 'test'}}))}>
              Run a test
            </button>
          </>
        ) : (
          <>
            <div style={{fontSize: 14, fontWeight: 600, marginBottom: 4}}>No events yet</div>
            <div className="dim" style={{fontSize: 12.5, marginBottom: 16}}>
              Your pipeline is running. Requests to <span className="mono">/v1/clean</span> will appear here.
            </div>
            <button className="btn btn-primary"
              onClick={() => window.dispatchEvent(new CustomEvent('bulwark:goto', {detail: {page: 'test'}}))}>
              Run a test
            </button>
          </>
        )
      ) : (
        <>
          <div style={{fontSize: 14, fontWeight: 600, marginBottom: 4}}>No events match this filter</div>
          <div className="dim" style={{fontSize: 12.5, marginBottom: 16}}>
            Try a different filter, or send a request to generate activity.
          </div>
          <button className="btn" onClick={onClearFilters}>Clear filters</button>
        </>
      )}
    </div>
  );
}

function EventRow({ event, expanded, onToggle }) {
  return (
    <div>
      <div onClick={onToggle} style={{
        display: 'grid', gridTemplateColumns: '100px 120px 90px 180px 1fr auto',
        padding: '12px 20px', borderBottom: '1px solid var(--hairline)',
        fontSize: 13, alignItems: 'center', cursor: 'pointer', gap: 10,
        background: expanded ? 'var(--surface-2)' : 'transparent',
      }}>
        <span className="mono tabular dim">{fmtTime(event.ts)}</span>
        <span style={{display: 'flex', alignItems: 'center', gap: 7}}>
          <LayerIcon id={event.layer} /> <span style={{fontWeight: 500, fontSize: 12.5}}>{event.layer}</span>
        </span>
        <Verdict v={event.verdict}/>
        <span className="mono dim" style={{fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>{event.source}</span>
        <span style={{overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-2)'}}>{event.detail}</span>
        <span className="mono tabular dim" style={{fontSize: 12}}>{event.duration_ms}ms</span>
      </div>
      {expanded && <EventExpansion event={event} />}
    </div>
  );
}

function EventExpansion({ event }) {
  // Before/after pulled from event.metadata when the pipeline provides it.
  // Without it, show the best-effort request summary.
  const md = event.metadata || {};
  const before = md.before ?? md.original ?? null;
  const after  = md.after  ?? md.sanitized ?? null;
  const trace  = Array.isArray(md.trace) ? md.trace : null;
  const blockReason = md.reason || md.block_reason || md.matched_pattern || '';

  return (
    <div style={{padding: '16px 20px 20px 20px', borderBottom: '1px solid var(--hairline)', background: 'var(--bg-2)'}}>
      <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16}}>
        <div>
          <div className="label" style={{marginBottom: 6}}>
            {event.verdict === 'modified' ? 'Before → after' : (event.verdict === 'blocked' ? 'Block reason' : 'Request')}
          </div>
          {event.verdict === 'modified' && before !== null && after !== null ? (
            <div style={{display: 'grid', gap: 8}}>
              <pre style={{background: 'var(--red-soft)', padding: 10, borderRadius: 6, fontSize: 11.5, fontFamily: 'var(--font-mono)', color: 'var(--text-2)', border: '1px solid var(--red-line)', margin: 0, overflow: 'auto', whiteSpace: 'pre-wrap'}}>{before}</pre>
              <pre style={{background: 'var(--green-soft)', padding: 10, borderRadius: 6, fontSize: 11.5, fontFamily: 'var(--font-mono)', color: 'var(--text-2)', border: '1px solid var(--green-line)', margin: 0, overflow: 'auto', whiteSpace: 'pre-wrap'}}>{after}</pre>
            </div>
          ) : event.verdict === 'blocked' && blockReason ? (
            <pre style={{background: 'var(--red-soft)', padding: 12, borderRadius: 6, fontSize: 11.5, fontFamily: 'var(--font-mono)', color: 'var(--red)', border: '1px solid var(--red-line)', margin: 0, overflow: 'auto', whiteSpace: 'pre-wrap'}}>{blockReason}</pre>
          ) : (
            <pre style={{background: 'var(--surface)', padding: 12, borderRadius: 6, fontSize: 11.5, fontFamily: 'var(--font-mono)', color: 'var(--text-2)', overflow: 'auto', border: '1px solid var(--border)', whiteSpace: 'pre-wrap'}}>{JSON.stringify({
              source: event.source,
              layer: event.layer,
              verdict: event.verdict,
              duration_ms: event.duration_ms,
              timestamp: new Date(event.ts).toISOString(),
              ...(Object.keys(md).length ? { metadata: md } : {}),
            }, null, 2)}</pre>
          )}
        </div>
        <div>
          <div className="label" style={{marginBottom: 6}}>Trace</div>
          <div className="mono" style={{background: 'var(--surface)', padding: 12, borderRadius: 6, fontSize: 11.5, color: 'var(--text-2)', border: '1px solid var(--border)'}}>
            {(trace || _defaultTrace(event)).map((step, i) => (
              <div key={i} style={{display: 'flex', gap: 8, padding: '3px 0'}}>
                <span className="dim">{i+1}.</span>
                <span>{step.id || step.layer || step}</span>
                <span style={{marginLeft: 'auto', color: _verdictColor(step.verdict || ((step.id || step.layer) === event.layer ? event.verdict : 'passed'))}}>
                  {step.verdict || ((step.id || step.layer) === event.layer ? event.verdict : 'passed')}
                </span>
              </div>
            ))}
          </div>
          {event.verdict === 'blocked' && (
            <button className="btn" style={{marginTop: 10, width: '100%', justifyContent: 'center', fontSize: 12}}
              onClick={() => window.dispatchEvent(new CustomEvent('bulwark:goto', {detail: {page: 'test', focus: null, payload: md.payload || event.detail || ''}}))}>
              Replay in Test →
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function _defaultTrace(event) {
  // When the backend doesn't carry a trace, synthesize a per-layer pipeline
  // view so the expansion pane still shows something useful. Layers come
  // from the canonical LAYERS list (sanitizer, detection, boundary, canary).
  return LAYERS.map(l => ({ id: l.id }));
}

function _verdictColor(v) {
  if (v === 'blocked')  return 'var(--red)';
  if (v === 'modified') return 'var(--amber)';
  if (v === 'alert')    return 'var(--red)';
  if (v === 'passed' || v === 'clean') return 'var(--green)';
  return 'var(--text-dim)';
}

Object.assign(window, { PageEvents, filterEvents, isAnyFilterActive });
