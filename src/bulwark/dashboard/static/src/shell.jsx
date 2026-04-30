// App shell — top-nav tabs, status pill, brand.
// Sidebar variant removed per ADR-020.

// Pure status-pill state machine. v2 (ADR-031): Bulwark never calls an LLM,
// so status tracks detector availability + judge state + the `mode` field
// returned by /v1/clean (ADR-038/040 degraded-explicit). The Events empty
// state and Shield layer cards read from the same helper so the dashboard's
// top-level signal stays consistent across pages.
//
// Returns { kind: 'ok'|'warn'|'bad', label: string, detail?: string }.
// Contract: G-UI-STATUS-001..005 (legacy) + ADR-040 / ADR-038 surfacing.
function computeStatusPill(store) {
  const { layerConfig, detectorStatus, integrations, judge, serviceMode } = store;
  const det = (detectorStatus && detectorStatus.protectai) || { status: 'loading' };
  const promptguardActive = (integrations && integrations.promptguard) === 'active';
  const judgeEnabled = !!(judge && judge.enabled);

  // ADR-038 — operator opted into BULWARK_ALLOW_NO_DETECTORS=1; /v1/clean
  // returned mode:"degraded-explicit". Sanitizer-only is intentional, but the
  // user should know they're not getting detection.
  if (serviceMode === 'degraded-explicit') {
    return {
      kind: 'warn',
      label: 'Sanitize-only mode',
      detail: 'BULWARK_ALLOW_NO_DETECTORS=1 — /v1/clean runs sanitizer only.',
    };
  }

  // ADR-040 — fail-closed: zero ML detectors AND judge disabled means
  // /v1/clean is returning HTTP 503 to every caller. Surface this loudly
  // instead of cheerfully claiming "All layers active".
  if (det.status === 'error' && !promptguardActive && !judgeEnabled) {
    return {
      kind: 'bad',
      label: 'No detectors loaded',
      detail: '/v1/clean is returning 503 — see ADR-040 / Configure page.',
    };
  }

  if (det.status === 'loading') return { kind: 'warn', label: 'Loading detector…' };
  if (det.status === 'error')   return { kind: 'bad',  label: 'Detector unreachable' };

  const active = activeLayerCount(layerConfig);
  const total = LAYERS.length;
  if (active < total) return { kind: 'warn', label: `${active} of ${total} layers active` };
  return { kind: 'ok', label: 'All layers active' };
}

function TopNav({ page, setPage, store }) {
  const { kind: statusKind, label: statusLabel } = computeStatusPill(store);

  const tabs = [
    { id: 'shield',         label: 'Shield' },
    { id: 'events',         label: 'Events' },
    { id: 'configure',      label: 'Configure' },
    { id: 'leak-detection', label: 'Leak Detection' },
    { id: 'test',           label: 'Test' },
  ];

  return (
    <header style={{
      display: 'flex', alignItems: 'center', gap: 20,
      padding: '14px 28px', borderBottom: '1px solid var(--border)',
      background: 'var(--bg-2)', position: 'sticky', top: 0, zIndex: 50,
      backdropFilter: 'blur(8px)',
    }}>
      <Brand version={store.version} />
      <nav style={{display: 'flex', gap: 2, marginLeft: 12}}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setPage(t.id)} style={{
            padding: '7px 14px', borderRadius: 8, fontSize: 13,
            color: page === t.id ? 'var(--text)' : 'var(--text-dim)',
            background: page === t.id ? 'var(--surface-2)' : 'transparent',
            fontWeight: page === t.id ? 600 : 500,
            transition: 'all 0.15s',
          }}>{t.label}</button>
        ))}
      </nav>
      <div style={{marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10}}>
        <button className="btn btn-ghost" data-hint="Search events (⌘K)" onClick={() => {}}>
          <svg width="14" height="14" viewBox="0 0 16 16"><circle cx="7" cy="7" r="4.5" fill="none" stroke="currentColor" strokeWidth="1.4"/><path d="M10.5 10.5l3 3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/></svg>
        </button>
        <StatusPill kind={statusKind} label={statusLabel} />
      </div>
    </header>
  );
}

function Brand({ version }) {
  return (
    <div style={{display: 'flex', alignItems: 'center', gap: 10}}>
      <svg width="20" height="20" viewBox="0 0 20 20">
        <path d="M10 1.5L17 4v6c0 4.5-3.2 7.8-7 8.5C6.2 17.8 3 14.5 3 10V4l7-2.5z"
              fill="none" stroke="var(--accent)" strokeWidth="1.4" strokeLinejoin="round"/>
        <path d="M10 5.5L13.5 7v3c0 2.2-1.5 3.8-3.5 4.2-2-.4-3.5-2-3.5-4.2V7L10 5.5z"
              fill="var(--accent)" opacity="0.3"/>
      </svg>
      <span style={{fontSize: 15, fontWeight: 700, letterSpacing: '-0.01em'}}>Bulwark</span>
      {version && <span className="mono dim" style={{fontSize: 11, marginLeft: 2}}>v{version}</span>}
    </div>
  );
}

function StatusPill({ kind, label, compact }) {
  const colors = {
    ok:   { bg: 'var(--green-soft)',  fg: 'var(--green)',  bd: 'var(--green-line)' },
    warn: { bg: 'var(--amber-soft)',  fg: 'var(--amber)',  bd: 'var(--amber-line)' },
    bad:  { bg: 'var(--red-soft)',    fg: 'var(--red)',    bd: 'var(--red-line)' },
  }[kind] || { bg: 'var(--accent-soft)', fg: 'var(--accent)', bd: 'var(--accent-line)' };
  return (
    <div role="status" aria-live="polite" style={{
      display: 'inline-flex', alignItems: 'center', gap: 8,
      padding: compact ? '6px 10px' : '6px 12px',
      borderRadius: 999,
      background: colors.bg, color: colors.fg,
      border: '1px solid ' + colors.bd,
      fontSize: 12, fontWeight: 600,
    }}>
      <Dot kind={kind === 'ok' ? 'green' : (kind === 'warn' ? 'warn' : 'bad')} size={7} />
      {label}
    </div>
  );
}

Object.assign(window, { TopNav, StatusPill, computeStatusPill });
