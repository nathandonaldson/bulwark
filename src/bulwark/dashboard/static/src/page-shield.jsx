// Shield page — radial variant only. Data/Hybrid variants removed per ADR-020.

// Pure predicate — exported for testing. STATES.md §2 / G-UI-INCIDENT-001:
// an incident is "any blocked event in the last 30 minutes".
function hasRecentIncident(events, nowMs) {
  const cutoff = (nowMs || Date.now()) - 30 * 60 * 1000;
  return events.some(e => e.verdict === 'blocked' && e.ts > cutoff);
}
// activeLayerCount is defined in data.jsx (attached to window).

function PageShield({ store }) {
  return <ShieldRadial store={store} />;
}

// --- shared ---
function HeroStatus({ store, size = 'lg' }) {
  const activeLayers = activeLayerCount(store.layerConfig);
  const totalLayers = LAYERS.length;
  const recentBlocked = store.events.filter(e => e.verdict === 'blocked' && Date.now() - e.ts < 30 * 60 * 1000);
  const hasIncident = hasRecentIncident(store.events);

  if (hasIncident) {
    return (
      <div>
        <div style={{display: 'flex', alignItems: 'baseline', gap: 14, flexWrap: 'wrap'}}>
          <div className="display hero-metric" style={{
            fontSize: size === 'lg' ? 72 : 56, lineHeight: 0.95,
            fontWeight: 600, letterSpacing: '-0.03em', color: 'var(--text)',
          }}>Protected</div>
          <div style={{color: 'var(--text-dim)', fontSize: 14, display: 'flex', alignItems: 'center', gap: 10}}>
            <Dot kind="green" size={8}/>
            <span>{activeLayers} of {totalLayers} layers active · {recentBlocked.length} threat{recentBlocked.length === 1 ? '' : 's'} neutralized in last 30m</span>
          </div>
        </div>
        <div role="alert" style={{
          marginTop: 16, padding: '12px 16px', background: 'var(--amber-soft)',
          border: '1px solid var(--amber-line)', borderRadius: 10,
          display: 'flex', alignItems: 'center', gap: 12,
        }}>
          <span style={{color: 'var(--amber)', fontSize: 18}}>⚡</span>
          <div style={{flex: 1}}>
            <div style={{fontSize: 13, fontWeight: 600, color: 'var(--amber)'}}>Active defense — {recentBlocked.length} attack{recentBlocked.length === 1 ? '' : 's'} blocked</div>
            <div className="dim" style={{fontSize: 12, marginTop: 2}}>Latest: {recentBlocked[0].detail}</div>
          </div>
          <button className="btn" style={{fontSize: 12}}>Review ›</button>
        </div>
      </div>
    );
  }

  return (
    <div style={{display: 'flex', alignItems: 'baseline', gap: 14, flexWrap: 'wrap'}}>
      <div className="display hero-metric" style={{
        fontSize: size === 'lg' ? 72 : 56, lineHeight: 0.95,
        fontWeight: 600, letterSpacing: '-0.03em', color: 'var(--text)',
      }}>Protected</div>
      <div style={{color: 'var(--text-dim)', fontSize: 14, display: 'flex', alignItems: 'center', gap: 10}}>
        <Dot kind="green" size={8}/>
        <span>{activeLayers} of {totalLayers} layers active · no threats in 24h</span>
      </div>
    </div>
  );
}

function StatTile({ label, value, color, spark, hint }) {
  return (
    <div className="card" style={{padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: 4, minHeight: 92}}>
      <div style={{display: 'flex', alignItems: 'center', justifyContent: 'space-between'}}>
        <div className="label">{label}</div>
        {hint && <span className="dim" style={{fontSize: 11}}>{hint}</span>}
      </div>
      <div className="tabular" style={{
        fontSize: 30, fontWeight: 600, letterSpacing: '-0.02em',
        color: color || 'var(--text)', marginTop: 2,
      }}>{value}</div>
      {spark && <div style={{marginTop: 'auto'}}><Sparkline values={spark} color={color || 'var(--accent)'} width={180} height={24}/></div>}
    </div>
  );
}

// -----------------------------------------------------------------------------
// Variant A — Radial shield (refined)
// -----------------------------------------------------------------------------
function ShieldRadial({ store }) {
  const s24 = store.stats24h;
  const recent = store.events.slice(0, 6);
  return (
    <div style={{padding: '28px 28px 60px', maxWidth: 1320, margin: '0 auto'}}>
      <div style={{marginBottom: 24}}><HeroStatus store={store} /></div>

      <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, alignItems: 'start'}}>
        {/* Left: radial */}
        <div className="card" style={{padding: 28, display: 'flex', flexDirection: 'column', alignItems: 'center', minHeight: 520}}>
          <RadialShield store={store} />
          <div style={{marginTop: 24, width: '100%', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10}}>
            <StatTile label="Processed / 24h" value={s24.processed.toLocaleString()} spark={store.sparks.sanitizer} />
            <StatTile label="Neutralized" value={s24.blocked} color="var(--accent)" spark={store.sparks.detection} />
            <StatTile label="Canary leaks" value={s24.canary} color={s24.canary ? 'var(--red)' : 'var(--text-2)'} />
            <StatTile label="Detection blocks" value={s24.detection} color={s24.detection ? 'var(--amber)' : 'var(--text-2)'} />
          </div>
        </div>

        {/* Right: layer list */}
        <div style={{display: 'flex', flexDirection: 'column', gap: 8}}>
          {LAYERS.map(layer => (
            <LayerRow key={layer.id} layer={layer} store={store} onClick={() => window.dispatchEvent(new CustomEvent('bulwark:goto', {detail: {page: 'configure', focus: layer.id}}))} />
          ))}
          <div style={{marginTop: 14}}>
            <div className="label" style={{marginBottom: 6}}>Recent activity</div>
            <div className="card" style={{padding: 0, overflow: 'hidden'}}>
              {recent.map(e => <MiniEventRow key={e.id} event={e} />)}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function RadialShield({ store }) {
  const [flash, setFlash] = React.useState(null);
  React.useEffect(() => BulwarkStore.onEvent(ev => {
    setFlash(ev.layer);
    const t = setTimeout(() => setFlash(null), 800);
    return () => clearTimeout(t);
  }), []);

  // Ring colors reference the per-stage tokens defined in index.html :root
  // (--stage-sanitizer .. --stage-canary). v2: four rings, one per layer.
  const rings = [
    { id: 'sanitizer', r: 140, color: 'var(--stage-sanitizer)', dash: '4 2' },
    { id: 'detection', r: 108, color: 'var(--stage-detection)', dash: '8 4' },
    { id: 'boundary',  r: 76,  color: 'var(--stage-boundary)',  dash: null  },
    { id: 'canary',    r: 44,  color: 'var(--stage-canary)',    dash: '6 3' },
  ];

  return (
    <svg width="340" height="340" viewBox="0 0 320 320">
      {rings.map((ring, i) => {
        const on = store.layerConfig[ring.id];
        const isFlashing = flash === ring.id;
        return (
          <g key={ring.id}>
            <circle cx="160" cy="160" r={ring.r}
              fill="none" stroke={ring.color}
              strokeWidth={isFlashing ? 20 : 14}
              strokeOpacity={on ? (isFlashing ? 1 : 0.85) : 0.12}
              strokeDasharray={ring.dash || undefined}
              style={{transition: 'all 0.25s'}}
            />
          </g>
        );
      })}
    </svg>
  );
}

function LayerRow({ layer, store, onClick }) {
  const [pulse, setPulse] = React.useState(false);
  const [hover, setHover] = React.useState(false);
  React.useEffect(() => BulwarkStore.onEvent(ev => {
    if (ev.layer === layer.id) {
      setPulse(true);
      setTimeout(() => setPulse(false), 900);
    }
  }), [layer.id]);
  const on = store.layerConfig[layer.id];
  const count = store.events.filter(e => e.layer === layer.id && Date.now() - e.ts < 24*3600*1000).length;
  return (
    <button onClick={onClick} onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
      className={"card" + (pulse ? ' tick' : '')} style={{
      padding: '14px 18px', display: 'grid', textAlign: 'left',
      gridTemplateColumns: 'auto 1fr auto auto auto', gap: 14, alignItems: 'center',
      opacity: on ? 1 : 0.5, transition: 'all 0.2s', cursor: 'pointer',
      borderColor: hover ? 'var(--border-2)' : undefined,
    }}>
      <Dot kind={on ? 'ok' : 'off'} pulse={on}/>
      <div>
        <div style={{display: 'flex', alignItems: 'center', gap: 8}}>
          <LayerIcon id={layer.id} />
          <span style={{fontWeight: 600, fontSize: 13.5}}>{layer.name}</span>
        </div>
        <div className="dim" style={{fontSize: 12, marginTop: 2}}>{layer.desc}</div>
      </div>
      <Sparkline values={store.sparks[layer.id] || []} color="var(--accent)" width={70} height={22} filled={false}/>
      <div style={{textAlign: 'right', minWidth: 48}}>
        <div className="tabular" style={{fontWeight: 600, fontSize: 14}}>{count}</div>
        <div className="dim" style={{fontSize: 10.5}}>{layer.events}</div>
      </div>
      <span style={{
        fontSize: 16, color: hover ? 'var(--text-dim)' : 'var(--text-faint)',
        transform: hover ? 'translateX(2px)' : 'none', transition: 'all 0.15s',
      }}>›</span>
    </button>
  );
}

function MiniEventRow({ event }) {
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: 'auto auto 1fr auto', gap: 12,
      padding: '10px 16px', borderBottom: '1px solid var(--hairline)',
      fontSize: 12.5, alignItems: 'center',
    }}>
      <span className="dim mono tabular">{fmtTime(event.ts)}</span>
      <Verdict v={event.verdict} />
      <span className="dim" style={{overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>{event.detail}</span>
      <span className="mono dim" style={{fontSize: 11}}>{event.layer}</span>
    </div>
  );
}

Object.assign(window, { PageShield, hasRecentIncident, activeLayerCount });
