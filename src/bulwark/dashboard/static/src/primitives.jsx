// Shared primitive components.

function Sparkline({ values, color = 'var(--accent)', width = 120, height = 28, filled = true }) {
  const max = Math.max(1, ...values);
  const min = 0;
  const n = values.length;
  const stepX = width / (n - 1 || 1);
  const pts = values.map((v, i) => {
    const x = i * stepX;
    const y = height - ((v - min) / (max - min || 1)) * (height - 2) - 1;
    return [x, y];
  });
  const path = pts.map((p, i) => (i === 0 ? `M${p[0]},${p[1]}` : `L${p[0]},${p[1]}`)).join(' ');
  const area = `${path} L${width},${height} L0,${height} Z`;
  return (
    <svg className="spark" width={width} height={height} viewBox={`0 0 ${width} ${height}`}>
      {filled && <path d={area} fill={color} opacity="0.14" />}
      <path d={path} fill="none" stroke={color} strokeWidth="1.4" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={pts[pts.length-1][0]} cy={pts[pts.length-1][1]} r="2.2" fill={color} />
    </svg>
  );
}

function Toggle({ on, onClick, size = 'md' }) {
  const w = size === 'sm' ? 32 : 40;
  const h = size === 'sm' ? 18 : 22;
  const k = h - 6;
  return (
    <button
      onClick={onClick}
      aria-pressed={on}
      style={{
        width: w, height: h, borderRadius: h/2,
        background: on ? 'var(--accent)' : 'var(--surface-3)',
        position: 'relative', transition: 'background 0.2s',
        border: '1px solid ' + (on ? 'var(--accent)' : 'var(--border)'),
        flexShrink: 0,
      }}>
      <span style={{
        position: 'absolute', top: 2, left: on ? w - k - 3 : 2,
        width: k, height: k, borderRadius: '50%',
        background: on ? 'var(--accent-ink)' : 'var(--ink-dim)',
        transition: 'left 0.2s',
      }} />
    </button>
  );
}

// Status dot that subtly pulses
function Dot({ kind = 'ok', size = 8, pulse = true }) {
  const color = { ok: 'var(--accent)', green: 'var(--green)', warn: 'var(--amber)', bad: 'var(--red)', off: 'var(--text-faint)' }[kind];
  return <span className={pulse && kind !== 'off' ? 'pulse-dot' : ''} style={{
    display: 'inline-block', width: size, height: size, borderRadius: '50%',
    background: color,
    boxShadow: kind !== 'off' ? `0 0 0 3px ${color}20` : 'none',
  }} />;
}

// Section heading — varies by type mode
function SectionTitle({ eyebrow, title, action, size = 'md' }) {
  return (
    <div style={{display:'flex', alignItems:'flex-end', justifyContent:'space-between', marginBottom: 16, gap: 16}}>
      <div>
        {eyebrow && <div className="label" style={{marginBottom: 6}}>{eyebrow}</div>}
        <h2 className="display" style={{
          fontSize: size === 'lg' ? 28 : (size === 'sm' ? 16 : 20),
          fontWeight: 600, letterSpacing: '-0.01em', color: 'var(--text)',
        }}>{title}</h2>
      </div>
      {action && <div>{action}</div>}
    </div>
  );
}

// Verdict badge
function Verdict({ v }) {
  const map = {
    passed: { bg: 'transparent', fg: 'var(--text-dim)', bd: 'var(--border)', label: 'passed' },
    blocked: { bg: 'var(--red-soft)', fg: 'var(--red)', bd: 'var(--red-line)', label: 'blocked' },
    modified: { bg: 'var(--amber-soft)', fg: 'var(--amber)', bd: 'var(--amber-line)', label: 'modified' },
    clean: { bg: 'var(--green-soft)', fg: 'var(--green)', bd: 'var(--green-line)', label: 'clean' },
    alert: { bg: 'var(--red-soft)', fg: 'var(--red)', bd: 'var(--red-line)', label: 'alert' },
  };
  const s = map[v] || map.passed;
  return (
    <span style={{
      display: 'inline-block',
      fontSize: 11, fontWeight: 600, fontFamily: 'var(--font-mono)',
      padding: '2px 8px', borderRadius: 5,
      background: s.bg, color: s.fg, border: '1px solid ' + s.bd,
    }}>{s.label}</span>
  );
}

// Layer icons (minimal SVG glyphs)
function LayerIcon({ id, size = 16 }) {
  const paths = {
    sanitizer: <g stroke="currentColor" strokeWidth="1.4" fill="none" strokeLinecap="round"><path d="M3 5h10M3 9h10M3 13h6"/><path d="M11 13l2 2 3-4" stroke="var(--accent)"/></g>,
    boundary:  <g stroke="currentColor" strokeWidth="1.4" fill="none"><rect x="2.5" y="3.5" width="11" height="9" rx="1"/><path d="M5 6h6M5 10h4"/></g>,
    detection: <g stroke="currentColor" strokeWidth="1.4" fill="none"><circle cx="7" cy="7" r="4"/><path d="M10 10l3.5 3.5"/></g>,
    analyze:   <g stroke="currentColor" strokeWidth="1.4" fill="none" strokeLinecap="round"><path d="M2 8h12M6 4l-4 4 4 4"/></g>,
    bridge:    <g stroke="currentColor" strokeWidth="1.4" fill="none"><path d="M2 11l3-4 3 3 3-2 3 3"/><path d="M2 13h12"/></g>,
    canary:    <g stroke="currentColor" strokeWidth="1.4" fill="none"><path d="M8 2v12M5 5l3-3 3 3M5 11l3 3 3-3"/></g>,
    execute:   <g stroke="currentColor" strokeWidth="1.4" fill="none" strokeLinecap="round"><path d="M4 3l8 5-8 5V3z"/></g>,
  };
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" style={{color: 'currentColor', flexShrink: 0}}>
      {paths[id] || paths.sanitizer}
    </svg>
  );
}

Object.assign(window, { Sparkline, Toggle, Dot, SectionTitle, Verdict, LayerIcon });
