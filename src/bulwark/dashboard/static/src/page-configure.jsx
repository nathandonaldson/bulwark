// Configure page (v2.x): pipeline-flow visualization. Each detector is a
// separate stage. Trust Boundary is shown last (Output formatter — not a
// defense gate, just response formatting). LLM judge is opt-in, off by
// default; it carries a latency warning since it adds 1–3s per request.

function PageConfigure({ store }) {
  const [selected, setSelected] = React.useState('sanitizer');
  React.useEffect(() => {
    const h = (e) => { if (STAGES.find(s => s.id === e.detail)) setSelected(e.detail); };
    window.addEventListener('bulwark:focus', h);
    return () => window.removeEventListener('bulwark:focus', h);
  }, []);

  return (
    <div style={{padding: '28px 28px 60px', maxWidth: 1320, margin: '0 auto'}}>
      <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 24, gap: 20}}>
        <div>
          <div className="label">System</div>
          <h2 className="display" style={{fontSize: 28, fontWeight: 600, letterSpacing: '-0.01em', marginTop: 4}}>Configure pipeline</h2>
          <div className="dim" style={{fontSize: 13, marginTop: 4, maxWidth: 640}}>
            Untrusted content flows top to bottom through the pipeline, then is returned to the caller.
            Bulwark never invokes a generative LLM &mdash; it sanitizes, classifies, and wraps. Your application calls <span className="mono">/v1/clean</span>,
            feeds the safe output to your own LLM, and calls <span className="mono">/v1/guard</span> on the response.
          </div>
        </div>
      </div>

      <div style={{display: 'grid', gridTemplateColumns: '440px 1fr', gap: 28, alignItems: 'start'}}>
        <PipelineFlow store={store} selected={selected} onSelect={setSelected} />
        <div style={{paddingTop: 32}}>
          <DetailPane store={store} selected={selected} />
        </div>
      </div>
    </div>
  );
}

const STAGES = [
  { id: 'sanitizer',   name: 'Sanitizer',                  desc: 'Strip hidden chars, steganography, emoji smuggling',                tag: '<1ms',             color: 'var(--stage-sanitizer)' },
  { id: 'protectai',   name: 'DeBERTa (mandatory)',        desc: 'ProtectAI deberta-v3 classifier; chunked across 512-token windows', tag: '~30ms',            color: 'var(--stage-detection)' },
  { id: 'promptguard', name: 'PromptGuard (optional)',     desc: 'Meta mDeBERTa second-opinion detector. Requires HF approval.',      tag: '~50ms',            color: 'var(--stage-detection)' },
  { id: 'llm_judge',   name: 'LLM Judge (optional)',       desc: 'Send sanitized input to your own classifier LLM. High latency.',     tag: '~1\u20133s',       color: 'var(--stage-detection)' },
  { id: 'boundary',    name: 'Trust Boundary',             desc: 'Wrap cleaned content in XML boundary tags',                         tag: 'Output formatter', color: 'var(--stage-boundary)' },
];

function _stageWiring(store, id) {
  const detEvents24h = store.events.filter(
    e => e.layer === 'detection' && Date.now() - e.ts < 24 * 3600 * 1000,
  ).length;
  if (id === 'protectai') {
    const det = (store.detectorStatus && store.detectorStatus.protectai) || {};
    return { on: true, togglable: false, onToggle: () => {}, needsAttention: det.status === 'error', stats: detEvents24h };
  }
  if (id === 'promptguard') {
    const det = (store.detectorStatus && store.detectorStatus.promptguard) || {};
    const active = store.integrations.promptguard === 'active';
    return {
      on: active, togglable: true,
      onToggle: () => BulwarkStore.setIntegration('promptguard', active ? 'available' : 'active'),
      needsAttention: det.status === 'error',
      stats: detEvents24h,
    };
  }
  if (id === 'llm_judge') {
    const j = store.judge || {};
    return {
      on: !!j.enabled,
      togglable: true,
      onToggle: () => BulwarkStore.setJudgeEnabled(!j.enabled),
      needsAttention: !!j.enabled && (!j.base_url || !j.model),
      stats: detEvents24h,
    };
  }
  return {
    on: !!store.layerConfig[id],
    togglable: true,
    onToggle: () => BulwarkStore.toggleLayer(id),
    needsAttention: false,
    stats: store.events.filter(e => e.layer === id && Date.now() - e.ts < 24 * 3600 * 1000).length,
  };
}

function PipelineFlow({ store, selected, onSelect }) {
  return (
    <div style={{position: 'relative'}}>
      <div style={{display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, padding: '0 4px'}}>
        <span className="dim" style={{fontSize: 11, letterSpacing: '0.08em', textTransform: 'uppercase', fontWeight: 600}}>Pipeline</span>
        <span style={{flex: 1, height: 1, background: 'var(--hairline)'}}/>
        <span className="dim" style={{fontSize: 11}}>Click a stage to configure ›</span>
      </div>

      <div style={{display: 'flex', flexDirection: 'column', gap: 0, position: 'relative'}}>
        <FlowEndpoint label="Untrusted content" role="in" />
        {STAGES.map((stage) => {
          const w = _stageWiring(store, stage.id);
          return (
            <React.Fragment key={stage.id}>
              <FlowConnector active={w.on} />
              <FlowNode
                stage={stage}
                on={w.on}
                togglable={w.togglable}
                isSelected={selected === stage.id}
                onSelect={() => onSelect(stage.id)}
                onToggle={w.onToggle}
                stats={w.stats}
                needsAttention={w.needsAttention}
              />
            </React.Fragment>
          );
        })}
        <FlowConnector active={true} />
        <FlowEndpoint label="Safe output" role="out" />
      </div>
    </div>
  );
}

function FlowEndpoint({ label, role }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: '10px 14px', margin: '0 auto',
      background: 'var(--bg-2)', border: '1px dashed var(--border-2)',
      borderRadius: 999, fontSize: 11.5, color: 'var(--text-dim)',
      letterSpacing: '0.08em', textTransform: 'uppercase', fontWeight: 600,
    }}>
      {role === 'in' && '▼ '}{label}{role === 'out' && ' ✓'}
    </div>
  );
}

function FlowConnector({ active }) {
  return (
    <div style={{
      width: 2, height: 14, margin: '0 auto',
      background: active ? 'linear-gradient(to bottom, var(--accent), var(--accent-line))' : 'var(--border)',
      opacity: active ? 0.6 : 0.4,
    }}/>
  );
}

function FlowNode({ stage, on, togglable, isSelected, onSelect, onToggle, stats, needsAttention }) {
  const [hover, setHover] = React.useState(false);
  return (
    <button onClick={onSelect} onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)} style={{
      display: 'grid', gridTemplateColumns: 'auto auto 1fr auto auto auto',
      gap: 12, alignItems: 'center',
      padding: '14px 14px 14px 0', textAlign: 'left',
      background: isSelected ? 'var(--surface-2)' : 'var(--surface)',
      border: '1px solid ' + (isSelected ? `color-mix(in srgb, ${stage.color} 50%, transparent)` : (hover && on ? 'var(--border-2)' : 'var(--border)')),
      borderRadius: 10,
      opacity: on ? 1 : 0.6,
      transition: 'all 0.15s',
      cursor: 'pointer',
      boxShadow: isSelected ? `0 0 0 3px color-mix(in srgb, ${stage.color} 13%, transparent), inset 3px 0 0 ${stage.color}` : (hover ? 'inset 3px 0 0 var(--border-2)' : 'inset 3px 0 0 transparent'),
      position: 'relative',
    }}>
      <span style={{width: 16}}/>
      <span style={{
        width: 10, height: 10, borderRadius: '50%',
        background: on ? stage.color : 'var(--text-faint)',
        boxShadow: on ? `0 0 0 3px color-mix(in srgb, ${stage.color} 19%, transparent)` : 'none',
      }}/>
      <div>
        <div style={{display: 'flex', alignItems: 'center', gap: 8}}>
          <span style={{fontSize: 13.5, fontWeight: 600, color: 'var(--text)'}}>{stage.name}</span>
          {needsAttention && <span className="pill warn" style={{fontSize: 10, padding: '2px 6px'}}>Needs setup</span>}
        </div>
        <div className="dim" style={{fontSize: 11.5, marginTop: 2, lineHeight: 1.4}}>{stage.desc}</div>
      </div>
      <div style={{textAlign: 'right'}}>
        <div className="mono tabular" style={{fontSize: 12.5, fontWeight: 600, color: on ? 'var(--text)' : 'var(--text-dim)'}}>{stats}</div>
        <div className="dim" style={{fontSize: 10, letterSpacing: '0.08em', textTransform: 'uppercase'}}>{stage.tag}</div>
      </div>
      <span style={{
        fontSize: 16, color: isSelected ? stage.color : (hover ? 'var(--text-dim)' : 'var(--text-faint)'),
        transition: 'all 0.15s',
        transform: isSelected ? 'translateX(2px)' : (hover ? 'translateX(1px)' : 'none'),
        width: 14, textAlign: 'center',
      }}>›</span>
      {togglable ? (
        <div onClick={(e) => { e.stopPropagation(); onToggle(); }}>
          <Toggle on={on} onClick={() => {}} size="sm" />
        </div>
      ) : (
        <span className="pill" style={{fontSize: 10, padding: '2px 8px', background: 'var(--accent-soft)', color: 'var(--accent-ink)', borderRadius: 999, letterSpacing: '0.05em', textTransform: 'uppercase', fontWeight: 600}}>Required</span>
      )}
    </button>
  );
}

function DetailPane({ store, selected }) {
  const stage = STAGES.find(s => s.id === selected);
  if (!stage) return null;
  if (selected === 'sanitizer')   return <SanitizerPane store={store} stage={stage} />;
  if (selected === 'protectai')   return <DetectorPane store={store} stage={stage} id="protectai"   mandatory />;
  if (selected === 'promptguard') return <DetectorPane store={store} stage={stage} id="promptguard" />;
  if (selected === 'llm_judge')   return <LLMJudgePane store={store} stage={stage} />;
  return <BoundaryPane store={store} stage={stage} />;
}

function DetailHeader({ stage, children }) {
  return (
    <div style={{padding: '22px 24px 18px', borderBottom: '1px solid var(--border)'}}>
      <div className="label" style={{color: stage.color}}>Stage settings</div>
      <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginTop: 6, gap: 14}}>
        <div>
          <h3 style={{fontSize: 18, fontWeight: 600, letterSpacing: '-0.01em'}}>{stage.name}</h3>
          <div className="dim" style={{fontSize: 13, marginTop: 4, maxWidth: 520}}>{stage.desc}</div>
        </div>
        {children}
      </div>
    </div>
  );
}

function SubToggle({ name, desc, on, onToggle }) {
  return (
    <div style={{display: 'flex', alignItems: 'center', gap: 14, padding: '12px 0', borderBottom: '1px solid var(--hairline)'}}>
      <div style={{flex: 1}}>
        <div style={{fontSize: 13, fontWeight: 500}}>{name}</div>
        <div className="dim" style={{fontSize: 12, marginTop: 2}}>{desc}</div>
      </div>
      <Toggle on={on} onClick={onToggle} size="sm" />
    </div>
  );
}

function SanitizerPane({ store, stage }) {
  const opts = [
    { id: 'emoji_smuggling', name: 'Emoji smuggling defense', desc: 'Strip variation selectors and tag characters' },
    { id: 'bidi_override',   name: 'Bidirectional override',  desc: 'Strip bidi override and embedding characters' },
    { id: 'nfkc',            name: 'NFKC normalization',      desc: 'Map Unicode homoglyphs to canonical forms' },
  ];
  return (
    <div className="card" style={{padding: 0}}>
      <DetailHeader stage={stage}/>
      <div style={{padding: '8px 24px 22px'}}>
        {opts.map(o => (
          <SubToggle key={o.id} name={o.name} desc={o.desc}
            on={store.layerConfig[o.id]} onToggle={() => BulwarkStore.toggleLayer(o.id)}/>
        ))}
      </div>
    </div>
  );
}

function DetectorPane({ store, stage, id, mandatory }) {
  const meta = {
    protectai: {
      huggingface: 'protectai/deberta-v3-base-prompt-injection-v2',
      latency: '~30ms', size: '180MB',
      blurb: 'Ungated, loads on the first /v1/clean call after install. Inputs over 512 tokens are split into overlapping windows (ADR-032) so the detector sees the entire payload.',
    },
    promptguard: {
      huggingface: 'meta-llama/Prompt-Guard-86M',
      latency: '~50ms', size: '184MB',
      blurb: 'Meta\u2019s mDeBERTa second-opinion detector. Requires HuggingFace approval; once enabled, weights download on first use and the detector runs alongside DeBERTa.',
    },
  }[id];

  const det = (store.detectorStatus && store.detectorStatus[id]) || { status: 'available' };
  const isActive = store.integrations[id] === 'active';
  let pillKind = 'warn', pillLabel = 'Available';
  if (det.status === 'loading') { pillKind = 'warn'; pillLabel = 'Loading\u2026'; }
  else if (det.status === 'error') { pillKind = 'bad'; pillLabel = 'Error'; }
  else if (det.status === 'ready' || isActive) { pillKind = 'ok'; pillLabel = 'Ready'; }

  return (
    <div className="card" style={{padding: 0}}>
      <DetailHeader stage={stage}>
        <StatusPill kind={pillKind} label={pillLabel} compact />
      </DetailHeader>
      <div style={{padding: '18px 24px 22px'}}>
        <div className="dim" style={{fontSize: 13, lineHeight: 1.5}}>{meta.blurb}</div>
        <div style={{marginTop: 14, display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 16px', fontSize: 12}}>
          <span className="dim">Model</span><span className="mono">{meta.huggingface}</span>
          <span className="dim">Latency</span><span className="mono">{meta.latency}</span>
          <span className="dim">Size</span><span className="mono">{meta.size}</span>
        </div>
        {det.status === 'error' && (
          <div style={{marginTop: 14, padding: 10, background: 'var(--red-soft)', color: 'var(--red)', borderRadius: 6, fontSize: 12}}>
            {det.message || 'Failed to load \u2014 check the server log.'}
          </div>
        )}
        {!mandatory && (
          <div style={{marginTop: 18, display: 'flex', alignItems: 'center', gap: 12}}>
            <button className="btn"
              onClick={() => BulwarkStore.setIntegration(id, isActive ? 'available' : 'active')}
              disabled={det.status === 'loading'}
              style={{fontSize: 12}}>
              {det.status === 'loading' ? 'Loading\u2026' : (isActive ? 'Disable' : 'Enable')}
            </button>
            <span className="dim" style={{fontSize: 11.5}}>
              Toggling this here is the same as flipping the inline switch in the pipeline.
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

// LLM Judge — opt-in third detector (ADR-033). Off by default. Adds 1\u20133s
// latency per request when enabled.
function LLMJudgePane({ store, stage }) {
  const j = store.judge || {};
  const [busy, setBusy] = React.useState(false);
  const [draft, setDraft] = React.useState({
    base_url: j.base_url || '',
    model: j.model || '',
    api_key: '',
    threshold: j.threshold ?? 0.85,
    fail_open: j.fail_open ?? true,
    mode: j.mode || 'openai_compatible',
  });
  React.useEffect(() => {
    setDraft(d => ({...d,
      base_url: j.base_url || '',
      model: j.model || '',
      threshold: j.threshold ?? 0.85,
      fail_open: j.fail_open ?? true,
      mode: j.mode || 'openai_compatible',
    }));
  }, [j.base_url, j.model, j.threshold, j.fail_open, j.mode]);

  async function save() {
    setBusy(true);
    try {
      const patch = {
        mode: draft.mode,
        base_url: draft.base_url,
        model: draft.model,
        threshold: parseFloat(draft.threshold) || 0.85,
        fail_open: !!draft.fail_open,
      };
      if (draft.api_key && !draft.api_key.includes('...')) patch.api_key = draft.api_key;
      await BulwarkStore.setJudgeConfig(patch);
      setDraft(d => ({...d, api_key: ''}));
    } finally { setBusy(false); }
  }

  return (
    <div className="card" style={{padding: 0}}>
      <DetailHeader stage={stage}>
        <StatusPill
          kind={j.enabled ? 'ok' : 'warn'}
          label={j.enabled ? 'Enabled' : 'Disabled'}
          compact />
      </DetailHeader>
      <div style={{padding: '14px 24px 22px'}}>
        <div style={{padding: 12, background: 'var(--amber-soft)', color: 'var(--amber)', border: '1px solid var(--amber-line)', borderRadius: 8, fontSize: 12.5, lineHeight: 1.5, marginBottom: 16}}>
          <strong>High-latency option.</strong> The LLM judge adds ~1\u20133 seconds per /v1/clean request. Enable it only when DeBERTa + PromptGuard miss attacks specific to your domain. Bulwark&rsquo;s standard red-team scan (3,112 probes) achieves 100% defense without it.
        </div>

        <div className="dim" style={{fontSize: 13, lineHeight: 1.5, marginBottom: 14}}>
          Sends sanitized input to your endpoint with a fixed classifier prompt and parses the verdict.
          Detection only &mdash; the LLM&rsquo;s raw output never reaches /v1/clean callers (G-JUDGE-007, NG-JUDGE-004).
          The classifier prompt is fixed in code (NG-JUDGE-003).
        </div>

        <div style={{display: 'grid', gridTemplateColumns: '1fr', gap: 10, marginBottom: 14}}>
          <label style={{display: 'flex', flexDirection: 'column', gap: 4}}>
            <span className="dim" style={{fontSize: 11}}>Mode</span>
            <select value={draft.mode} onChange={e => setDraft({...draft, mode: e.target.value})}
              style={{padding: '6px 8px', background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-1)', fontSize: 12}}>
              <option value="openai_compatible">OpenAI-compatible (LM Studio, Ollama, vLLM, OpenAI)</option>
              <option value="anthropic">Anthropic Claude</option>
            </select>
          </label>
          {draft.mode === 'openai_compatible' && (
            <label style={{display: 'flex', flexDirection: 'column', gap: 4}}>
              <span className="dim" style={{fontSize: 11}}>Base URL</span>
              <input type="text" value={draft.base_url} onChange={e => setDraft({...draft, base_url: e.target.value})}
                placeholder="http://192.168.1.78:1234/v1"
                style={{padding: '6px 8px', background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-1)', fontSize: 12, fontFamily: 'var(--font-mono)'}}/>
            </label>
          )}
          <label style={{display: 'flex', flexDirection: 'column', gap: 4}}>
            <span className="dim" style={{fontSize: 11}}>Model</span>
            <input type="text" value={draft.model} onChange={e => setDraft({...draft, model: e.target.value})}
              placeholder={draft.mode === 'anthropic' ? 'claude-sonnet-4-5' : 'prompt-injection-judge-8b'}
              style={{padding: '6px 8px', background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-1)', fontSize: 12, fontFamily: 'var(--font-mono)'}}/>
          </label>
          <label style={{display: 'flex', flexDirection: 'column', gap: 4}}>
            <span className="dim" style={{fontSize: 11}}>API key {j.api_key && <span className="mono" style={{marginLeft: 6}}>({j.api_key})</span>}</span>
            <input type="password" value={draft.api_key} onChange={e => setDraft({...draft, api_key: e.target.value})}
              placeholder={draft.mode === 'anthropic' ? 'sk-ant-...' : '(optional for local endpoints)'}
              style={{padding: '6px 8px', background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-1)', fontSize: 12, fontFamily: 'var(--font-mono)'}}/>
          </label>
          <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10}}>
            <label style={{display: 'flex', flexDirection: 'column', gap: 4}}>
              <span className="dim" style={{fontSize: 11}}>Block threshold</span>
              <input type="number" min="0" max="1" step="0.05" value={draft.threshold}
                onChange={e => setDraft({...draft, threshold: e.target.value})}
                style={{padding: '6px 8px', background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-1)', fontSize: 12}}/>
            </label>
            <label style={{display: 'flex', alignItems: 'center', gap: 8, paddingTop: 18}}>
              <input type="checkbox" checked={!!draft.fail_open}
                onChange={e => setDraft({...draft, fail_open: e.target.checked})}/>
              <span style={{fontSize: 12}}>Fail open on judge error</span>
            </label>
          </div>
        </div>

        <div style={{display: 'flex', alignItems: 'center', gap: 12}}>
          <button className="btn" onClick={save} disabled={busy} style={{fontSize: 12}}>
            {busy ? 'Saving\u2026' : 'Save settings'}
          </button>
          <button className="btn"
            onClick={() => BulwarkStore.setJudgeEnabled(!j.enabled)}
            disabled={busy}
            style={{fontSize: 12}}>
            {j.enabled ? 'Disable judge' : 'Enable judge'}
          </button>
        </div>
      </div>
    </div>
  );
}

function BoundaryPane({ store, stage }) {
  return (
    <div className="card" style={{padding: 0}}>
      <DetailHeader stage={stage}/>
      <div style={{padding: '18px 24px 22px'}}>
        <div className="dim" style={{fontSize: 13, lineHeight: 1.5}}>
          The cleaned content is wrapped in trust-boundary tags before it
          leaves <span className="mono">/v1/clean</span>. The <span className="mono">format</span> field on the request
          chooses the boundary style &mdash; <span className="mono">xml</span> (default), <span className="mono">markdown</span>,
          or <span className="mono">delimiter</span>. Pick whichever your downstream LLM follows best.
          This is not a defense gate &mdash; it&rsquo;s how Bulwark formats safe output.
        </div>
        <div style={{marginTop: 14, padding: 12, background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 8, fontFamily: 'var(--font-mono)', fontSize: 11.5, color: 'var(--text-dim)'}}>
          {'<untrusted_input source="email" treat_as="data_only">'}
          <br />&nbsp;&nbsp;&hellip;cleaned content&hellip;
          <br />{'</untrusted_input>'}
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { PageConfigure });
