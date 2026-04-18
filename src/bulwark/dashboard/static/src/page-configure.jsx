// Configure page — one readable pipeline (vertical flow), each node = a real control.

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
          <div className="dim" style={{fontSize: 13, marginTop: 4, maxWidth: 560}}>
            Content flows top to bottom. Click any stage to configure it. Toggle the switch to remove it from the pipeline.
          </div>
        </div>
      </div>

      <div style={{display: 'grid', gridTemplateColumns: '420px 1fr', gap: 28, alignItems: 'start'}}>
        <PipelineFlow store={store} selected={selected} onSelect={setSelected} />
        <div style={{paddingTop: 72}}>
          <DetailPane store={store} selected={selected} />
        </div>
      </div>
    </div>
  );
}

// Pipeline stages — each has a real ID that maps to store.layerConfig.
// Colors reference the per-stage tokens in index.html :root (G-UI-TOKENS-002).
const STAGES = [
  { id: 'sanitizer', name: 'Sanitizer',         desc: 'Strip hidden chars, steganography, emoji smuggling',  tag: '<1ms',          color: 'var(--stage-sanitizer)' },
  { id: 'boundary',  name: 'Trust Boundary',    desc: 'Wrap untrusted content in XML boundary tags',         tag: 'deterministic', color: 'var(--stage-boundary)' },
  { id: 'detection', name: 'Detection',         desc: 'ProtectAI / PromptGuard classifiers',                 tag: '~30ms',         color: 'var(--stage-detection)' },
  { id: 'analyze',   name: 'Phase 1 — Analyze', desc: 'LLM reads content. No tools available.',              tag: 'LLM',           color: 'var(--stage-analyze)' },
  { id: 'bridge',    name: 'Bridge Guard',      desc: 'Check Phase 1 output for injection patterns',         tag: 'deterministic', color: 'var(--stage-bridge)' },
  { id: 'canary',    name: 'Canary Tokens',     desc: 'Detect exfil via embedded tripwire tokens',           tag: 'deterministic', color: 'var(--stage-canary)' },
  { id: 'execute',   name: 'Phase 2 — Execute', desc: 'LLM acts on analysis. Never sees raw content.',       tag: 'LLM',           color: 'var(--stage-execute)' },
];

function PipelineFlow({ store, selected, onSelect }) {
  const needsSetup = (id) => {
    if (id === 'analyze' || id === 'execute') return store.llm.status !== 'connected';
    if (id === 'detection') return !Object.values(store.integrations).some(v => v === 'active');
    return false;
  };

  // Phase 1 and Phase 2 share the LLM backend — visually bracket them.
  const isLLMStage = (id) => id === 'analyze' || id === 'execute';
  const llmSelected = selected === 'analyze' || selected === 'execute';

  return (
    <div style={{position: 'relative'}}>
      <div style={{display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, padding: '0 4px'}}>
        <span className="dim" style={{fontSize: 11, letterSpacing: '0.08em', textTransform: 'uppercase', fontWeight: 600}}>Pipeline</span>
        <span style={{flex: 1, height: 1, background: 'var(--hairline)'}}/>
        <span className="dim" style={{fontSize: 11}}>Click a stage to configure ›</span>
      </div>

      <div style={{display: 'flex', flexDirection: 'column', gap: 0, position: 'relative'}}>
        <FlowEndpoint label="Untrusted content" role="in" />
        {STAGES.map((stage, i) => {
          const prev = STAGES[i - 1];
          const next = STAGES[i + 1];
          const inLLMGroup = isLLMStage(stage.id);
          const prevInGroup = prev && isLLMStage(prev.id);
          const nextInGroup = next && isLLMStage(next.id);
          const grouped = inLLMGroup ? (prevInGroup ? (nextInGroup ? 'mid' : 'bot') : (nextInGroup ? 'top' : null)) : null;

          return (
            <React.Fragment key={stage.id}>
              {!prevInGroup || !inLLMGroup ? (
                <FlowConnector active={store.layerConfig[stage.id]} />
              ) : null}
              {grouped === 'top' && (
                <div style={{
                  marginBottom: -1, padding: '6px 14px 8px',
                  background: 'var(--surface)', border: '1px solid var(--border)',
                  borderBottom: 'none', borderRadius: '10px 10px 0 0',
                  display: 'flex', alignItems: 'center', gap: 8,
                }}>
                  <span className="label" style={{fontSize: 10, color: 'var(--stage-analyze)'}}>Shared LLM backend</span>
                  <span style={{flex: 1, height: 1, background: 'var(--hairline)'}}/>
                  <span className="dim" style={{fontSize: 10.5}}>configures both phases</span>
                </div>
              )}
              <FlowNode
                stage={stage}
                on={store.layerConfig[stage.id]}
                isSelected={selected === stage.id}
                onSelect={() => onSelect(stage.id)}
                onToggle={() => BulwarkStore.toggleLayer(stage.id)}
                stats={store.events.filter(e => e.layer === stage.id && Date.now() - e.ts < 24*3600*1000).length}
                needsAttention={needsSetup(stage.id)}
                grouped={grouped}
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

function FlowNode({ stage, on, isSelected, onSelect, onToggle, stats, needsAttention, grouped }) {
  const [hover, setHover] = React.useState(false);
  return (
    <button onClick={onSelect} onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)} style={{
      display: 'grid', gridTemplateColumns: 'auto auto 1fr auto auto auto',
      gap: 12, alignItems: 'center',
      padding: '14px 14px 14px 0', textAlign: 'left',
      background: isSelected ? 'var(--surface-2)' : (hover ? 'var(--surface)' : 'var(--surface)'),
      border: '1px solid ' + (isSelected ? `color-mix(in srgb, ${stage.color} 50%, transparent)` : (hover && on ? 'var(--border-2)' : 'var(--border)')),
      borderRadius: 10,
      opacity: on ? 1 : 0.6,
      transition: 'all 0.15s',
      cursor: 'pointer',
      boxShadow: isSelected ? `0 0 0 3px color-mix(in srgb, ${stage.color} 13%, transparent), inset 3px 0 0 ${stage.color}` : (hover ? 'inset 3px 0 0 var(--border-2)' : 'inset 3px 0 0 transparent'),
      position: 'relative',
      borderTopLeftRadius: grouped === 'top' ? 10 : (grouped === 'mid' || grouped === 'bot' ? 0 : 10),
      borderTopRightRadius: grouped === 'top' ? 10 : (grouped === 'mid' || grouped === 'bot' ? 0 : 10),
      borderBottomLeftRadius: grouped === 'bot' ? 10 : (grouped === 'mid' || grouped === 'top' ? 0 : 10),
      borderBottomRightRadius: grouped === 'bot' ? 10 : (grouped === 'mid' || grouped === 'top' ? 0 : 10),
      borderTop: grouped === 'mid' || grouped === 'bot' ? '1px solid var(--hairline)' : undefined,
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
      <div onClick={(e) => { e.stopPropagation(); onToggle(); }}>
        <Toggle on={on} onClick={() => {}} size="sm" />
      </div>
    </button>
  );
}

// -----------------------------------------------------------------------------
// Detail pane — context-dependent on selected stage
// -----------------------------------------------------------------------------
function DetailPane({ store, selected }) {
  const stage = STAGES.find(s => s.id === selected);
  if (!stage) return null;

  // LLM stages use the LLM backend panel
  if (selected === 'analyze' || selected === 'execute') {
    return <LLMBackendPane store={store} selected={selected} stage={stage} />;
  }
  if (selected === 'detection') {
    return <DetectionPane store={store} stage={stage} />;
  }
  if (selected === 'sanitizer') {
    return <SanitizerPane store={store} stage={stage} />;
  }
  if (selected === 'bridge') {
    return <BridgePane store={store} stage={stage} />;
  }
  if (selected === 'canary') {
    return <CanaryPane store={store} stage={stage} />;
  }
  // Default (boundary)
  return <GenericPane stage={stage} />;
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
    <div style={{
      display: 'flex', alignItems: 'center', gap: 14,
      padding: '12px 0', borderBottom: '1px solid var(--hairline)',
    }}>
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

function BridgePane({ store, stage }) {
  // Patterns come from store.guardPatterns (populated from /api/config.guard_patterns).
  // Live hit counts aren't aggregated yet — we show no count rather than fake one
  // (NG-UI-CONFIG-002).
  const patterns = Array.isArray(store.guardPatterns) ? store.guardPatterns : [];
  return (
    <div className="card" style={{padding: 0}}>
      <DetailHeader stage={stage}/>
      <div style={{padding: '8px 24px 22px'}}>
        <SubToggle name="Require JSON" desc="Enforce valid JSON output from Phase 1"
          on={store.layerConfig.require_json} onToggle={() => BulwarkStore.toggleLayer('require_json')}/>
        <div style={{padding: '14px 0'}}>
          <div className="label" style={{marginBottom: 6}}>Block patterns <span className="mono dim" style={{marginLeft: 8, letterSpacing: 0, textTransform: 'none', fontSize: 11}}>{patterns.length}</span></div>
          <div className="dim" style={{fontSize: 12, marginBottom: 10}}>Regex patterns that block Phase 1 output from reaching Phase 2. Configure via <span className="mono">bulwark-config.yaml</span>.</div>
          {patterns.length === 0 ? (
            <div className="empty-slate" style={{padding: 20, border: '1px dashed var(--border)', borderRadius: 8, fontSize: 12}}>
              No guard patterns configured.
            </div>
          ) : (
            <div style={{background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 8, padding: 4, fontFamily: 'var(--font-mono)', fontSize: 11.5, maxHeight: 260, overflow: 'auto'}}>
              {patterns.map((p, i) => (
                <div key={i} style={{display: 'flex', alignItems: 'center', gap: 10, padding: '7px 10px', borderBottom: i < patterns.length - 1 ? '1px solid var(--hairline)' : 'none'}}>
                  <span style={{flex: 1, color: 'var(--amber)', wordBreak: 'break-all'}}>{p}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function CanaryPane({ store, stage }) {
  const tokens = store.canaryTokens && typeof store.canaryTokens === 'object' ? store.canaryTokens : {};
  const entries = Object.entries(tokens);
  return (
    <div className="card" style={{padding: 0}}>
      <DetailHeader stage={stage}/>
      <div style={{padding: '8px 24px 22px'}}>
        <SubToggle name="Encoding-resistant variants" desc="Check base64, hex, reversed, case-insensitive"
          on={store.layerConfig.encoding_canaries} onToggle={() => BulwarkStore.toggleLayer('encoding_canaries')}/>
        <div style={{padding: '14px 0'}}>
          <div className="label" style={{marginBottom: 10}}>
            Active canaries
            <span className="mono dim" style={{marginLeft: 8, letterSpacing: 0, textTransform: 'none', fontSize: 11}}>{entries.length} token{entries.length === 1 ? '' : 's'}</span>
          </div>
          {entries.length === 0 ? (
            <div className="empty-slate" style={{padding: 20, border: '1px dashed var(--border)', borderRadius: 8, fontSize: 12}}>
              No canary tokens configured. Add entries to <span className="mono">bulwark-config.yaml</span> under <span className="mono">canary_tokens</span>.
            </div>
          ) : (
            <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8}}>
              {entries.map(([src, token]) => (
                <div key={src} style={{padding: 12, background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 8}}>
                  <div className="label" style={{marginBottom: 4}}>{src}</div>
                  <div className="mono" style={{fontSize: 11, color: 'var(--amber)', wordBreak: 'break-all'}}>{token}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function DetectionPane({ store, stage }) {
  const items = [
    { id: 'protectai', name: 'ProtectAI DeBERTa', desc: 'Prompt injection classifier. Ungated. Recommended default.', latency: '~30ms', size: '180MB' },
    { id: 'promptguard', name: 'PromptGuard-86M', desc: "Meta's mDeBERTa classifier. Requires HuggingFace approval.", latency: '~50ms', size: '86M params' },
  ];
  // Sort: active first.
  const sorted = [...items].sort((a, b) => {
    const aOn = store.integrations[a.id] === 'active' ? 0 : 1;
    const bOn = store.integrations[b.id] === 'active' ? 0 : 1;
    return aOn - bOn;
  });
  const anyActive = sorted.some(it => store.integrations[it.id] === 'active');

  return (
    <div className="card" style={{padding: 0}}>
      <DetailHeader stage={stage}/>
      <div style={{padding: '14px 24px 22px'}}>
        <div className="dim" style={{fontSize: 12.5, marginBottom: 14}}>Detection models run in parallel; any positive classification blocks the request before it reaches the LLM.</div>

        <div className="label" style={{marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8}}>
          <span>In use</span>
          <span style={{flex: 1, height: 1, background: 'var(--hairline)'}}/>
        </div>
        {sorted.filter(it => store.integrations[it.id] === 'active').map(it => (
          <DetectionCard key={it.id} item={it} active={true} onToggle={() => BulwarkStore.setIntegration(it.id, 'available')}/>
        ))}
        {!anyActive && (
          <div style={{padding: 14, marginBottom: 14, background: 'var(--amber-soft)', border: '1px dashed var(--amber-line)', borderRadius: 10, fontSize: 12.5, color: 'var(--amber)'}}>
            No detection model active — activate one below to enable this stage.
          </div>
        )}

        <div className="label" style={{marginTop: 18, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8}}>
          <span>Available</span>
          <span style={{flex: 1, height: 1, background: 'var(--hairline)'}}/>
        </div>
        {sorted.filter(it => store.integrations[it.id] !== 'active').map(it => (
          <DetectionCard key={it.id} item={it} active={false} onToggle={() => BulwarkStore.setIntegration(it.id, 'active')}/>
        ))}
      </div>
    </div>
  );
}

function DetectionCard({ item, active, onToggle }) {
  return (
    <div style={{
      padding: 14, marginBottom: 10,
      background: active ? 'var(--surface-2)' : 'var(--bg-2)',
      border: '1px solid ' + (active ? 'var(--accent-line)' : 'var(--border)'),
      borderRadius: 10,
      display: 'grid', gridTemplateColumns: '1fr auto', gap: 14, alignItems: 'center',
      boxShadow: active ? '0 0 0 2px var(--accent-soft)' : 'none',
      opacity: active ? 1 : 0.85,
    }}>
      <div>
        <div style={{display: 'flex', alignItems: 'center', gap: 8}}>
          <span style={{fontSize: 13.5, fontWeight: 600}}>{item.name}</span>
          {active && <span className="pill ok" style={{fontSize: 10.5}}><Dot kind="green" size={5}/> Active</span>}
        </div>
        <div className="dim" style={{fontSize: 12, marginTop: 2, lineHeight: 1.45}}>{item.desc}</div>
        <div className="dim mono" style={{fontSize: 11, marginTop: 6}}>{item.latency} · {item.size}</div>
      </div>
      <button className={'btn ' + (active ? '' : 'btn-primary')} onClick={onToggle}>
        {active ? 'Disable' : 'Activate'}
      </button>
    </div>
  );
}

function LLMBackendPane({ store, selected, stage }) {
  const modes = [
    { id: 'none', name: 'Sanitize only', desc: 'Deterministic layers only' },
    { id: 'anthropic', name: 'Anthropic', desc: 'Claude via Anthropic SDK' },
    { id: 'openai_compatible', name: 'OpenAI compatible', desc: 'Ollama, vLLM, any endpoint' },
  ];

  // Editable fields — staged locally so the user can edit without saving on every keystroke.
  const [apiKey, setApiKey] = React.useState('');
  const [baseUrl, setBaseUrl] = React.useState(store.llm.baseUrl || '');
  const [analyzeModel, setAnalyzeModel] = React.useState(store.llm.analyzeModel || '');
  const [executeModel, setExecuteModel] = React.useState(store.llm.executeModel || '');

  // Sync local inputs to store on mode changes.
  React.useEffect(() => {
    setBaseUrl(store.llm.baseUrl || '');
    setAnalyzeModel(store.llm.analyzeModel || '');
    setExecuteModel(store.llm.executeModel || '');
    setApiKey('');
  }, [store.llm.mode, store.llm.baseUrl, store.llm.analyzeModel, store.llm.executeModel]);

  // Populate model list whenever mode or base_url changes — G-UI-CONFIG-002.
  React.useEffect(() => {
    if (store.llm.mode !== 'none') BulwarkStore.fetchModels();
  }, [store.llm.mode, store.llm.baseUrl]);

  // An env var sets the default source for a field. The UI stays editable —
  // users can override for the current session (in-memory), and the env value
  // is restored on dashboard restart. save() always sends every field the user
  // edited; the backend skips only empty-string updates to env-shadowed fields
  // (G-ENV-012), so blanks don't clobber defaults.
  const envOverrides = store.llm.envOverrides || {};
  const envDefault = (field) => envOverrides[field];

  const save = () => {
    const patch = {
      analyzeModel,
      executeModel,
      baseUrl,
    };
    if (apiKey) patch.apiKey = apiKey;
    BulwarkStore.setLlm(patch);
  };

  // Small badge + env-var hint for fields the user can still override.
  const EnvBadge = ({ envVar }) => (
    <span className="pill warn" data-hint={`Default from ${envVar}. Edits override for this session.`}
      style={{fontSize: 10, padding: '1px 7px', letterSpacing: '0.08em'}}>ENV</span>
  );

  return (
    <div className="card" style={{padding: 0}}>
      <div style={{padding: '22px 24px 18px', borderBottom: '1px solid var(--border)'}}>
        <div className="label" style={{color: stage.color}}>Stage settings · Phase 1 + Phase 2</div>
        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginTop: 6, gap: 14}}>
          <div>
            <h3 style={{fontSize: 18, fontWeight: 600, letterSpacing: '-0.01em'}}>LLM backend</h3>
            <div className="dim" style={{fontSize: 13, marginTop: 4, maxWidth: 520}}>Shared by both Phase 1 (analyze) and Phase 2 (execute). You can pick different models per phase below.</div>
          </div>
          {store.llm.status === 'loading' ? (
            <span className="pill warn"><Dot kind="warn" size={6}/> Testing…</span>
          ) : store.llm.status === 'connected' ? (
            <span className="pill ok"><Dot kind="green" size={6}/> {store.llm.mode === 'none' ? 'Sanitize-only' : 'Connected'}</span>
          ) : (
            <span className="pill bad"><Dot kind="bad" size={6}/> Unreachable</span>
          )}
        </div>
      </div>

      <div style={{padding: '18px 24px 22px'}}>
        {/* ─── SHARED BY BOTH PHASES ─── */}
        <div className="label" data-section="shared"
          style={{color: 'var(--accent)', marginBottom: 12, fontSize: 10.5, letterSpacing: '0.14em'}}>
          Shared by both phases
        </div>

        <div className="label" style={{marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8}}>
          <span>Backend</span>
          {envDefault('mode') && <EnvBadge envVar="BULWARK_LLM_MODE"/>}
        </div>
        <div style={{display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginBottom: envDefault('mode') ? 6 : 18}}>
          {modes.map(m => {
            const active = store.llm.mode === m.id;
            return (
              <button key={m.id}
                onClick={() => BulwarkStore.setLlm({mode: m.id})}
                style={{
                  padding: 12, borderRadius: 8, textAlign: 'left',
                  background: active ? 'var(--accent-soft)' : 'var(--bg-2)',
                  border: '1px solid ' + (active ? 'var(--accent-line)' : 'var(--border)'),
                  cursor: 'pointer',
                }}>
                <div style={{fontSize: 12.5, fontWeight: 600, color: active ? 'var(--accent)' : 'var(--text)'}}>
                  {m.name} {active && '✓'}
                </div>
                <div className="dim" style={{fontSize: 11, marginTop: 2, lineHeight: 1.4}}>{m.desc}</div>
              </button>
            );
          })}
        </div>
        {envDefault('mode') && (
          <div className="dim" style={{fontSize: 11, marginBottom: 18}}>
            Env default: <span className="mono">BULWARK_LLM_MODE</span>. Your selection overrides for this session.
          </div>
        )}

        {store.llm.mode !== 'none' && (
          <>
            {store.llm.mode === 'openai_compatible' && (
              <div style={{marginBottom: 14}}>
                <div className="label" style={{marginBottom: 6, display: 'flex', alignItems: 'center', gap: 8}}>
                  <span>Base URL</span>
                  {envDefault('base_url') && <EnvBadge envVar="BULWARK_BASE_URL"/>}
                </div>
                <input className="input" value={baseUrl} onChange={e => setBaseUrl(e.target.value)}
                  placeholder="http://localhost:1234/v1"
                  style={{fontFamily: 'var(--font-mono)', fontSize: 12.5}}/>
                {envDefault('base_url') && (
                  <div className="dim" style={{fontSize: 11, marginTop: 4}}>
                    Env default: <span className="mono">BULWARK_BASE_URL</span>. Edit to override for this session.
                  </div>
                )}
              </div>
            )}

            <div style={{marginBottom: 22}}>
              <div className="label" style={{marginBottom: 6, display: 'flex', alignItems: 'center', gap: 8}}>
                <span>API Key</span>
                {envDefault('api_key') && <EnvBadge envVar="BULWARK_API_KEY"/>}
              </div>
              <input className="input" type="password"
                value={apiKey} onChange={e => setApiKey(e.target.value)}
                placeholder={store.llm.apiKeySet ? store.llm.apiKeyPreview : 'Paste API key'}
                style={{fontFamily: 'var(--font-mono)'}}/>
              <div className="dim" style={{fontSize: 11, marginTop: 4}}>
                {envDefault('api_key')
                  ? <>Env default: <span className="mono">BULWARK_API_KEY</span> ({store.llm.apiKeyPreview || '•••'}). Type a new key to override for this session — env restores on restart.</>
                  : <>Set <span className="mono">BULWARK_API_KEY</span> env var for persistence across restarts.</>}
              </div>
            </div>

            {/* ─── PER PHASE ─── */}
            <div className="label" data-section="per-phase"
              style={{color: 'var(--stage-analyze)', marginBottom: 12, fontSize: 10.5, letterSpacing: '0.14em'}}>
              Per phase
            </div>
            <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 18}}>
              <PhaseCard
                phaseId="analyze"
                selected={selected === 'analyze'}
                model={analyzeModel}
                onChangeModel={setAnalyzeModel}
                models={store.models}
                modelsLoading={store.modelsLoading}
                envDefault={envDefault('analyze_model')}
                envVar="BULWARK_ANALYZE_MODEL"
              />
              <PhaseCard
                phaseId="execute"
                selected={selected === 'execute'}
                model={executeModel}
                onChangeModel={setExecuteModel}
                models={store.models}
                modelsLoading={store.modelsLoading}
                envDefault={envDefault('execute_model')}
                envVar="BULWARK_EXECUTE_MODEL"
              />
            </div>

            <div style={{display: 'flex', gap: 8}}>
              <button className="btn" onClick={() => BulwarkStore.testConnection()}
                disabled={store.llm.status === 'loading'}>
                {store.llm.status === 'loading' ? 'Testing…' : 'Test connection'}
              </button>
              <button className="btn btn-primary" style={{marginLeft: 'auto'}}
                onClick={save}>Save</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// One phase card — "Phase N · Verb" header + description + MODEL dropdown
// stacked inline. Highlights via accent when selected from the pipeline flow.
function PhaseCard({ phaseId, selected, model, onChangeModel, models, modelsLoading, envDefault, envVar }) {
  const meta = phaseId === 'analyze'
    ? { num: 1, verb: 'Analyze', desc: 'Reads untrusted content · no tools', token: 'var(--stage-analyze)' }
    : { num: 2, verb: 'Execute', desc: 'Acts on analysis · never sees raw', token: 'var(--stage-execute)' };
  return (
    <div data-phase={phaseId} style={{
      padding: 14,
      background: selected ? 'var(--accent-soft)' : 'var(--bg-2)',
      border: '1px solid ' + (selected ? 'var(--accent-line)' : 'var(--border)'),
      borderRadius: 10,
      transition: 'all 0.15s',
    }}>
      <div className="label" style={{fontSize: 10, color: meta.token, display: 'flex', alignItems: 'center', gap: 8}}>
        <span>Phase {meta.num} · {meta.verb}</span>
        {envDefault && <EnvBadgeStatic envVar={envVar}/>}
      </div>
      <div className="dim" style={{fontSize: 12, marginTop: 4, lineHeight: 1.4}}>{meta.desc}</div>

      <div className="label" style={{marginTop: 14, marginBottom: 6, fontSize: 10}}>Model</div>
      <ModelDropdown
        value={model}
        onChange={onChangeModel}
        models={models}
        loading={modelsLoading}
        phase={phaseId}
      />
      {envDefault && (
        <div className="dim" style={{fontSize: 11, marginTop: 6}}>
          Env default: <span className="mono">{envVar}</span>
        </div>
      )}
    </div>
  );
}

// Tiny local ENV pill for nested use inside PhaseCard (the outer one has the
// "session-override" tooltip which is wrong inside a card-level context).
function EnvBadgeStatic({ envVar }) {
  return (
    <span className="pill warn" data-hint={`Default from ${envVar}`}
      style={{fontSize: 9, padding: '0 6px', letterSpacing: '0.08em'}}>ENV</span>
  );
}

// Just the <select> — label + env hint live on the wrapping PhaseCard so the
// model dropdown nests cleanly inside one unified per-phase block.
function ModelDropdown({ value, onChange, models, loading, phase }) {
  const options = Array.isArray(models) ? models.filter(m =>
    !m.recommended_for || m.recommended_for.includes(phase) || m.recommended_for.includes('analyze')
  ) : [];
  return (
    <select className="input" value={value} onChange={e => onChange(e.target.value)} disabled={loading}>
      <option value="">{loading ? 'Loading models…' : (options.length ? '— pick a model —' : 'No models available')}</option>
      {options.map(m => (
        <option key={m.id} value={m.id}>{m.name || m.id}</option>
      ))}
      {/* Keep the current value visible even if it isn't in the discovered list
          (custom model names, env-shadowed unknowns). */}
      {value && !options.some(m => m.id === value) && (
        <option key={value} value={value}>{value}</option>
      )}
    </select>
  );
}

function GenericPane({ stage }) {
  return (
    <div className="card" style={{padding: 0}}>
      <DetailHeader stage={stage}/>
      <div style={{padding: 24}}>
        <div className="dim" style={{fontSize: 13}}>This stage has no additional settings — it's either on or off.</div>
      </div>
    </div>
  );
}

Object.assign(window, { PageConfigure });
