"""Spec-driven tests for dashboard Configure page — spec/contracts/dashboard_ui.yaml."""
import re
from pathlib import Path


SRC = Path(__file__).parent.parent / "src" / "bulwark" / "dashboard" / "static" / "src"
PAGE_CONFIGURE = SRC / "page-configure.jsx"
DATA_JSX = SRC / "data.jsx"


def _configure_src():
    return PAGE_CONFIGURE.read_text()


def _data_src():
    return DATA_JSX.read_text()


# ---------------------------------------------------------------------------
# G-UI-TOKENS-002 — STAGES colors use tokens only
# ---------------------------------------------------------------------------


class TestStageTokens:
    def test_stages_no_hex_colors(self):
        """G-UI-TOKENS-002: STAGES array uses var(--stage-*) tokens, no hex."""
        src = _configure_src()
        stages_block = re.search(r"const STAGES = \[.*?\];", src, flags=re.DOTALL)
        assert stages_block, "STAGES array not found"
        body = stages_block.group(0)
        assert not re.search(r"#[0-9a-fA-F]{3,6}", body), (
            "STAGES still contains hex color: " + body
        )
        for stage in ("sanitizer", "boundary", "detection", "analyze", "bridge", "canary", "execute"):
            assert f"var(--stage-{stage})" in body, f"STAGES missing --stage-{stage}"

    def test_file_has_no_remaining_hex_colors(self):
        """G-UI-TOKENS-002: entire page-configure.jsx has no hex literals."""
        src = _configure_src()
        # Strip commented-out lines so they don't trip us up (we have none today):
        assert not re.search(r"#[0-9a-fA-F]{3,6}", src), (
            "page-configure.jsx still contains hex color literals"
        )


# ---------------------------------------------------------------------------
# G-UI-NEEDS-001 / 002 — Needs setup pill triggers
# ---------------------------------------------------------------------------


class TestNeedsSetup:
    def test_analyze_and_execute_use_llm_status_check(self):
        """G-UI-NEEDS-001: analyze/execute show 'Needs setup' when llm.status != 'connected'."""
        src = _configure_src()
        needs_fn = re.search(
            r"const needsSetup = \(id\) => \{.*?\};",
            src, flags=re.DOTALL,
        )
        assert needs_fn, "needsSetup helper not found in PipelineFlow"
        body = needs_fn.group(0)
        assert "id === 'analyze' || id === 'execute'" in body
        assert "store.llm.status !== 'connected'" in body

    def test_detection_uses_integrations_active_check(self):
        """G-UI-NEEDS-002: detection shows 'Needs setup' when no integration is active."""
        src = _configure_src()
        needs_fn = re.search(
            r"const needsSetup = \(id\) => \{.*?\};",
            src, flags=re.DOTALL,
        )
        assert needs_fn
        body = needs_fn.group(0)
        assert "id === 'detection'" in body
        assert "store.integrations" in body
        assert "v === 'active'" in body


# ---------------------------------------------------------------------------
# G-UI-CONFIG-ENV-BADGE / G-UI-CONFIG-ENV-EDITABLE / G-UI-CONFIG-ENV-OVERRIDE
# Env vars are defaults, not locks — per ADR-022.
# ---------------------------------------------------------------------------


class TestEnvBadges:
    def test_env_badge_rendered_when_override_present(self):
        """G-UI-CONFIG-ENV-BADGE: ENV badge appears next to env-shadowed field labels."""
        src = _configure_src()
        # Shared EnvBadge component renders 'ENV' with warn pill styling:
        assert "const EnvBadge" in src
        assert '>ENV<' in src
        # Labels conditionally render the badge off envDefault():
        for field in ("mode", "api_key", "base_url", "analyze_model", "execute_model"):
            assert f"envDefault('{field}')" in src, (
                f"LLMBackendPane must branch on envDefault('{field}') to render the ENV badge"
            )

    def test_env_badge_cites_env_var_name(self):
        """G-UI-CONFIG-ENV-BADGE: helper text names the source env var."""
        src = _configure_src()
        for env_var in (
            "BULWARK_LLM_MODE", "BULWARK_API_KEY", "BULWARK_BASE_URL",
            "BULWARK_ANALYZE_MODEL", "BULWARK_EXECUTE_MODEL",
        ):
            assert env_var in src


class TestEnvEditable:
    def test_api_key_is_always_an_input(self):
        """G-UI-CONFIG-ENV-EDITABLE: API key renders <input type='password'>, never a read-only <div>."""
        src = _configure_src()
        # Controlled input bound to local state:
        assert "const [apiKey, setApiKey] = React.useState('')" in src
        assert 'type="password"' in src
        assert "value={apiKey}" in src
        assert "onChange={e => setApiKey(e.target.value)}" in src
        # The env-lock read-only branch is gone:
        assert "apiKeyLockedByEnv ? (" not in src
        assert "const apiKeyLockedByEnv" not in src

    def test_base_url_is_always_an_input(self):
        """G-UI-CONFIG-ENV-EDITABLE: base URL always rendered as <input>, never read-only."""
        src = _configure_src()
        assert "baseUrlLockedByEnv ? (" not in src
        assert "const baseUrlLockedByEnv" not in src
        # Still bound to local state:
        assert "value={baseUrl} onChange={e => setBaseUrl(e.target.value)}" in src

    def test_mode_cards_clickable_even_with_env(self):
        """G-UI-CONFIG-ENV-EDITABLE: mode cards have no disabled attribute."""
        src = _configure_src()
        assert "disabled={disabled}" not in src
        assert "const disabled = modeLockedByEnv" not in src
        # Every mode button goes through setLlm unconditionally:
        assert "onClick={() => BulwarkStore.setLlm({mode: m.id})}" in src

    def test_model_dropdowns_always_selectable(self):
        """G-UI-CONFIG-ENV-EDITABLE: per-phase model dropdown never swaps select for a read-only div."""
        src = _configure_src()
        # The lockedByEnv branch that swapped select→div is removed:
        assert "if (lockedByEnv)" not in src
        # ModelDropdown renders a plain <select>; PhaseCard handles label + env hint.
        assert "function ModelDropdown({ value, onChange, models, loading, phase })" in src


class TestLlmSectionLayout:
    def test_two_eyebrow_sections_rendered(self):
        """G-UI-CONFIG-LLM-SECTIONS-001: Shared + Per-phase sections both present."""
        src = _configure_src()
        assert 'data-section="shared"' in src
        assert 'Shared by both phases' in src
        assert 'data-section="per-phase"' in src
        assert 'Per phase' in src

    def test_shared_section_uses_accent_color(self):
        """G-UI-CONFIG-LLM-SECTIONS-001: SHARED eyebrow uses var(--accent) (teal)."""
        src = _configure_src()
        m = re.search(r'data-section="shared"[^>]*style=\{\{[^}]*color:\s*\'var\(--accent\)\'', src)
        assert m, 'SHARED eyebrow must use var(--accent)'

    def test_per_phase_section_uses_violet_color(self):
        """G-UI-CONFIG-LLM-SECTIONS-001: PER PHASE eyebrow uses var(--stage-analyze) (violet)."""
        src = _configure_src()
        m = re.search(r'data-section="per-phase"[^>]*style=\{\{[^}]*color:\s*\'var\(--stage-analyze\)\'', src)
        assert m, 'PER PHASE eyebrow must use var(--stage-analyze)'

    def test_phase_card_bundles_model_dropdown(self):
        """G-UI-CONFIG-LLM-SECTIONS-002: PhaseCard contains the model label + dropdown inline."""
        src = _configure_src()
        # Find the function body opening brace (skip past the destructured params).
        start = src.index("function PhaseCard(")
        body_open = src.index("{", src.index(")", start))  # the `{` after `) {`
        depth, i = 0, body_open
        while i < len(src):
            ch = src[i]
            if ch == "{": depth += 1
            elif ch == "}": depth -= 1
            if depth == 0 and ch == "}": break
            i += 1
        body = src[start:i + 1]
        # Renders a MODEL label + inline ModelDropdown:
        assert ">Model<" in body
        assert "<ModelDropdown" in body
        # Plus the phase header and description:
        assert "Phase {meta.num} · {meta.verb}" in body

    def test_phase_card_highlights_when_selected(self):
        """G-UI-CONFIG-LLM-SECTIONS-002: PhaseCard uses accent-soft bg when selected."""
        src = _configure_src()
        assert "selected ? 'var(--accent-soft)' : 'var(--bg-2)'" in src
        assert "selected ? 'var(--accent-line)' : 'var(--border)'" in src

    def test_env_badge_shown_inside_phase_card(self):
        """G-UI-CONFIG-LLM-SECTIONS-003: env-shadowed model shows EnvBadgeStatic + default line."""
        src = _configure_src()
        assert "function EnvBadgeStatic" in src
        assert "<EnvBadgeStatic envVar={envVar}/>" in src
        # Dim helper under the dropdown:
        assert "Env default: <span className=\"mono\">{envVar}</span>" in src


class TestEnvOverride:
    def test_save_sends_every_edited_field(self):
        """G-UI-CONFIG-ENV-OVERRIDE: save() patches every field, not just unlocked ones."""
        src = _configure_src()
        # The Stage-7 branch that skipped env-locked fields is gone:
        assert "if (!analyzeLockedByEnv) patch.analyzeModel" not in src
        assert "if (!executeLockedByEnv) patch.executeModel" not in src
        assert "if (!baseUrlLockedByEnv) patch.baseUrl" not in src
        # Find the save handler body by brace matching (it contains a nested {}).
        start = src.index("const save = () => {")
        # Walk forward until braces balance:
        depth, i = 0, start
        while i < len(src):
            ch = src[i]
            if ch == "{": depth += 1
            elif ch == "}": depth -= 1
            if depth == 0 and ch == "}":
                break
            i += 1
        body = src[start:i + 1]
        assert "analyzeModel," in body
        assert "executeModel," in body
        assert "baseUrl," in body
        # apiKey still gated on a non-empty user input (avoid sending a blank):
        assert "if (apiKey) patch.apiKey = apiKey" in body


# ---------------------------------------------------------------------------
# G-UI-CONFIG-MODELS-* — model fetch + dropdown wiring
# ---------------------------------------------------------------------------


class TestModels:
    def test_fetch_models_on_mode_and_baseurl_change(self):
        """G-UI-CONFIG-MODELS-001: LLMBackendPane calls fetchModels on mode/base_url change."""
        src = _configure_src()
        effect = re.search(
            r"React\.useEffect\(\(\) => \{\s*if \(store\.llm\.mode !== 'none'\) BulwarkStore\.fetchModels\(\);\s*\}, \[store\.llm\.mode, store\.llm\.baseUrl\]\)",
            src,
        )
        assert effect, "Expected fetchModels effect keyed on mode + baseUrl"

    def test_dropdowns_read_from_store_models(self):
        """G-UI-CONFIG-MODELS-001: ModelDropdown maps store.models into <option>s — no inline list."""
        src = _configure_src()
        assert "<ModelDropdown" in src
        body = re.search(r"function ModelDropdown.*?\n\}\n", src, flags=re.DOTALL).group(0)
        assert "options.map(m =>" in body
        # No hardcoded claude-* model names in the component:
        assert "claude-haiku" not in body
        assert "claude-opus"  not in body

    def test_store_fetchmodels_posts_llm_models(self):
        """G-UI-CONFIG-MODELS-002: fetchModels() POSTs /v1/llm/models and sets modelsLoading."""
        src = _data_src()
        assert "async fetchModels()" in src, "fetchModels not found on the store"
        # These strings only appear inside fetchModels (verified manually):
        assert "state.modelsLoading = true" in src
        assert "/v1/llm/models" in src
        assert "state.modelsLoading = false" in src
        # Verify the POST + store update land in the same function:
        fetch_start = src.index("async fetchModels()")
        # Next sibling method starts with `async ` or `},\n\n    async`.
        fetch_end = src.index("\n    },\n", fetch_start)
        body = src[fetch_start:fetch_end]
        assert "method: 'POST'" in body
        assert "state.models" in body


class TestTestConnection:
    def test_store_test_connection_posts_llm_test(self):
        """G-UI-CONFIG-TEST-CONNECTION: testConnection() POSTs /v1/llm/test and updates status."""
        src = _data_src()
        assert "async testConnection()" in src, "testConnection not found on the store"
        start = src.index("async testConnection()")
        end = src.index("\n    },\n", start)
        body = src[start:end]
        assert "/v1/llm/test" in body
        assert "state.llm = { ...state.llm, status: 'loading' }" in body
        assert "status: ok ? 'connected' : 'error'" in body

    def test_test_connection_button_wired(self):
        """G-UI-CONFIG-TEST-CONNECTION: LLMBackendPane has a button calling testConnection()."""
        src = _configure_src()
        assert "onClick={() => BulwarkStore.testConnection()}" in src


# ---------------------------------------------------------------------------
# G-UI-CONFIG-CANARIES-001 / G-UI-CONFIG-PATTERNS-001
# ---------------------------------------------------------------------------


class TestCanaryPane:
    def test_reads_from_store(self):
        """G-UI-CONFIG-CANARIES-001: CanaryPane iterates store.canaryTokens, no rand()."""
        src = _configure_src()
        fn = re.search(r"function CanaryPane.*?\n\}\n", src, flags=re.DOTALL)
        assert fn
        body = fn.group(0)
        assert "store.canaryTokens" in body
        # No random-generated token values:
        assert "rand(" not in body
        assert "BLWK-" not in body  # old faked prefix

    def test_empty_state_points_to_config_file(self):
        """G-UI-CONFIG-CANARIES-001: empty state names the config file."""
        src = _configure_src()
        fn = re.search(r"function CanaryPane.*?\n\}\n", src, flags=re.DOTALL)
        assert fn
        body = fn.group(0)
        assert "bulwark-config.yaml" in body
        assert "No canary tokens configured" in body


class TestBridgePane:
    def test_reads_patterns_from_store(self):
        """G-UI-CONFIG-PATTERNS-001: BridgePane renders store.guardPatterns, no hardcoded list."""
        src = _configure_src()
        fn = re.search(r"function BridgePane.*?\n\}\n", src, flags=re.DOTALL)
        assert fn
        body = fn.group(0)
        assert "store.guardPatterns" in body
        # No hardcoded regex list from the old reference:
        assert "ignore (all |)?previous" not in body
        assert "you are (now |)(DAN|a )" not in body

    def test_no_random_hit_counts(self):
        """NG-UI-CONFIG-002: BridgePane does not show random hit counts."""
        src = _configure_src()
        fn = re.search(r"function BridgePane.*?\n\}\n", src, flags=re.DOTALL)
        assert fn
        body = fn.group(0)
        assert "rand(" not in body
        assert "hits" not in body

    def test_empty_state_points_to_config_file(self):
        """G-UI-CONFIG-PATTERNS-001: empty state names the config file."""
        src = _configure_src()
        fn = re.search(r"function BridgePane.*?\n\}\n", src, flags=re.DOTALL)
        assert fn
        body = fn.group(0)
        assert "bulwark-config.yaml" in body
        assert "No guard patterns configured" in body




class TestDataStoreShape:
    def test_store_exposes_configure_fields(self):
        """Store state has guardPatterns, canaryTokens, models, modelsLoading."""
        src = _data_src()
        for field in ("guardPatterns", "canaryTokens", "models", "modelsLoading"):
            assert field in src, f"data.jsx state missing {field}"

    def test_initial_load_pipes_patterns_and_canaries(self):
        """data.jsx _loadInitial extracts guard_patterns + canary_tokens from config."""
        src = _data_src()
        assert "state.guardPatterns = Array.isArray(configR.value.guard_patterns)" in src
        assert "state.canaryTokens = (configR.value.canary_tokens" in src


class TestNonGuarantees:
    def test_no_inline_pattern_editor(self):
        """NG-UI-CONFIG-001: guard patterns are not inline-editable."""
        src = _configure_src()
        fn = re.search(r"function BridgePane.*?\n\}\n", src, flags=re.DOTALL)
        assert fn
        body = fn.group(0)
        # No textarea / input / contentEditable for patterns:
        assert "<textarea" not in body
        assert "+ Add pattern" not in body

    def test_no_inline_canary_editor(self):
        """NG-UI-CONFIG-001: canary tokens are not inline-editable."""
        src = _configure_src()
        fn = re.search(r"function CanaryPane.*?\n\}\n", src, flags=re.DOTALL)
        assert fn
        body = fn.group(0)
        assert "<textarea" not in body
        assert "<input" not in body
