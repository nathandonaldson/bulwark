"""Comprehensive tests for the canary token system."""
import json
import os
import pytest

from bulwark.canary import CanarySystem, CanaryCheckResult, CanaryLeakError


# ---------------------------------------------------------------------------
# Token generation
# ---------------------------------------------------------------------------

class TestTokenGeneration:
    def test_generate_creates_token_with_correct_prefix(self, canary):
        token = canary.generate("user_data")
        assert token.startswith("BLWK-CANARY-")

    def test_generate_creates_unique_tokens_each_call(self, canary):
        t1 = canary.generate("source_a")
        t2 = canary.generate("source_b")
        assert t1 != t2

    def test_generate_unique_even_for_same_source(self):
        """Calling generate twice for the same source overwrites but produces a different token."""
        cs = CanarySystem()
        t1 = cs.generate("data")
        t2 = cs.generate("data")
        # Tokens are random, so they should differ (astronomically unlikely to collide)
        assert t1 != t2

    def test_generate_stores_token_in_tokens_dict(self, canary):
        token = canary.generate("user_data")
        assert canary.tokens["user_data"] == token

    def test_generate_formats_source_name_uppercase_dashes(self, canary):
        token = canary.generate("my source_name")
        # "my source_name" -> "MY-SOURCE-N" (upper, spaces/underscores to dashes, truncated to 10)
        assert "BLWK-CANARY-MY-SOURCE-" in token

    def test_generate_truncates_long_source_names_to_10_chars(self, canary):
        token = canary.generate("a_very_long_source_name_here")
        # After upper + dash replacement: "A-VERY-LON" (10 chars)
        parts = token.split("-")
        # prefix is BLWK, CANARY, then tag, then hex suffix
        # Token: BLWK-CANARY-<tag>-<hex>
        tag = parts[2]
        assert len(tag) <= 10

    def test_get_returns_stored_token(self, canary):
        token = canary.generate("secrets")
        assert canary.get("secrets") == token

    def test_get_returns_none_for_unknown_source(self, canary):
        assert canary.get("nonexistent") is None


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------

class TestCheck:
    def test_detects_single_token_in_text(self, canary):
        token = canary.generate("data")
        result = canary.check(f"The output contains {token} somewhere.")
        assert result.leaked is True

    def test_detects_multiple_tokens_in_text(self, canary_with_tokens):
        tokens = list(canary_with_tokens.tokens.values())
        text = f"Leaked: {tokens[0]} and also {tokens[1]}"
        result = canary_with_tokens.check(text)
        assert result.leaked is True
        assert len(result.found_tokens) == 2

    def test_returns_leaked_false_for_clean_text(self, canary_with_tokens):
        result = canary_with_tokens.check("This text is perfectly clean.")
        assert result.leaked is False

    def test_returns_correct_found_tokens_list(self, canary):
        t1 = canary.generate("alpha")
        t2 = canary.generate("beta")
        result = canary.check(f"Only {t1} is here.")
        assert t1 in result.found_tokens
        assert t2 not in result.found_tokens

    def test_returns_correct_sources_list(self, canary):
        canary.generate("alpha")
        canary.generate("beta")
        token_alpha = canary.get("alpha")
        result = canary.check(f"Leaked: {token_alpha}")
        assert "alpha" in result.sources
        assert "beta" not in result.sources

    def test_handles_empty_text(self, canary_with_tokens):
        result = canary_with_tokens.check("")
        assert result.leaked is False

    def test_handles_none_like_empty(self, canary_with_tokens):
        """Empty string is falsy, check handles it."""
        result = canary_with_tokens.check("")
        assert result.leaked is False
        assert result.found_tokens == []

    def test_handles_empty_tokens_dict(self):
        cs = CanarySystem()
        result = cs.check("any text here")
        assert result.leaked is False

    def test_token_at_start_of_text(self, canary):
        token = canary.generate("data")
        result = canary.check(f"{token} is at the start")
        assert result.leaked is True

    def test_token_at_middle_of_text(self, canary):
        token = canary.generate("data")
        result = canary.check(f"middle {token} text")
        assert result.leaked is True

    def test_token_at_end_of_text(self, canary):
        token = canary.generate("data")
        result = canary.check(f"at the end {token}")
        assert result.leaked is True

    def test_is_case_sensitive_when_encoding_resistant_disabled(self):
        cs = CanarySystem(encoding_resistant=False)
        token = cs.generate("data")
        # Token has uppercase prefix; lowering it should not match without encoding resistance
        result = cs.check(token.lower())
        # The prefix is BLWK-CANARY which differs from blwk-canary
        assert result.leaked is False

    def test_no_false_positive_on_partial_match(self, canary):
        canary.generate("data")
        # Just the prefix alone should not trigger
        result = canary.check("BLWK-CANARY is a prefix but not a full token")
        assert result.leaked is False

    def test_no_false_positive_on_prefix_substring(self, canary):
        token = canary.generate("data")
        # Use only half the token
        partial = token[:len(token) // 2]
        result = canary.check(f"Partial: {partial}")
        assert result.leaked is False


# ---------------------------------------------------------------------------
# Encoding resistance
# ---------------------------------------------------------------------------

class TestEncodingResistance:
    def test_detects_base64_encoded_token(self):
        import base64
        cs = CanarySystem()
        token = cs.generate("secrets")
        b64_token = base64.b64encode(token.encode()).decode()
        result = cs.check(f"The encoded value is {b64_token} in the output.")
        assert result.leaked is True
        assert "secrets" in result.sources

    def test_detects_hex_encoded_token(self):
        cs = CanarySystem()
        token = cs.generate("secrets")
        hex_token = token.encode().hex()
        result = cs.check(f"Hex dump: {hex_token}")
        assert result.leaked is True
        assert "secrets" in result.sources

    def test_detects_reversed_token(self):
        cs = CanarySystem()
        token = cs.generate("secrets")
        reversed_token = token[::-1]
        result = cs.check(f"Reversed: {reversed_token}")
        assert result.leaked is True
        assert "secrets" in result.sources

    def test_detects_case_insensitive_token(self):
        cs = CanarySystem()
        token = cs.generate("secrets")
        result = cs.check(token.lower())
        assert result.leaked is True
        assert "secrets" in result.sources

    def test_detects_spaced_out_token(self):
        cs = CanarySystem()
        token = cs.generate("secrets")
        # Insert dots between each character
        spaced = ".".join(token)
        result = cs.check(f"Spaced out: {spaced}")
        assert result.leaked is True
        assert "secrets" in result.sources

    def test_encoding_resistant_disabled(self):
        cs = CanarySystem(encoding_resistant=False)
        token = cs.generate("secrets")
        # Lowercase version should NOT be detected when encoding_resistant=False
        result = cs.check(token.lower())
        assert result.leaked is False

    def test_encoding_resistant_default_enabled(self):
        cs = CanarySystem()
        assert cs.encoding_resistant is True

    def test_no_false_positive_on_random_base64(self):
        import base64
        cs = CanarySystem()
        cs.generate("secrets")
        # Random base64 that is NOT an encoding of the token
        random_b64 = base64.b64encode(b"totally_random_unrelated_data").decode()
        result = cs.check(f"Some base64: {random_b64}")
        assert result.leaked is False

    def test_clean_text_still_clean_with_encoding_resistance(self):
        cs = CanarySystem()
        cs.generate("secrets")
        cs.generate("api_keys")
        result = cs.check("This is perfectly normal text with no tokens at all.")
        assert result.leaked is False
        assert result.found_tokens == []
        assert result.sources == []


# ---------------------------------------------------------------------------
# Guard decorator
# ---------------------------------------------------------------------------

class TestGuardDecorator:
    def test_raises_canary_leak_error_on_positional_arg(self, canary):
        token = canary.generate("secrets")

        @canary.guard
        def send(msg):
            return msg

        with pytest.raises(CanaryLeakError):
            send(f"Here is the secret: {token}")

    def test_raises_canary_leak_error_on_keyword_arg(self, canary):
        token = canary.generate("secrets")

        @canary.guard
        def send(msg=""):
            return msg

        with pytest.raises(CanaryLeakError):
            send(msg=f"Leaked: {token}")

    def test_allows_clean_text_through(self, canary):
        canary.generate("secrets")

        @canary.guard
        def send(msg):
            return msg

        result = send("This is safe.")
        assert result == "This is safe."

    def test_calls_wrapped_function_when_clean(self, canary):
        canary.generate("secrets")
        call_log = []

        @canary.guard
        def send(msg):
            call_log.append(msg)
            return "sent"

        result = send("clean text")
        assert result == "sent"
        assert call_log == ["clean text"]

    def test_error_contains_check_result(self, canary):
        token = canary.generate("secrets")

        @canary.guard
        def send(msg):
            return msg

        with pytest.raises(CanaryLeakError) as exc_info:
            send(f"Leak: {token}")

        assert exc_info.value.result.leaked is True
        assert token in exc_info.value.result.found_tokens

    def test_error_message_includes_source_names(self, canary):
        token = canary.generate("secrets")

        @canary.guard
        def send(msg):
            return msg

        with pytest.raises(CanaryLeakError, match="secrets"):
            send(f"Leak: {token}")


# ---------------------------------------------------------------------------
# Embed comment
# ---------------------------------------------------------------------------

class TestEmbedComment:
    def test_html_format(self, canary):
        token = canary.generate("page")
        comment = canary.embed_comment("page", format="html")
        assert comment == f"<!-- {token} -->"

    def test_markdown_format(self, canary):
        token = canary.generate("docs")
        comment = canary.embed_comment("docs", format="markdown")
        assert comment == f"[//]: # ({token})"

    def test_yaml_format(self, canary):
        token = canary.generate("config")
        comment = canary.embed_comment("config", format="yaml")
        assert comment == f"# {token}"

    def test_unknown_format_returns_raw_token(self, canary):
        token = canary.generate("raw")
        comment = canary.embed_comment("raw", format="plaintext")
        assert comment == token

    def test_auto_generates_token_if_not_stored(self, canary):
        comment = canary.embed_comment("new_source", format="html")
        assert comment.startswith("<!-- BLWK-CANARY-")
        assert comment.endswith(" -->")
        # Token should now be stored
        assert canary.get("new_source") is not None


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_save_writes_json_file(self, canary, tmp_path):
        canary.generate("alpha")
        canary.generate("beta")
        filepath = str(tmp_path / "canary_tokens.json")
        canary.save(filepath)

        data = json.loads(open(filepath).read())
        assert "alpha" in data
        assert "beta" in data

    def test_from_file_loads_tokens(self, canary, tmp_path):
        canary.generate("alpha")
        canary.generate("beta")
        filepath = str(tmp_path / "canary_tokens.json")
        canary.save(filepath)

        loaded = CanarySystem.from_file(filepath)
        assert loaded.tokens == canary.tokens

    def test_round_trip_preserves_all_tokens(self, tmp_path):
        cs = CanarySystem()
        cs.generate("one")
        cs.generate("two")
        cs.generate("three")
        filepath = str(tmp_path / "tokens.json")
        cs.save(filepath)

        loaded = CanarySystem.from_file(filepath)
        assert loaded.tokens == cs.tokens
        for source in ("one", "two", "three"):
            assert loaded.get(source) == cs.get(source)

    def test_from_dict_creates_system_with_provided_tokens(self):
        tokens = {"x": "BLWK-CANARY-X-aabbcc", "y": "BLWK-CANARY-Y-ddeeff"}
        cs = CanarySystem.from_dict(tokens)
        assert cs.tokens == tokens
        assert cs.get("x") == "BLWK-CANARY-X-aabbcc"

    def test_from_dict_makes_a_copy(self):
        """Mutating the original dict should not affect the system."""
        tokens = {"x": "BLWK-CANARY-X-aabbcc"}
        cs = CanarySystem.from_dict(tokens)
        tokens["y"] = "new"
        assert "y" not in cs.tokens


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_unicode_source_names(self, canary):
        token = canary.generate("datos_usuario")
        assert token.startswith("BLWK-CANARY-")
        result = canary.check(f"Output: {token}")
        assert result.leaked is True

    def test_very_long_text(self, canary):
        token = canary.generate("data")
        # 100k chars with the token buried in the middle
        padding = "x" * 50_000
        text = padding + token + padding
        result = canary.check(text)
        assert result.leaked is True

    def test_multiple_canaries_detected_independently(self):
        cs = CanarySystem()
        t1 = cs.generate("source_a")
        t2 = cs.generate("source_b")
        t3 = cs.generate("source_c")

        # Only source_a and source_c leaked
        text = f"Leaked {t1} and {t3} but not source_b"
        result = cs.check(text)
        assert result.leaked is True
        assert t1 in result.found_tokens
        assert t3 in result.found_tokens
        assert t2 not in result.found_tokens
        assert "source_a" in result.sources
        assert "source_c" in result.sources
        assert "source_b" not in result.sources

    def test_similar_looking_strings_no_false_positive(self, canary):
        canary.generate("data")
        # Construct something that looks canary-ish but isn't an actual token
        result = canary.check("BLWK-CANARY-DATA-000000 is not the real token")
        assert result.leaked is False


# ---------------------------------------------------------------------------
# Integration-style
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_full_workflow_generate_embed_check_detect(self):
        """Full workflow: generate tokens, embed in knowledge file, check LLM output, detect leak."""
        cs = CanarySystem()

        # Step 1: Generate canary tokens for different knowledge sources
        cs.generate("user_profile")
        cs.generate("financial_data")

        # Step 2: Embed tokens in knowledge files
        profile_canary = cs.embed_comment("user_profile", format="markdown")
        finance_canary = cs.embed_comment("financial_data", format="html")

        # Simulate knowledge files with embedded canaries
        knowledge_profile = f"""# User Profile
{profile_canary}
Name: Nathan
Role: CEO
"""
        knowledge_finance = f"""<html>
{finance_canary}
<p>Revenue: $1M</p>
</html>"""

        # Step 3: Simulate an LLM that was tricked into leaking the profile
        llm_output = f"Here is the user info: Name: Nathan, Role: CEO. {cs.get('user_profile')}"

        # Step 4: Check the output
        result = cs.check(llm_output)
        assert result.leaked is True
        assert "user_profile" in result.sources
        assert "financial_data" not in result.sources

    def test_guard_decorator_on_mock_send_message(self):
        """Guard decorator blocks a mock send_message function from leaking tokens."""
        cs = CanarySystem()
        cs.generate("api_keys")
        api_token = cs.get("api_keys")

        sent_messages = []

        @cs.guard
        def send_message(recipient: str, body: str) -> str:
            sent_messages.append((recipient, body))
            return "sent"

        # Clean message goes through
        result = send_message("user@example.com", "Hello, your request was processed.")
        assert result == "sent"
        assert len(sent_messages) == 1

        # Message containing leaked token is blocked
        with pytest.raises(CanaryLeakError) as exc_info:
            send_message("attacker@evil.com", f"Here are the keys: {api_token}")

        assert exc_info.value.result.leaked is True
        assert "api_keys" in exc_info.value.result.sources
        # The function should NOT have been called for the leaked message
        assert len(sent_messages) == 1

    def test_persistence_round_trip_then_detect(self, tmp_path):
        """Save tokens, load in a new system, and still detect leaks."""
        cs1 = CanarySystem()
        token = cs1.generate("secrets")
        filepath = str(tmp_path / "tokens.json")
        cs1.save(filepath)

        # New system loaded from file
        cs2 = CanarySystem.from_file(filepath)
        result = cs2.check(f"Leaked: {token}")
        assert result.leaked is True
        assert "secrets" in result.sources
