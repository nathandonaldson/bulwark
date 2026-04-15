/**
 * Bulwark Shield plugin for OpenClaw
 *
 * Infrastructure-level prompt injection defense. Sanitizes all external content
 * before the agent sees it by hooking into OpenClaw's message and tool pipelines.
 *
 * Three hooks:
 *   message:received      — sanitize inbound chat messages via /v1/clean
 *   tool_result_persist   — sanitize tool results (web, email, MCP, files) via /v1/clean
 *   before_message_write  — guard outbound content via /v1/guard
 *
 * Requires the Bulwark sidecar running on localhost:8100.
 * Fail-open: if the sidecar is unreachable, content passes through with a warning.
 */

const BULWARK_URL = process.env.BULWARK_URL || "http://localhost:8100";

/**
 * Call Bulwark /v1/clean to sanitize content.
 * Returns the sanitized result, or the original content if Bulwark is unreachable.
 */
async function sanitize(content, source) {
  try {
    const resp = await fetch(`${BULWARK_URL}/v1/clean`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, source: source || "openclaw" }),
    });
    if (!resp.ok) {
      console.warn(`[bulwark] /v1/clean returned ${resp.status}, passing through`);
      return content;
    }
    const data = await resp.json();
    return data.result || content;
  } catch (err) {
    console.warn(`[bulwark] sidecar unreachable (${err.message}), passing content through`);
    return content;
  }
}

/**
 * Call Bulwark /v1/guard to check outbound content.
 * Returns { safe, reason } or { safe: true } if Bulwark is unreachable.
 */
async function guard(text) {
  try {
    const resp = await fetch(`${BULWARK_URL}/v1/guard`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!resp.ok) {
      console.warn(`[bulwark] /v1/guard returned ${resp.status}, passing through`);
      return { safe: true };
    }
    return await resp.json();
  } catch (err) {
    console.warn(`[bulwark] sidecar unreachable (${err.message}), passing content through`);
    return { safe: true };
  }
}

/**
 * Register Bulwark hooks with the OpenClaw plugin API.
 */
module.exports = function bulwarkPlugin(api) {
  console.log("[bulwark] Bulwark Shield plugin loaded");
  console.log(`[bulwark] Sidecar URL: ${BULWARK_URL}`);

  // Hook 1: Sanitize inbound chat messages before prompt construction
  api.on("message:received", async (context) => {
    if (!context.body) return context;

    const sanitized = await sanitize(context.body, "message");
    if (sanitized !== context.body) {
      console.log(`[bulwark] Sanitized inbound message (${context.body.length} → ${sanitized.length} chars)`);
    }
    return { ...context, body: sanitized };
  });

  // Hook 2: Sanitize all tool results before they enter the transcript
  api.on("tool_result_persist", async (message) => {
    if (!message.content) return message;

    const content = typeof message.content === "string"
      ? message.content
      : JSON.stringify(message.content);

    const sanitized = await sanitize(content, `tool:${message.toolName || "unknown"}`);
    if (sanitized !== content) {
      console.log(`[bulwark] Sanitized tool result from ${message.toolName || "unknown"} (${content.length} → ${sanitized.length} chars)`);
    }
    return { ...message, content: sanitized };
  });

  // Hook 3: Guard outbound messages before they're written to history
  api.on("before_message_write", async (message) => {
    // Only guard assistant/outbound messages, not user messages
    if (message.role !== "assistant") return message;
    if (!message.content) return message;

    const text = typeof message.content === "string"
      ? message.content
      : JSON.stringify(message.content);

    const result = await guard(text);
    if (!result.safe) {
      console.warn(`[bulwark] Blocked outbound message: ${result.reason}`);
      return {
        ...message,
        content: `[Bulwark Shield blocked this message: ${result.reason}]`,
      };
    }
    return message;
  });
};
