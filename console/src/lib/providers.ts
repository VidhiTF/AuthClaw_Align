export const providerCatalog = {
  openai: {
    label: "OpenAI-compatible chat",
    shortLabel: "OpenAI",
    path: "/v1/chat/completions",
    header: "X-Provider: openai",
    defaultEndpoint: "https://api.openai.com/v1/chat/completions",
    modelWhitelist: "gpt-4o, gpt-4-turbo, gpt-3.5-turbo",
    readiness: "production-ready",
    lastReviewed: "2026-07-07",
    payloadContract: "OpenAI chat.completions messages[]",
    streamingContract: "SSE choices[].delta.content with [DONE]",
    ciGate: "gateway provider contract drift gate",
    sampleBody: `{
  "model": "gpt-4o-mini",
  "messages": [
    {
      "role": "user",
      "content": "My email is jane@example.com. Can you summarize this?"
    }
  ]
}`,
    testBody: {
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "My email is jane@example.com. Reply with one short safe sentence." }],
    },
  },
  anthropic: {
    label: "Anthropic-compatible messages",
    shortLabel: "Anthropic",
    path: "/v1/messages",
    header: "X-Provider: anthropic",
    defaultEndpoint: "https://api.anthropic.com/v1/messages",
    modelWhitelist: "claude-3-5-sonnet, claude-3-opus, claude-3-haiku",
    readiness: "production-ready",
    lastReviewed: "2026-07-07",
    payloadContract: "Anthropic messages payload",
    streamingContract: "SSE content_block_delta delta.text events",
    ciGate: "gateway provider contract drift gate",
    sampleBody: `{
  "model": "claude-3-5-sonnet",
  "max_tokens": 300,
  "messages": [
    {
      "role": "user",
      "content": "Patient John Smith has a follow-up next week. Draft a note."
    }
  ]
}`,
    testBody: {
      model: "claude-3-5-sonnet",
      max_tokens: 80,
      messages: [{ role: "user", content: "My email is jane@example.com. Reply with one short safe sentence." }],
    },
  },
  cohere: {
    label: "Cohere-compatible chat",
    shortLabel: "Cohere",
    path: "/v2/chat",
    header: "X-Provider: cohere",
    defaultEndpoint: "https://api.cohere.ai/v2/chat",
    modelWhitelist: "command-r-plus, command-r",
    readiness: "production-ready",
    lastReviewed: "2026-07-07",
    payloadContract: "Cohere v2 chat messages[]",
    streamingContract: "SSE content-delta message text events",
    ciGate: "gateway provider contract drift gate",
    sampleBody: `{
  "model": "command-r",
  "messages": [
    {
      "role": "user",
      "content": "My email is jane@example.com. Make this answer safe."
    }
  ]
}`,
    testBody: {
      model: "command-r",
      messages: [{ role: "user", content: "My email is jane@example.com. Reply with one short safe sentence." }],
    },
  },
  azure_openai: {
    label: "Azure OpenAI-compatible chat",
    shortLabel: "Azure OpenAI",
    path: "/v1/chat/completions",
    header: "X-Provider: azure_openai",
    defaultEndpoint: "https://YOUR_RESOURCE.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT/chat/completions",
    modelWhitelist: "gpt-4o, gpt-4",
    readiness: "production-ready",
    lastReviewed: "2026-07-07",
    payloadContract: "Azure deployment chat.completions messages[]",
    streamingContract: "SSE choices[].delta.content with [DONE]",
    ciGate: "gateway provider contract drift gate",
    sampleBody: `{
  "model": "gpt-4o-mini",
  "messages": [
    {
      "role": "user",
      "content": "My email is jane@example.com. Can you summarize this?"
    }
  ]
}`,
    testBody: {
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "My email is jane@example.com. Reply with one short safe sentence." }],
    },
  },
  gemini: {
    label: "Gemini-compatible generation",
    shortLabel: "Gemini",
    path: "/v1/models/gemini-2.5-flash-lite:generateContent",
    header: "X-Provider: gemini",
    defaultEndpoint: "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent",
    modelWhitelist: "gemini-2.5-flash-lite, gemini-2.5-flash, gemini-2.5-pro",
    readiness: "validated",
    lastReviewed: "2026-07-07",
    payloadContract: "Gemini generateContent contents[].parts[]",
    streamingContract: "SSE candidates[].content.parts[].text",
    ciGate: "gateway deterministic tests",
    sampleBody: `{
  "contents": [
    {
      "parts": [
        { "text": "My phone is 555-123-9911. Make this support response safer." }
      ]
    }
  ]
}`,
    testBody: {
      contents: [{ parts: [{ text: "My email is jane@example.com. Reply with one short safe sentence." }] }],
    },
  },
} as const;

export type Provider = keyof typeof providerCatalog;

export function isProvider(value: string): value is Provider {
  return value in providerCatalog;
}
