# Provider-call quota enforcement

Reuse decision (before implementation): provider implementations already expose
the actual configured model immediately before `requests.post`. Extend those
existing invocation seams and the existing provider base module; do not introduce
a second transport or import another deployable service. Existing Gemini retries
must each obtain fresh provider-call admission outside the retry exception block.
New admission lines are necessary because these calls currently have no quota
boundary. This is a confirmed enforcement gap from direct source inspection;
mocked failure-injection tests establish zero HTTP calls when admission fails.

Tenant identity comes only from verified request tenant context. Missing context
fails closed, including background/internal calls. All external model calls are
conservatively expensive, including embeddings, unrecognized aliases and resolved
fallbacks. Calls share an aggregate tenant expensive-model quota so changing a model
cannot reset allowance; provider admission never consumes ingress dimensions.
No internal exemption exists.
Denials and unavailable state must propagate through optional AI fallback handlers.

Direct call inventory: OpenAI, Anthropic, Azure OpenAI, Cohere, Gemini provider
classes; document pipeline Gemini review; RAG compliance review and embeddings;
Anthropic live credential test; main.py's legacy document Gemini review. Gateway
forwarding delegates provider admission to the Go gateway's actual egress boundary,
so the forwarding adapter does not charge a second provider admission. Gateway
429/503 responses propagate as quota exceptions. The LLM worker copies the trusted
context into its thread; quota exceptions bypass its offline fallback and the
gateway service's generic error translation.

Compatibility: standalone provider calls now require tenant context and configured
quota enforcement. Retried provider requests consume an admission each time.
Rollback must retain these admission seams and fail-closed exceptions.

Validation: `smoke_tests.test_provider_quotas`, `smoke_tests.test_gateway_provider`,
and `smoke_tests.test_provider_logging_sanitization`: the final provider suite has
7 tests (included in the combined 42-test agent run); 6 compatibility/logging
tests passed separately. Provider tests cover each external provider denied admission (zero HTTP),
success (exactly one HTTP and one resolved-model admission), Gemini alias resolution,
per-retry admission, missing tenant denial, embeddings fallback suppression and
tenant-context propagation through the LLM worker. Redis transport and concurrency
evidence belongs to the quota core suite; these tests isolate that admission seam.
The document pipeline and compliance review use the same guarded call but have not
been integration-tested with their database/storage dependencies in this suite.
