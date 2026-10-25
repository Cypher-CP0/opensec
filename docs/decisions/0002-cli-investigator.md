# Decision: a tool-less subscription CLI adapter

The first adapter uses Claude Code non-interactively with structured output and built-in tools/MCP disabled. An operator profile selects the executable and model, authorizes exact source files for disclosure, and binds the project/policy/repository. The CLI manages its normal account login.

OpenSec mediates source queries inside the offline inspector. Hypotheses must cite prior reads. The operator supplies the source tuple, web target and optional check template; the coordinator schedules that template transactionally. Fresh discovery and independent replay remain necessary for confirmation.

Prompt text is not the enforcement boundary. Mandatory flags are checked through local help before a worker claims tasks. The additional restricted-mode flag is negotiated for compatibility; native tools, MCP and customizations remain disabled on older supported releases. Linux process groups provide cancellation. The CLI binary, host and administrator policy remain trusted.

Tokens are reported after completion, so the task threshold is soft for this adapter. Overages remain visible and reduce run capacity. No hard provider-side monetary cap is claimed.

The Go Adapter interface permits future Codex/direct API implementations. Codex is not exposed until an equally explicit tool/disclosure boundary is implemented and tested. Scripted models cover harness tests; live CLI smoke tests are separate.
