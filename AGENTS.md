# AGENTS

## Design principles

Before any code or structural change, read the stack's design principles and follow their hard rule (refactor to the principle first, then change behavior): `../../../docs/policies/design-principles.md` inside the spacedatanetwork-stack checkout, or https://github.com/DigitalArsenal/spacedatanetwork-stack/blob/main/docs/policies/design-principles.md.

## Mandatory Session Startup

1. Read `.claude/SKILLS.md`.
2. If the task touches plugin manifests, plugin API/ABI exports, compiled plugin artifacts, or SDN plugin compliance, load the shared SDN Plugin ABI & Compliance skill from `sdn-flow`.
3. Read `.claude/Agents.md` for repo-specific cryptography rules before editing implementation code.
