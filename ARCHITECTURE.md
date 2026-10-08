# Implemented architecture

The console is React/TypeScript on Vercel. A single FastAPI service on Render hosts the versioned API, shared inspection plane, credentialed model gateway, server-owned agent profiles and execution broker. Existing Linux Landlock/seccomp isolation is retained. No additional microservices were added.

```mermaid
flowchart TB
  subgraph Sources[1. Untrusted information]
    Upload[Uploads / pasted material]
    Web[Public HTTPS sources]
    Repo[Synthetic repository]
  end
  subgraph Inspection[2. Shared inspection plane]
    Worker[Credential-free restricted parser worker]
    Tree[Artifact tree + locations + explicit coverage]
    Rules[Deterministic checks]
    Router[Intelligence router]
    Guard[Optional Prompt Guard 2 classifier]
    Policy[Risk signals + server policy]
    Sanitize[Quarantine hostile fragments / withhold unknown regions]
    Worker --> Tree --> Rules --> Router
    Router -->|checks sufficient| Policy
    Router -->|bounded semantic need| Guard --> Policy
    Policy --> Sanitize
  end
  subgraph Context[3. Trusted agent context]
    Builder[Server-issued context snapshot]
    Gateway[Server-owned roles + egress DLP + Groq gateway]
    Agent[Sealed Linux agent runtime]
    Builder --> Gateway
    Agent -->|snapshot request only| Gateway
    Gateway -->|bounded response| Agent
  end
  subgraph Effects[4. Side-effect security]
    Broker[Mandatory execution broker]
    Auth[Current authorization + exact immutable envelope]
    DLP[Payload / final-output DLP]
    Sink[Contained mock email sink]
    Agent -->|proposed operation| Broker --> Auth --> DLP --> Sink
  end
  Upload --> Worker
  Web --> Worker
  Repo --> Worker
  Sanitize --> Builder
  Broker -->|server-approved read plan only| Web
  Broker -->|server-approved read plan only| Repo
  Agent -->|finalize| DLP
  DLP --> User[Released response / user]
  Inspection -.-> Store[Bounded temporary SQLite audit and records]
  Broker -.-> Store
  Store --> Console[Security console / investigations / evaluation]
```

```mermaid
flowchart LR
  Task[Authenticated task intent] --> Inspect[Inspect selected evidence]
  Inspect --> Release{Declared fragments releasable?}
  Release -->|unsupported or unknown| Hold[Withhold / review / error]
  Release -->|released fragments only| Snapshot[Server snapshot bound to principal / task / policy / hashes / TTL]
  Snapshot --> LLM[Groq generation through trusted gateway]
  LLM --> Proposed[Agent proposes operation]
  Proposed --> Check{Current authority and exact payload valid?}
  Check -->|no| Deny[Reject + audit]
  Check -->|yes| Execute[Consume single-use permit + mock dispatch]
  LLM --> Final[Buffered final output DLP]
  Final --> Complete[Return response + sources + actual events]
```

The snapshot is not an authorization credential: the broker validates ownership, release hashes, current policy and expiry. Partial original files are never passed to the agent. Only inspected text fragments are imported as separately released UTF-8 evidence. Unsupported children remain withheld. Sanitized data remains untrusted.

Attack Lab A removes application firewall defenses in a synthetic model comparison. B uses deterministic controls; C adds the measured routed classifier. All tool effects are contained. Model persuasion, legitimate-task completion, detection, simulated execution and leakage are reported separately.

History is temporary SQLite on Render's free filesystem, not durable enterprise storage. Binary uploads are discarded after extraction. Persistent memory, arbitrary shell, live repository writes, autonomous red-team generation and general MCP access remain disabled.
