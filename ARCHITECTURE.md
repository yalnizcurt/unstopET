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

## Universal inspection pipeline

```mermaid
flowchart LR
  Raw[Untrusted file / tool response] --> Signature[Magic and extension consistency / byte budget]
  Signature --> Parser[Restricted credential-free parser / English OCR]
  Parser --> Tree[Fragments / filename and metadata / recursive provenance / gaps]
  Tree --> Normalize[Unicode normalization / bounded decoding]
  Normalize --> Rules[Rules and known-secret DLP]
  Rules --> Router{Bounded semantic need?}
  Router -->|yes| Guard[Prompt Guard specialist classifier]
  Router -->|no / disabled| Signals[Recorded signals and engine reasons]
  Guard --> Signals
  Signals --> Risk[Uncalibrated risk signals]
  Risk --> Policy[Server content and completeness policy]
  Policy --> Release[Allow / sanitize / withhold / reject]
  Release --> Snapshot[Only released untrusted fragments enter server context]
```


The snapshot is not an authorization credential: the broker validates ownership, release hashes, current policy and expiry. Partial original files are never passed to the agent. Only inspected text fragments are imported as separately released UTF-8 evidence. Unsupported children remain withheld. Sanitized data remains untrusted.

Attack Lab A removes application firewall defenses in a synthetic model comparison. B uses deterministic controls; C adds the measured routed classifier. All tool effects are contained. Model persuasion, legitimate-task completion, detection, simulated execution and leakage are reported separately.

History is temporary SQLite on Render's free filesystem, not durable enterprise storage. Binary uploads are discarded after extraction. Persistent memory, arbitrary shell, live repository writes, autonomous red-team generation and general MCP access remain disabled.

## Trusted context assembly

```mermaid
flowchart TB
  System[Authenticated server profile and policy] --> Builder[Trusted context builder]
  Intent[Authenticated task intent] --> Separate{Quoted or pasted evidence?}
  Separate -->|task instruction| Builder
  Separate -->|data channel| Inspect[Shared inspection and fragment release]
  Evidence[Uploads / fetched pages / approved repository] --> Inspect
  Inspect -->|released text remains untrusted| Builder
  Builder --> Snapshot[Owner / task / policy / hash / expiry snapshot]
  Child[Isolated agent] -->|snapshot reference only| Validate[Gateway validates snapshot and egress DLP]
  Snapshot --> Validate
  Validate --> Messages[Server constructs system and user roles]
  Messages --> Groq[Fixed Groq provider]
  Forge[Forged role / stale or other-owner snapshot] --> Reject[Reject and audit]
```

## Action authorization and dispatch

```mermaid
flowchart LR
  Proposal[Untrusted operation proposal] --> Registry{Registered capability?}
  Registry -->|no| Deny[Deny and audit]
  Registry -->|yes| Auth{Current owner / snapshot / destination / resource permission?}
  Auth -->|no| Deny
  Auth -->|yes| DLP{Payload and dependency disclosure allowed?}
  DLP -->|no| Deny
  DLP -->|yes| Envelope[Immutable exact payload envelope]
  Envelope --> Approve[Trusted application approval]
  Approve --> Permit[Short-lived single-use permit]
  Permit --> Dispatch[Atomic revalidation and consumption]
  Dispatch -->|revoked / altered / stale / replay| Deny
  Dispatch -->|valid| Mock[Exact bytes in mock sink]
```

Approval and live email are absent from public agent capabilities. Positive mock dispatch tests exercise the server-side contract; Attack Lab forces an unauthorized proposal and records its real rejection. That forced proposal is explicitly separate from model behavior.

## Three-agent integration

```mermaid
flowchart TB
  UI[Vercel security console] --> API[Authenticated FastAPI]
  API --> Procurement[Procurement profile: supplier comparison]
  API --> Research[Research profile: public HTTPS brief]
  API --> Developer[Developer profile: synthetic code review]
  Procurement --> Shared[One firewall / snapshot / gateway / runtime / DLP]
  Research --> Shared
  Developer --> Shared
  Shared --> Groq[Groq real inference]
  Shared --> Broker[Mandatory broker]
  Broker --> HTTPS[Pinned public fetch and inspected tool output]
  Broker --> Repo[Fixed inert repository and inspected tool output]
  Shared --> Audit[Real task / artifact / decision records]
  Audit --> UI
```

## Attack Lab and evaluation

```mermaid
flowchart TB
  Fixture[Same authored synthetic fixture / task / model settings] --> A[A: raw evidence; contained model baseline]
  Fixture --> B[B: deterministic inspection and enforcement]
  Fixture --> C[C: same controls plus routed Prompt Guard]
  A --> Sink[Contained simulated tool sink and canary observation]
  B --> Measure[Actual output / task / detection / latency / tokens]
  C --> Measure
  Sink --> Measure
  B --> Probe[Labelled forced-compromise proposal to real broker]
  C --> Probe
  Probe --> Denial[Actual decision and zero mock dispatches]
  Denial --> Measure
  Measure --> Report[Separate outcomes; unknowns and failures retained]
  Report --> UI[Attack Lab / Evaluations / Security Events]
  Report --> Evidence[Versioned JSON evidence; original timestamps and scope]
```

The first two diagrams show the overall platform and universal inspection pipeline. These four additional diagrams detail context assembly, action authorization, shared integration and evaluation. Detection scores are uncalibrated signals. Contextual LLM escalation, cross-source correlation and persistent memory are absent rather than hidden bypass paths.
