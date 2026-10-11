# Integration-first Agent Trust Firewall

One FastAPI service, one shared security engine, the existing sealed Linux runtime and the existing Groq gateway. Hosted execution is enforceable; an inspection-only external caller must obey release guidance. The Python SDK is a client, not an alternate privileged agent runtime.

```mermaid
flowchart TB
  subgraph Connect[1. Integration and untrusted information]
    Console[Security console on Vercel]
    SDK[Independent application / Python SDK]
    Sources[Task intent separately from files / pasted evidence]
    Registry[Server-owned integration registry]
    Console --> API[Authenticated versioned API]
    SDK --> API
    Sources --> API
    Registry --> API
  end
  subgraph Inspect[2. Shared inspection plane]
    Parser[Restricted parser / declared channels / provenance]
    Rules[Normalize / rules / DLP / bounded decoding]
    Router[Conditional Prompt Guard]
    Policy[Content and completeness policy]
    Release[Inspected released fragments; unsupported portions withheld]
    Parser --> Rules --> Router --> Policy --> Release
  end
  subgraph Runtime[3. Trusted context and bounded agent]
    Snapshot[Server-issued owner / task / policy / hash / expiry snapshot]
    Gateway[Server constructs system and user roles / egress DLP]
    Groq[Groq generation]
    Child[Credential-free Linux child: maximum 3 model turns]
    Snapshot --> Gateway --> Groq
    Groq --> Child
    Child -->|snapshot reference only| Gateway
  end
  subgraph Actions[4. Mandatory broker and output security]
    Broker[Existing Firewall.handle]
    Validate[Profile / exact schema / resource / current snapshot]
    Tool[Released read / deterministic scoring / inert patch]
    Effect[Exact envelope / authorization / DLP / single-use permit]
    Mock[Contained mock sink; live email disabled]
    Final[Final output DLP]
    Child -->|proposal only; maximum 2 tool turns| Broker
    Broker --> Validate --> Tool
    Validate --> Effect --> Mock
    Child --> Final --> User[Released response]
  end
  API --> Parser
  Release --> Snapshot
  Tool -->|Tool result must be inspected| Parser
  Inspect -.-> Trace[Trusted run ID / events / decisions / temporary SQLite]
  Runtime -.-> Trace
  Actions -.-> Trace
  Trace --> Activity[Runtime Activity / incidents / investigations]
  Trace --> Lab[Contained A/B/C Lab; actual utility and outcome scoring]
  Activity --> Console
  Lab --> Console
```

The authenticated source plan collects at most two selected public pages or the fixed repository before generation. Subsequent model-selected reads use the released task cache; they cannot introduce a new URL or filesystem path. Procurement's `score_suppliers` reads released explicit fields and uses decimal price, supplied delivery and warranty, with absent/conflicting currencies disclosed. It grants no purchase or email permission. A proposed patch is inert text. Every tool receipt is parsed and inspected before a fresh snapshot and next model call.

```mermaid
sequenceDiagram
  participant Client as Independent SDK application
  participant API as Trusted API
  participant Inspect as Shared inspection
  participant Child as Isolated bounded agent
  participant Broker as Mandatory broker / gateway
  participant Groq as Groq
  Client->>API: Upload four synthetic supplier files
  API->>Inspect: Extract hidden sheet, inspect, release fragments
  Client->>API: Separate task intent and artifact IDs
  API->>Child: Server-issued context snapshot
  Child->>Broker: model.generate(snapshot)
  Broker->>Groq: Server-built roles and released evidence
  Groq-->>Child: TOOL_REQUEST score_suppliers
  Child->>Broker: Validated proposal; no authority grant
  Broker->>Inspect: Deterministic score result as untrusted text
  Inspect-->>Broker: Released result / explicit coverage
  Broker-->>Child: New snapshot reference
  Child->>Broker: Second model request
  Broker->>Groq: Server-controlled context with inspected receipt
  Groq-->>Child: FINAL_RESPONSE
  Child->>Broker: finalize / DLP
  API->>Broker: Labelled independent forbidden mock-email probe
  Broker-->>API: DENY; zero dispatches
  API-->>Client: Released output + run ID + actual trace
```

Events carry trusted run/integration IDs, sequence/timestamp, stage, snapshot/resource/evidence references, payload hashes and policy decisions. No model chain-of-thought is published. A final response indicates output release; business task success is independently evaluated. Failed/provider-limited/reviewed runs retain their prior evidence and decisions. Inspection-only and unavailable proxy/MCP modes do not advertise hosted runtime enforcement.

Integration verification compares the packaged Linux acceptance source hashes with current modules and requires actual startup containment. A health response, a registration or browser configuration cannot mark protection verified. Record retention remains temporary, one shared demo identity, 24 hours / 300 total rows. Lab run views adapt existing evaluation rows rather than duplicating persistence tables.

## Retained security diagrams and historical architecture

The following diagrams describe the preserved inspection, authority and exact-dispatch controls; the bounded turn loop and integration control plane above extend the original one-response product.

### Original platform architecture

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
