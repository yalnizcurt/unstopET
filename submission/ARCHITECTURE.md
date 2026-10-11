# Scoped product architecture

The deck’s seventh slide contains an editable architecture diagram. Its standalone PNG is a faithful export of that slide, not a separate invented product design.

```mermaid
flowchart TB
  App[External application / SDK client]
  subgraph Server[Server-controlled authority]
    Policy[Policy and authenticated task intent]
    Inspect[Shared inspection / coverage / release]
    Context[Trusted Context Builder / server snapshot]
    Gateway[Model Gateway / Groq provider]
    Broker[Mandatory execution broker]
    Receipt[Tool receipt inspection and DLP]
    Output[Final output policy and DLP]
    Audit[Run evidence / provenance / incidents]
    Inspect --> Context --> Gateway
    Policy --> Context
    Policy --> Broker
    Broker --> Receipt --> Inspect
    Inspect --> Audit
    Broker --> Audit
    Output --> Audit
  end
  App -->|Task and evidence| Inspect
  Runtime[Isolated Linux child runtime]
  Gateway --> Runtime
  Runtime -->|Bounded action proposal| Broker
  Runtime --> Output --> App
```

The child has no direct model credential, network, shell, unrestricted filesystem or alternate MCP access. The broker validates exact profile schemas, resources and action permits at execution. Released receipts receive a fresh context snapshot. Inspection-only integrations do not gain runtime enforcement. Memory is disabled and rejects writes.

The external application or SDK client submits authenticated task requests and evidence. It is outside server-controlled authority and cannot define model roles, profiles, grants or action permissions.
