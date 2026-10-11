import React from "react";
import { ShieldCheck, FileSearch, LockKeyhole, Play } from "lucide-react";
import {
  Badge,
  Empty,
  Output,
  type Row,
  type ViewProps,
} from "../components/Common";
import { EventTable } from "../components/EventTable";
import { ArtifactInspector } from "../components/ArtifactInspector";
import { API } from "../app/api";
export function AttackLab(props: ViewProps) {
  const {
    page,
    go,
    agents,
    setResult,
    agent,
    evidence,
    result,
    action,
    api,
    busy,
    refresh,
    setInvestigate,
    scenario,
    surface,
    comparison,
    setComparison,
    setAgent,
    setScenario,
    setSurface,
    attacks,
  } = props;
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">CONTAINED ADVERSARIAL TESTING</span>
          <h1>Attack lab</h1>
          <p className="subtle">
            Same model, task and fixture. Three security configurations. Actual
            observed outcomes.
          </p>
        </div>
        <Badge value="SYNTHETIC ONLY" />
      </div>
      <form
        className="panel lab-controls"
        onSubmit={(e) => {
          e.preventDefault();
          action(async () => {
            setComparison(null);
            const r = await api("attacks/run", {
              agent_id: agent,
              scenario,
              surface,
            });
            setComparison(r);
            await refresh();
          });
        }}
      >
        <label>
          Target agent
          <select
            value={agent}
            disabled={busy}
            onChange={(e) => {
              setAgent(e.target.value);
              setResult(null);
              setComparison(null);
            }}
          >
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Attack scenario
          <select
            value={scenario}
            disabled={busy}
            onChange={(e) => {
              setScenario(e.target.value);
              setComparison(null);
            }}
          >
            {attacks.scenarios?.map((s: Row) => (
              <option key={s.id} value={s.id}>
                {s.description}
              </option>
            ))}
          </select>
        </label>
        <label>
          Injection surface
          <select
            value={surface}
            disabled={busy}
            onChange={(e) => {
              setSurface(e.target.value);
              setComparison(null);
            }}
          >
            {attacks.surfaces?.map((s: string) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        <button className="primary" disabled={busy}>
          {props.connecting ? "Connecting workspace…" : busy ? "Running actual comparison…" : "Run contained test"}
          <Play size={15} />
        </button>
      </form>
      <div className="notice subtle-notice">
        <LockKeyhole size={16} /> All external effects are simulated. No live
        secrets, email or unrestricted network tools enter the unprotected
        baseline.
      </div>
      {comparison ? (
        <>
          <div className="comparison-grid">
            {comparison.results.map((r: Row) => (
              <section className="panel comparison" key={r.configuration}>
                <span className="eyebrow">CONFIGURATION {r.configuration}</span>
                <h2>
                  {r.configuration === "A"
                    ? "Unprotected baseline"
                    : r.configuration === "B"
                      ? "Deterministic defense"
                      : "Routed AI defense"}
                </h2>
                <Badge value={r.status} />
                {r.output ? (
                  <>
                    <div className="outcomes">
                      {[
                        ["Attack detected", r.detection],
                        ["Legitimate task completed", r.task_success],
                        [
                          "Model followed attacker objective",
                          r.attacker_objective_observed,
                        ],
                        ["Attacker objective prevented", r.attack_prevented],
                        ["Canary leaked", r.sensitive_synthetic_canary_leakage],
                      ].map(([label, val]) => (
                        <div key={String(label)}>
                          <span>{label}</span>
                          <strong>
                            {val == null ? "Unknown / N/A" : val ? "Yes" : "No"}
                          </strong>
                        </div>
                      ))}
                    </div>
                    <small>
                      {r.seconds}s · {r.usage?.total_tokens ?? 0} generation
                      tokens · {r.classifier_calls} classifier calls
                    </small>
                    <Output value={r.output} />
                    {r.inspection && (
                      <button
                        className="secondary"
                        onClick={() => {
                          setInvestigate(r.inspection);
                          go("Threat Intelligence");
                        }}
                      >
                        Inspect tested evidence
                        <FileSearch size={14} />
                      </button>
                    )}
                    {r.containment_probe && (
                      <div className="notice">
                        <ShieldCheck size={16} />
                        <span>
                          Forced containment probe: unauthorized mock email{" "}
                          {r.containment_probe.decision.ok
                            ? "allowed"
                            : "denied"}{" "}
                          ({r.containment_probe.decision.error || "ALLOW"}).
                          This proposal is forced by the test, not generated by
                          the model. {r.containment_probe.emails_executed}{" "}
                          emails executed.
                        </span>
                      </div>
                    )}
                    <details>
                      <summary>Actual decisions</summary>
                      {r.decisions.map((d: Row, i: number) => (
                        <div className="boundary-row" key={i}>
                          <span>{d.operation}</span>
                          <Badge value={d.result} />
                        </div>
                      ))}
                    </details>
                  </>
                ) : (
                  <p className="subtle">
                    {r.error ||
                      "Semantic layer disabled pending measured incremental benefit."}
                  </p>
                )}
              </section>
            ))}
          </div>
          <p className="subtle">
            {comparison.scope} {comparison.scoring}
          </p>
        </>
      ) : (
        <section className="panel">
          <Empty text="Choose a scenario and run a test. No outcomes have been fabricated." />
          <div className="config-explainer">
            <div>
              <b>A</b>
              <h3>Model baseline</h3>
              <p>Raw synthetic evidence and a contained mock tool sink.</p>
            </div>
            <div>
              <b>B</b>
              <h3>Deterministic controls</h3>
              <p>Rules, context authority, broker authorization and DLP.</p>
            </div>
            <div>
              <b>C</b>
              <h3>Routed intelligence</h3>
              <p>Same controls with measured specialist classifier support.</p>
            </div>
          </div>
        </section>
      )}
    </>
  );
}
