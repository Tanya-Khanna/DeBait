import { FormEvent, useEffect, useState } from "react";
function Shell({ children }: { children: React.ReactNode }) {
  return (
    <>
      <header className="nav">
        <a className="brand" href="/">
          <img src="/debait-mark.svg" alt="" />
          DeBait
        </a>
        <nav aria-label="Primary navigation">
          <a href="/">Overview</a>
          <a href="/evaluations">Evaluations</a>
          <a href="/architecture">Architecture</a>
        </nav>
      </header>
      <main className="utility">{children}</main>
    </>
  );
}
export function Workspace() {
  type Usage = {mode:string;fresh_model_enabled:boolean;currency:string;model:{limit_microdollars:number;spent_microdollars:number;reserved_microdollars:number;available_microdollars:number}};
  const [state, setState] = useState("Connecting…");
  const [token, setToken] = useState("");
  const [episodes,setEpisodes]=useState<Array<{id:string;state:string}>>([]);
  const [reports,setReports]=useState<Array<{episode_id:string;episode_state:string;world:Record<string,string>;actions:Array<{target:{provider:string;resource_id:string;operation:string};observations:Array<{state:string;level:string;source:string}>}>}>>([]);
  const [details,setDetails]=useState<Record<string,{agent_trace:Array<{index:number;phase:string;summary:string;data:Record<string,unknown>}>;events:Array<{event_id:string;provider:string;payload:{resource_id?:string}}>;edges:Array<{source_id:string;target_id:string;kind:string}>}>>({});
  const [running,setRunning]=useState(false);
  const [runningHunter,setRunningHunter]=useState<string | null>(null);
  const [hunterResults,setHunterResults]=useState<Record<string,{state:string;sent_messages:number;indicators:Array<{kind:string;value:string;claim_status:string}>}>>({});
  const [usage,setUsage]=useState<Usage | null>(null);
  const dollars=(microdollars:number)=>`$${(microdollars/1_000_000).toFixed(3)}`;
  const load = () =>
    fetch("/api/episodes")
      .then((r) => {
        if (r.status === 401) {
          setState("Local session locked");
          return;
        }
        if (!r.ok) throw Error();
        return r.json();
      })
      .then((data) => {
        if (data) {
          setEpisodes(data);
          setState(data.length ? "Episodes available" : "No active episodes");
          fetch('/api/reports').then(r=>r.ok?r.json():[]).then(setReports).catch(()=>setReports([]));
          fetch('/api/usage').then(r=>r.ok?r.json():null).then(setUsage).catch(()=>setUsage(null));
          data.forEach((episode:{id:string})=>fetch(`/api/episodes/${episode.id}`).then(r=>r.ok?r.json():null).then(detail=>{if(detail&&Array.isArray(detail.agent_trace))setDetails(current=>({...current,[episode.id]:detail}));}).catch(()=>{}));
        }
      })
      .catch(() => setState("Backend unavailable"));
  useEffect(() => {
    void load();
  }, []);
  const unlock = async (e: FormEvent) => {
    e.preventDefault();
    setState("Connecting…");
    try {
      const r = await fetch("/api/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      if (!r.ok) {
        setState("Token not accepted");
        return;
      }
      setToken("");
      await load();
    } catch {
      setState("Backend unavailable");
    }
  };
  const runLocal=async()=>{
    setRunning(true);
    try {
      const session=await fetch('/api/session');
      if(!session.ok) throw Error('Unlock the workspace again');
      const {csrf_token}=await session.json();
      const r=await fetch('/api/local-runs',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf_token},body:JSON.stringify({case:'four_app_two_payments'})});
      if(!r.ok) throw Error('Local run failed');
      await load();
    } catch { setState('Local session locked'); }
    finally { setRunning(false); }
  };
  const runHunter=async(episodeId:string)=>{
    setRunningHunter(episodeId);
    try {
      const session=await fetch('/api/session');
      if(!session.ok) throw Error('Unlock the workspace again');
      const {csrf_token}=await session.json();
      const response=await fetch(`/api/local-hunter/${episodeId}`,{method:'POST',headers:{'X-CSRF-Token':csrf_token}});
      if(!response.ok) throw Error('Hunter fixture failed');
      const result=await response.json();
      setHunterResults(current=>({...current,[episodeId]:result}));
    } catch { setState('Local session locked'); }
    finally { setRunningHunter(null); }
  };
  return (
    <Shell>
      <p className="eyebrow">CONTROLLED LOCAL WORKSPACE</p>
      <h1>Protection workspace</h1>
      <div className="empty">
        <span className="status-dot" />
        <h2 aria-live="polite">{state}</h2>
        {["Local session locked", "Token not accepted"].includes(state) ? (
          <form className="unlock" onSubmit={unlock}>
            <p>
              Enter the operator token stored by your local DeBait backend. It
              stays in this request and is never bundled into the frontend.
            </p>
            <label htmlFor="operator-token">Local operator token</label>
            <input
              id="operator-token"
              type="password"
              autoComplete="current-password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              required
            />
            <button className="button" type="submit">
              Unlock workspace
            </button>
          </form>
        ) : (
          <p>
            {state === "Backend unavailable"
              ? "Start the DeBait backend on 127.0.0.1:8000 to inspect episodes. No episode data has been invented."
              : "The workspace is ready for controlled episode data."}
          </p>
        )}
      </div>
      {['Episodes available','No active episodes'].includes(state) && <section className="episode-console">
        {usage && <section className="usage-panel" data-testid="usage-panel"><div><p className="eyebrow">PERSISTED MODEL BUDGET · {usage.currency}</p><h2>Usage boundary</h2><p>{usage.fresh_model_enabled?'Fresh model enabled':'Fresh model disabled'} · {usage.mode.replaceAll('_',' ')}</p></div><dl><div><dt>{dollars(usage.model.spent_microdollars)} measured</dt><dd>settled usage</dd></div><div><dt>{dollars(usage.model.reserved_microdollars)} reserved</dt><dd>unknown or in flight</dd></div><div><dt>{dollars(usage.model.available_microdollars)} available</dt><dd>within {dollars(usage.model.limit_microdollars)} cap</dd></div></dl></section>}
        <div className="run-toolbar"><div><p className="eyebrow">LOCAL STATEFUL WORLD</p><p>Deterministic fixture baseline · no live providers or model calls</p></div>
        <button className="button" disabled={running} onClick={runLocal}>{running?'Running…':'Run synthetic scenario'}</button></div>
        {episodes.map(episode=>{const proof=reports.find(r=>r.episode_id===episode.id);const detail=details[episode.id];const labelFor=(id:string)=>{const ev=detail?.events.find(e=>e.event_id===id);return ev?`${ev.provider}·${ev.payload.resource_id??''}`:id;};return <article className="episode-card" key={episode.id}>
          <header><h2>{episode.id}</h2><span className="state-pill">{episode.state.replaceAll('_',' ')}</span></header>
          {detail && detail.agent_trace.length>0 && <section className="agent-trace" data-testid="agent-trace"><p className="eyebrow">AGENT DECISION LOOP</p><ol>{detail.agent_trace.map(step=><li key={step.index} data-phase={step.phase}><span className="phase">{step.phase}</span><span className="summary">{step.summary}</span></li>)}</ol></section>}
          {detail && detail.edges.length>0 && <section className="causal-chain"><p className="eyebrow">CAUSAL CHAIN · TRUSTED PROVENANCE</p><div className="chain">{detail.edges.map(edge=><div key={`${edge.source_id}->${edge.target_id}:${edge.kind}`}><span>{labelFor(edge.source_id)}</span><em>{edge.kind.replaceAll('_',' ')}</em><span>{labelFor(edge.target_id)}</span></div>)}</div></section>}
          {proof && <><div className="payment-pair"><div data-testid="payment-scam"><span>Episode-linked test payment</span><strong>{proof.world.pi_scam}</strong></div><div data-testid="payment-unrelated"><span>Unrelated test payment</span><strong>{proof.world.pi_unrelated}</strong></div></div>
          <div className="action-list">{proof.actions.map(action=>{const observation=action.observations.at(-1);return <div key={action.target.resource_id}><span>{action.target.provider}</span><strong>{action.target.operation} · {action.target.resource_id}</strong><span>{observation?.state??'unverified'}</span><small>{observation?.level?.replaceAll('_',' ')} · {observation?.source}</small></div>})}</div>
          {episode.state==='CONTAINED' && <section className="hunter-panel"><div><p className="eyebrow">DETERMINISTIC LOCAL DECOY · NO REAL CONTACT</p><h3>Post-containment Hunter</h3><p>One bounded fixture exchange asks the controlled attacker for demonstration payment infrastructure. It cannot reopen the victim context or send money.</p></div><button className="button secondary" disabled={runningHunter===episode.id} onClick={()=>runHunter(episode.id)}>{runningHunter===episode.id?'Running…':'Run isolated Hunter fixture'}</button>
          {hunterResults[episode.id] && <div className="indicator-list">{hunterResults[episode.id].indicators.map(item=><div key={`${item.kind}:${item.value}`}><span>{item.kind.replaceAll('_',' ')}</span><strong>{item.value}</strong><small>{item.claim_status.replaceAll('_',' ')}</small></div>)}</div>}</section>}</>}
        </article>})}
      </section>}
    </Shell>
  );
}
export function Evaluations() {
  type EvaluationReport = {
    run_id: string;
    run_mode: string;
    reasoning_mode: string;
    created_at: string;
    repeats: number;
    metrics: Record<string, number | null>;
    limitations: string[];
  };
  const [reports, setReports] = useState<EvaluationReport[] | null>(null);
  const [locked, setLocked] = useState(false);
  useEffect(() => {
    fetch("/api/evaluations")
      .then((response) => {
        if (response.status === 401) {
          setLocked(true);
          return [];
        }
        if (!response.ok) throw Error();
        return response.json();
      })
      .then(setReports)
      .catch(() => setReports([]));
  }, []);
  const latest = reports?.[0];
  const metrics = latest?.metrics;
  const isFresh = !!latest && (latest.run_mode?.includes("fresh_model") || latest.reasoning_mode?.startsWith("fresh_model"));
  const modelName = latest?.reasoning_mode?.includes(":") ? latest.reasoning_mode.split(":")[1] : "openai";
  return (
    <Shell>
      <p className="eyebrow">MEASURED EVIDENCE</p>
      <h1>{latest ? (isFresh ? "Live-model reliability run" : "Local reliability baseline") : "Evaluation not run."}</h1>
      {latest ? (
        <>
          <p className="lede">
            {isFresh ? (
              <span className="live-badge" data-testid="reasoning-badge">LIVE MODEL · {modelName}</span>
            ) : (
              <span className="live-badge fixture" data-testid="reasoning-badge">DETERMINISTIC FIXTURE</span>
            )}{" "}
            {latest.run_mode.replaceAll("_", " ")} · {latest.repeats} repeat{latest.repeats === 1 ? "" : "s"}
          </p>
          <div className="metric-grid" aria-label="Evaluation metrics">
            <article><strong>{metrics?.unique_case_count}</strong><span>authored fixture cases</span></article>
            <article><strong>{metrics?.total_runs}</strong><span>total runs</span></article>
            {metrics?.correct_outcomes != null && <article data-testid="correct-outcomes"><strong>{metrics.correct_outcomes} / {metrics.total_runs}</strong><span>correct outcomes{metrics.outcome_accuracy != null ? ` · ${Math.round(metrics.outcome_accuracy * 100)}%` : ""}</span></article>}
            <article><strong>{metrics?.recoverable_attacks_contained ?? metrics?.attacks_contained} / {metrics?.recoverable_attack_count ?? metrics?.attack_count}</strong><span>recoverable attacks contained</span></article>
            {metrics?.fault_cases != null && metrics.fault_cases > 0 && <article><strong>{metrics.fault_outcomes_correct} / {metrics.fault_cases}</strong><span>fault outcomes correct</span></article>}
            <article><strong>{metrics?.benign_uninterrupted} / {metrics?.benign_count}</strong><span>benign uninterrupted</span></article>
            {metrics?.model_cost_microdollars != null && metrics.model_cost_microdollars > 0 && <article data-testid="model-cost"><strong>${(metrics.model_cost_microdollars / 1_000_000).toFixed(2)}</strong><span>measured model cost</span></article>}
            <article><strong>{metrics?.false_financial_interventions}</strong><span>false financial interventions</span></article>
            <article><strong>{metrics?.unauthorized_effects}</strong><span>unauthorized effects</span></article>
            <article><strong>{metrics?.duplicate_logical_effects}</strong><span>duplicate effects</span></article>
            <article><strong>{metrics?.incorrect_final_states}</strong><span>incorrect final states</span></article>
          </div>
          {metrics?.fault_cases != null && metrics.fault_cases > 0 && (
            <p className="metric-note" data-testid="fault-note">
              Integration-fault and payment-already-settled cases are designed to end
              partially contained or prevention-failed, so full-containment rate is below 100% by
              construction. Correct-outcome accuracy — did each case reach its correct best-possible
              state — is the quality measure, and unrecoverable faults are counted honestly.
            </p>
          )}
          <section className="limitations" aria-labelledby="limits-title">
            <h2 id="limits-title">What this run does and does not prove</h2>
            <ul>{latest.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
          </section>
        </>
      ) : (
        <p className="lede">
          {locked
            ? "Unlock the local workspace to view measured reports."
            : reports === null
              ? "Checking the local report store…"
              : "No measured results are available. Run an authored local fixture manifest to create one."}
        </p>
      )}
      <a className="button secondary" href="/architecture">
        Review evaluation design
      </a>
    </Shell>
  );
}
