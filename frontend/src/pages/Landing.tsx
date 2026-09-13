import { ChainIllustration } from "../components/ChainIllustration";
const lifecycle = [
  ["01", "Observe", "Collect authorized signals without assuming identity."],
  [
    "02",
    "Connect",
    "Join evidence through provider IDs and controlled navigation.",
  ],
  ["03", "Decide", "Resolve an exact resource against trusted scope."],
  [
    "04",
    "Contain",
    "Prioritize the bound sandbox payment and linked surfaces.",
  ],
  ["05", "Verify", "Read fresh provider state and expose uncertainty."],
  ["06", "Improve", "Turn reviewed traces into stronger regression worlds."],
];
export function Landing() {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  return (
    <>
      <header className="nav">
        <a className="brand" href="/">
          <img src="/debait-mark.svg" alt="" />
          DeBait
        </a>
        <nav aria-label="Primary navigation">
          <a href="#how">How it works</a>
          <a href="/evaluations">Evaluations</a>
          <a href="/architecture">Architecture</a>
        </nav>
        <a className="nav-cta" href="/app">
          Open workspace <span>↗</span>
        </a>
      </header>
      <main>
        <section className="hero">
          <div className="hero-copy">
            <p className="eyebrow">
              <span /> CONTROLLED PROTECTION WORKSPACE
            </p>
            <h1>
              Scammers cross apps. <em>DeBait does too.</em>
            </h1>
            <p className="lede">
              Connect the evidence across authorized calls, test chats, managed
              browsing, and sandbox payments. Stop the linked test payment.
              Verify every action.
            </p>
            <div className="actions">
              <a className="button" href="/app">
          Open protection workspace <span>→</span>
              </a>
              <a className="text-link" href="#how">
                See how it connects ↓
              </a>
            </div>
            <p className="fine">
              Built for synthetic scenarios and controlled integrations.
            </p>
          </div>
          <ChainIllustration reducedMotion={reduced} />
        </section>
        <section className="section split" id="how">
          <div>
            <p className="eyebrow">CONNECTED CONTEXT</p>
            <h2>One episode. Four surfaces. One precise response.</h2>
          </div>
          <div>
            <p className="section-copy">
              A matching amount is only a clue. DeBait follows evidence-backed
              relationships to the intended sandbox payment while leaving an
              equal-value, unrelated payment untouched.
            </p>
            <div className="compare">
              <div>
                <small>LINKED ORIGIN</small>
                <b>$250.00</b>
                <span className="safe">Bound · eligible to protect</span>
              </div>
              <div>
                <small>UNRELATED ORIGIN</small>
                <b>$250.00</b>
                <span>Preserved · no action</span>
              </div>
            </div>
          </div>
        </section>
        <section className="section lifecycle">
          <p className="eyebrow">THE FULL LOOP</p>
          <h2>See every step from signal to stronger policy.</h2>
          <div className="steps">
            {lifecycle.map(([n, t, d]) => (
              <article key={n}>
                <span>{n}</span>
                <h3>{t}</h3>
                <p>{d}</p>
              </article>
            ))}
          </div>
        </section>
        <section className="section proof">
          <div>
            <p className="eyebrow">INSPECTABLE PROOF</p>
            <h2>Claims should come with receipts.</h2>
            <p>
              Every proposed action can point back to its evidence, scope check,
              durable action record, and fresh verification result.
            </p>
            <a className="text-link" href="/architecture">
              Explore system architecture →
            </a>
          </div>
          <div className="terminal">
            <div>
              <i />
              <i />
              <i />
            </div>
            <code>
              <span>episode / ep_demo_017</span>
              {"\n"}target&nbsp;&nbsp; / pi_sandbox_7A3{`\n`}basis&nbsp;&nbsp; /
              browser binding + provider id{`\n`}scope&nbsp;&nbsp; / authorized
              test resource{`\n`}result&nbsp; / <b>verification pending</b>
            </code>
          </div>
        </section>
        <section className="section boundaries">
          <div>
            <p className="eyebrow">OPERATING BOUNDARY</p>
            <h2>Designed for controlled environments.</h2>
          </div>
          <div className="boundary-grid">
            <p>
              <b>Works with</b>Synthetic content, authorized test conversations,
              managed browser sessions, and sandbox payments.
            </p>
            <p>
              <b>Does not claim</b>Access to private messages, ordinary cellular
              calls, arbitrary browsing, or consumer bank transfers.
            </p>
          </div>
        </section>
        <section className="section eval">
          <div>
            <p className="eyebrow">EVALUATION STATUS</p>
            <h2>Evaluation not run.</h2>
            <p>
              Results will appear only after a recorded run, with denominators
              and failures intact.
            </p>
          </div>
          <a className="button secondary" href="/evaluations">
            View evaluation approach <span>→</span>
          </a>
        </section>
        <section className="closing">
          <p className="eyebrow">FOR TRUST, RISK & FRAUD TEAMS</p>
          <h2>
            Follow the scam.
            <br />
            <em>Protect the right payment.</em>
          </h2>
          <a className="button light" href="/app">
            Explore protection workspace <span>→</span>
          </a>
        </section>
      </main>
      <footer>
        <a className="brand" href="/">
          <img src="/debait-mark.svg" alt="" />
          DeBait
        </a>
        <p>Scoped protection for controlled, connected scenarios.</p>
        <nav aria-label="Footer navigation">
          <a href="/architecture">Architecture</a>
          <a href="/evaluations">Evaluations</a>
        </nav>
      </footer>
    </>
  );
}
