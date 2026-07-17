// Generated from the approved legacy marketing markup during the F25 App Router migration.
// The strings are static, repository-owned HTML and never include user-controlled content.

export const homeContent = `
<!-- HERO -->
<section class="hero" id="platform">
  <div class="wrap hero-in">
    <div class="h-copy">
      <span class="eyebrow">The runtime layer for AI compliance</span>
      <h1>Stop sensitive data <span class="hl">before</span> it reaches the model.</h1>
      <p class="sub">AuthClaw sits in the live path between your applications and AI. It removes PII and PHI in real time, fixes compliance gaps with human approval, and keeps a tamper-evident record your auditors can trust.</p>
      <div class="cta-row">
      <a class="btn btn-primary" href="{{trial}}">Start free trial</a>
        <a class="btn btn-ghost" href="#how">See how it works</a>
      </div>
      <p class="microcopy">No card required · 14-day trial · Deploys in your VPC</p>
      <div class="trust">
        <div class="t-label">Built for teams shipping AI in regulated environments</div>
        <div class="badge-row">
          <span class="fw">SOC 2</span><span class="fw">HIPAA</span><span class="fw">GDPR</span>
          <span class="fw">ISO 42001</span><span class="fw">EU AI Act</span>
        </div>
      </div>
    </div>

    <!-- signature: live gateway -->
    <div class="gw" aria-label="Live redaction gateway demonstration">
      <div class="lat" id="lat">+38ms</div>
      <div class="gw-bar"><i></i><i></i><i class="g"></i><span class="gw-title">authclaw · in-line gateway</span></div>
      <div class="gw-flow">
        <div class="node">
          <div class="nlabel"><span>Inbound prompt</span><span>app → authclaw</span></div>
          <div class="code" id="inNode">
            <span class="tok">summarize the chart for patient </span><span class="pii" data-real="Priya Nair">Priya Nair</span><span class="tok">, dob </span><span class="pii" data-real="04/12/1986">04/12/1986</span><span class="tok">, mrn </span><span class="pii" data-real="8830-221">8830-221</span>
          </div>
        </div>
        <div class="arrow">↓</div>
        <div class="node gwcore">
          <div class="nlabel"><span>AuthClaw</span><span>redact · enforce · log</span></div>
          <div class="gw-chips">
            <span class="chip v">Presidio + NER</span>
            <span class="chip v">policy: PHI-block</span>
            <span class="chip ok">audit ✓ chained</span>
          </div>
        </div>
        <div class="arrow">↓</div>
        <div class="node">
          <div class="nlabel"><span>Forwarded to model</span><span>authclaw → provider</span></div>
          <div class="code" id="outNode">
            <span class="tok">summarize the chart for patient </span><span class="pii masked">[NAME]</span><span class="tok">, dob </span><span class="pii masked">[DATE]</span><span class="tok">, mrn </span><span class="pii masked">[ID]</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- LOGO WALL -->
<section class="logowall">
  <div class="wrap">
    <span class="ll">Trusted by teams shipping AI in regulated markets</span>
    <span class="logo-ipsum">Meridian&nbsp;Health</span>
    <span class="logo-ipsum">Northwind&nbsp;Bank</span>
    <span class="logo-ipsum">Vantel</span>
    <span class="logo-ipsum">Corvus&nbsp;AI</span>
    <span class="logo-ipsum">Halcyon</span>
    <span class="logo-ipsum">Bluecliff</span>
  </div>
</section>

<!-- CONTRAST / POSITIONING -->
<section class="contrast band-tight">
  <div class="wrap">
    <div class="reveal">
      <span class="eyebrow" style="color:var(--violet-300)">Posture tools prove yesterday</span>
      <h2>Most compliance tools tell you what happened. <span class="kv">AuthClaw acts on every request</span>, right now.</h2>
      <p class="lead">Dashboards and audits describe your posture after the fact. AuthClaw is the enforcement point: it inspects each call to a model, strips what should never leave, and blocks what breaks your rules, before anything reaches an external provider.</p>
    </div>
    <div class="stat-grid reveal">
      <div class="stat"><div class="n">&lt;50<span class="u">ms</span></div><div class="l">added latency per request</div></div>
      <div class="stat"><div class="n">99.99<span class="u">%</span></div><div class="l">uptime target, multi-region</div></div>
      <div class="stat"><div class="n">100<span class="u">%</span></div><div class="l">of prompts and responses inspected</div></div>
      <div class="stat"><div class="n">1<span class="u">-click</span></div><div class="l">verifiable audit export</div></div>
    </div>
  </div>
</section>

<!-- PILLARS -->
<section class="band">
  <div class="wrap">
    <div class="sec-head reveal">
      <span class="eyebrow">One gateway, three jobs</span>
      <h2>Everything AI touches, governed in one place.</h2>
      <p class="sub">AuthClaw runs as a single in-line service. It protects data on the way out, fixes the gaps it finds, and records proof of both.</p>
    </div>
    <div class="pillars">
      <div class="pcard reveal">
        <div class="top-accent"></div>
        <div class="pnum">01 / Gateway</div>
        <div class="picon">▤</div>
        <h3>The checkpoint</h3>
        <p>AI traffic configured to use AuthClaw passes through the gateway first. Configured sensitive-data patterns can be detected and masked, hashed, or replaced before model-provider egress. Rules can block traffic that violates configured policies.</p>
      </div>
      <div class="pcard reveal">
        <div class="top-accent"></div>
        <div class="pnum">02 / Agent</div>
        <div class="picon">◈</div>
        <h3>The remediation agent</h3>
        <p>An AI agent scans your cloud, explains in plain language where you fall short of GDPR, HIPAA, and SOC 2, and prepares the fix. Nothing risky runs until a person approves it, with a security check.</p>
      </div>
      <div class="pcard reveal">
        <div class="top-accent"></div>
        <div class="pnum">03 / Audit</div>
        <div class="picon">⛭</div>
        <h3>The audit recorder</h3>
        <p>Every request, decision, and approval is written to a tamper-evident, hash-chained log. Export verifiable evidence for auditors and customers, or publish a live trust page, in one click.</p>
      </div>
    </div>
  </div>
</section>

<!-- HOW IT WORKS -->
<section class="band-tight" id="how" style="background:var(--paper-2);border-top:1px solid var(--line);border-bottom:1px solid var(--line)">
  <div class="wrap">
    <div class="sec-head reveal">
      <span class="eyebrow">The request lifecycle</span>
      <h2>Four steps, on every call.</h2>
    </div>
    <div class="steps">
      <div class="step reveal"><div class="sn">1</div><h3>Intercept</h3><p>Requests reach the gateway over HTTPS or gRPC, native provider format preserved.</p></div>
      <div class="step reveal"><div class="sn">2</div><h3>Redact and enforce</h3><p>Presidio and NER strip sensitive data. Policy rules block traffic that breaks your standards.</p></div>
      <div class="step reveal"><div class="sn">3</div><h3>Forward</h3><p>The clean payload goes to OpenAI, Anthropic, Azure, or Cohere with nothing sensitive attached.</p></div>
      <div class="step reveal"><div class="sn">4</div><h3>Record</h3><p>A hash-chained audit entry is written for the request, the response, and every decision made.</p></div>
    </div>
  </div>
</section>

<!-- MODULES -->
<section class="band" id="modules">
  <div class="wrap">
    <div class="sec-head center reveal">
      <span class="eyebrow">The platform</span>
      <h2>Four products. One in-line service.</h2>
    </div>

    <div class="module reveal">
      <div class="m-copy">
        <span class="eyebrow">In-line gateway</span>
        <h3>A safe path to every model.</h3>
        <p class="md">Reverse-proxy the major providers without changing your API calls. AuthClaw redacts in real time and holds the line on policy, even on streaming responses, token by token.</p>
        <ul class="mlist">
          <li><span class="tk">▸</span> Multi-model proxy for OpenAI, Anthropic, Azure OpenAI, and Cohere</li>
          <li><span class="tk">▸</span> Masking, salted hashing, or synthetic replacement per field</li>
          <li><span class="tk">▸</span> Policy-as-code with topic and pattern blocking</li>
        </ul>
      </div>
      <div class="m-visual">
        <div class="mv-head"><span><span class="dotpill"></span>gateway · live traffic</span><span>redaction on</span></div>
        <div class="rowline"><span>prompt · support-bot</span><span class="pill appr">2 fields masked</span></div>
        <div class="rowline"><span>prompt · billing-agent</span><span class="pill block">blocked · card number</span></div>
        <div class="rowline"><span>response · claims-llm</span><span class="pill appr">clean</span></div>
        <div class="rowline"><span>prompt · intake-form</span><span class="pill appr">1 field hashed</span></div>
      </div>
    </div>

    <div class="module rev reveal">
      <div class="m-copy">
        <span class="eyebrow">Agentic remediation</span>
        <h3>The agent proposes. A human decides.</h3>
        <p class="md">The remediation agent finds gaps, drafts the exact change as a Terraform or CLI diff, and waits. Consequential actions sit in an approval state, expire if untouched, and only run after a person clears a security check.</p>
        <ul class="mlist">
          <li><span class="tk">▸</span> Orchestrator with short-lived, scoped workers</li>
          <li><span class="tk">▸</span> Human approval with MFA on every change</li>
          <li><span class="tk">▸</span> Approvals expire automatically after 30 minutes</li>
        </ul>
      </div>
      <div class="m-visual">
        <div class="mv-head"><span><span class="dotpill" style="background:var(--gold)"></span>remediation · pending</span><span>1 awaiting approval</span></div>
        <div class="rowline"><span>Restrict S3 bucket policy</span><span class="pill wait">awaiting approval</span></div>
        <div class="rowline"><span>Rotate exposed API key</span><span class="pill appr">approved · applied</span></div>
        <div class="rowline"><span>Enable audit logging</span><span class="pill appr">approved · applied</span></div>
        <div class="rowline"><span>Delete public snapshot</span><span class="pill wait">needs MFA</span></div>
      </div>
    </div>

    <div class="module reveal">
      <div class="m-copy">
        <span class="eyebrow">Continuous audit &amp; trust center</span>
        <h3>Proof that cannot be quietly changed.</h3>
        <p class="md">Every action lands in an append-only log, each entry chained to the last with a SHA-256 hash. Export a signed evidence bundle for an auditor, or publish a live trust page for buyers, without assembling anything by hand.</p>
        <ul class="mlist">
          <li><span class="tk">▸</span> Tamper-evident, hash-chained records</li>
          <li><span class="tk">▸</span> Cryptographically verifiable export</li>
          <li><span class="tk">▸</span> Buyer-ready trust center with current readiness information</li>
        </ul>
      </div>
      <div class="m-visual">
        <div class="mv-head"><span><span class="dotpill"></span>audit trail · verified</span><span>chain intact</span></div>
        <div class="rowline"><span class="code" style="font-size:12.5px">#4471 · redaction · gateway</span><span class="pill appr">✓ hash</span></div>
        <div class="rowline"><span class="code" style="font-size:12.5px">#4472 · approval · user</span><span class="pill appr">✓ hash</span></div>
        <div class="rowline"><span class="code" style="font-size:12.5px">#4473 · execute · agent</span><span class="pill appr">✓ hash</span></div>
        <div class="rowline"><span class="code" style="font-size:12.5px">#4474 · export · SOC 2</span><span class="pill appr">✓ signed</span></div>
      </div>
    </div>

    <div class="module rev reveal">
      <div class="m-copy">
        <span class="eyebrow">Framework scoring</span>
        <h3>Readiness you can read at a glance.</h3>
        <p class="md">See live readiness for SOC 2, GDPR, and the HIPAA Security Rule, scored from real signals across your systems, not a survey filled in once a quarter.</p>
        <ul class="mlist">
          <li><span class="tk">▸</span> Real-time scores per framework</li>
          <li><span class="tk">▸</span> Control-by-control mapping and evidence links</li>
          <li><span class="tk">▸</span> Upload any regulation or contract to add controls</li>
        </ul>
      </div>
      <div class="m-visual">
        <div class="mv-head"><span><span class="dotpill"></span>readiness · this org</span><span>updated live</span></div>
        <div class="scorecard">
          <div class="srow"><div class="top"><span>SOC 2 Type II</span><b>92%</b></div><div class="meter"><i style="width:92%"></i></div></div>
          <div class="srow"><div class="top"><span>GDPR</span><b>88%</b></div><div class="meter"><i style="width:88%"></i></div></div>
          <div class="srow"><div class="top"><span>HIPAA Security Rule</span><b>81%</b></div><div class="meter"><i style="width:81%"></i></div></div>
        </div>
      </div>
    </div>
    <div class="center" style="margin-top:40px">
      <a class="btn btn-ghost" href="/product">Explore the full platform →</a>
    </div>
  </div>
</section>

<!-- FRAMEWORKS / MODELS RAIL -->
<section class="rail band-tight" id="frameworks">
  <div class="wrap grid2">
    <div class="reveal">
      <h3>Speaks every major model</h3>
      <div class="taglist">
        <span class="tag"><span class="d">◆</span>OpenAI</span>
        <span class="tag"><span class="d">◆</span>Anthropic</span>
        <span class="tag"><span class="d">◆</span>Azure OpenAI</span>
        <span class="tag"><span class="d">◆</span>Cohere</span>
        <span class="tag"><span class="d">◆</span>AWS Bedrock</span>
      </div>
      <h4 style="margin-top:26px">Connects your environment</h3>
      <div class="taglist">
        <span class="tag"><span class="d">◇</span>AWS</span>
        <span class="tag"><span class="d">◇</span>GCP</span>
        <span class="tag"><span class="d">◇</span>Azure</span>
        <span class="tag"><span class="d">◇</span>GitHub</span>
      </div>
    </div>
    <div class="reveal">
      <h3>Maps every framework</h3>
      <div class="taglist">
        <span class="tag">SOC 2</span><span class="tag">HIPAA</span><span class="tag">GDPR</span>
        <span class="tag">ISO 27001</span><span class="tag">ISO 42001</span><span class="tag">NIST AI RMF</span>
        <span class="tag">EU AI Act</span><span class="tag">PCI DSS</span>
      </div>
      <p style="color:var(--slate);font-size:15px;margin-top:18px">Upload any additional regulation or contract, and AuthClaw turns it into controls it can score and enforce.</p>
    </div>
  </div>
</section>

<!-- PLANS PREVIEW -->
<section class="band">
  <div class="wrap">
    <div class="sec-head center reveal">
      <span class="eyebrow">Pricing</span>
      <h2>Plans that scale from first prompt to enterprise.</h2>
      <p class="sub" style="margin-left:auto;margin-right:auto">Start self-serve, expand as your AI traffic and frameworks grow. Transparent tiers, no per-token markup.</p>
    </div>
    <div class="plans">
      <div class="plan reveal">
        <div class="pname">Team</div>
        <p class="pdesc">For a first regulated workload going live.</p>
        <div class="price"><span class="amt">$1,990</span><span class="per">/mo</span></div>
        <div class="billed">billed annually</div>
        <a class="btn btn-ghost btn-block p-cta" href="{{trial}}">Start free trial</a>
        <div class="pfeat-label">Includes</div>
        <ul class="feat">
          <li><span class="ck">✓</span> 1 compliance framework</li>
          <li><span class="ck">✓</span> Up to 5M protected calls / mo</li>
          <li><span class="ck">✓</span> Gateway + audit &amp; trust center</li>
        </ul>
      </div>
      <div class="plan featured reveal">
        <div class="ptag">Most popular</div>
        <div class="pname">Growth</div>
        <p class="pdesc">For teams scaling AI across the business.</p>
        <div class="price"><span class="amt">$4,500</span><span class="per">/mo</span></div>
        <div class="billed">billed annually</div>
        <a class="btn btn-primary btn-block p-cta" href="{{trial}}">Start free trial</a>
        <div class="pfeat-label">Everything in Team, plus</div>
        <ul class="feat">
          <li><span class="ck">✓</span> All three frameworks (SOC 2 / GDPR / HIPAA)</li>
          <li><span class="ck">✓</span> Up to 25M protected calls / mo</li>
          <li><span class="ck">✓</span> Agentic remediation + HITL approvals</li>
        </ul>
      </div>
      <div class="plan reveal">
        <div class="pname">Enterprise</div>
        <p class="pdesc">For regulated scale, custom volume &amp; SLAs.</p>
        <div class="price"><span class="custom">Custom</span></div>
        <div class="billed">annual contract</div>
        <a class="btn btn-ghost btn-block p-cta" href="{{contact}}">Contact sales</a>
        <div class="pfeat-label">Everything in Growth, plus</div>
        <ul class="feat">
          <li><span class="ck">✓</span> Unlimited frameworks &amp; volume</li>
          <li><span class="ck">✓</span> 99.99% SLA, multi-region / VPC</li>
          <li><span class="ck">✓</span> SSO/SAML, dedicated support</li>
        </ul>
      </div>
    </div>
    <div class="center" style="margin-top:32px">
      <a class="btn btn-ghost" href="/pricing">Compare all plans &amp; features →</a>
    </div>
  </div>
</section>

<!-- WHY / COMPARISON -->
<section class="band-tight" id="why" style="background:var(--paper-2);border-top:1px solid var(--line);border-bottom:1px solid var(--line)">
  <div class="wrap">
    <div class="sec-head reveal">
      <span class="eyebrow">Why AuthClaw</span>
      <h2>Other tools describe risk. AuthClaw removes it in the path.</h2>
      <p class="sub">Posture platforms and model-testing tools each cover one slice. AuthClaw is the live layer where enforcement, remediation, and proof come together.</p>
    </div>
    <table class="cmp reveal"><caption class="sr-only">AuthClaw capability comparison</caption>
      <thead>
        <tr><th scope="col"></th><th scope="col">Traditional GRC &amp; AI testing tools</th><th scope="col" class="us">AuthClaw</th></tr>
      </thead>
      <tbody>
        <tr><td>Sensitive data</td><td class="them">Reviewed after the fact</td><td class="us">Removed in real time, before egress</td></tr>
        <tr><td>Compliance gaps</td><td class="them">Flagged in a report</td><td class="us">Fixed with human approval</td></tr>
        <tr><td>Audit evidence</td><td class="them">Assembled by hand</td><td class="us">Recorded automatically, tamper-evident</td></tr>
        <tr><td>AI traffic</td><td class="them">Outside their view</td><td class="us">Inspected on every request</td></tr>
        <tr><td>Human role</td><td class="them">Doing the work</td><td class="us">Approving the decisions</td></tr>
      </tbody>
    </table>

    <div class="quotes">
      <div class="quote reveal">
        <div class="qm">”</div>
        <p>AuthClaw is the first tool that actually sits in the request path. We can show customers that nothing sensitive ever leaves our walls.</p>
        <div class="who"><b>Head of Security</b><br>Series C healthtech</div>
      </div>
      <div class="quote reveal">
        <div class="qm">”</div>
        <p>The approval workflow is what sold our board. The agent proposes the change, and a person is always the one who decides.</p>
        <div class="who"><b>VP Engineering</b><br>Financial services platform</div>
      </div>
    </div>
  </div>
</section>

<!-- FINAL CTA -->
<section class="finalcta" id="demo">
  <div class="wrap">
    <span class="eyebrow" style="color:var(--gold)">Get started</span>
    <h2>Put AuthClaw in front of your models.</h2>
    <p>See a live redaction, an approved remediation, and a verifiable audit export, in one walkthrough. Or start a free trial and be in the path today.</p>
    <div class="cta-row">
      <a class="btn btn-gold" href="{{trial}}">Start free trial</a>
      <a class="btn btn-light" href="{{demo}}">Book a demo</a>
    </div>
  </div>
</section>
`;

export const productContent = `
<!-- PAGE HEADER -->
<section class="pagehead">
  <div class="wrap">
    <span class="eyebrow">The platform</span>
    <h1>One service in the path. <br>Enforcement, remediation, and proof.</h1>
    <p class="sub">AuthClaw is a single, low-latency service that sits between your applications and every model you call. It redacts sensitive data before egress, remediates the gaps it finds under human approval, and records tamper-evident evidence of both.</p>
    <div class="cta-row">
      <a class="btn btn-primary" href="{{trial}}">Start free trial</a>
      <a class="btn btn-ghost" href="#architecture">See the architecture</a>
    </div>
  </div>
</section>

<!-- CAPABILITY GRID -->
<section class="band">
  <div class="wrap">
    <div class="sec-head center reveal" style="margin:0 auto">
      <span class="eyebrow">Capabilities</span>
      <h2>Four products, one in-line service.</h2>
      <p class="sub" style="margin-left:auto;margin-right:auto">Everything AI touches — inputs, outputs, cloud config, and evidence — governed in one place.</p>
    </div>
    <div class="fgrid">
      <div class="fcard reveal"><div class="ico">▤</div><h3>Multi-model gateway</h3><p>Reverse-proxy OpenAI, Anthropic, Azure OpenAI, Cohere, and Bedrock with native payload compatibility — no SDK changes.</p></div>
      <div class="fcard reveal"><div class="ico">◆</div><h3>PII / PHI redaction</h3><p>Microsoft Presidio plus custom NER detect sensitive data and mask, salt-hash, or synthetically replace it per field.</p></div>
      <div class="fcard reveal"><div class="ico">≋</div><h3>Streaming-safe filtering</h3><p>Token-by-token inspection on streamed responses with no fragmentation and no broken JSON.</p></div>
      <div class="fcard reveal"><div class="ico">⌘</div><h3>Policy-as-code</h3><p>YAML policies validated by Open Policy Agent. Block topics, patterns, and prompt-injection classes before egress.</p></div>
      <div class="fcard reveal"><div class="ico">◈</div><h3>Agentic remediation</h3><p>A LangGraph orchestrator scans your cloud, explains gaps via RAG over the regulations, and drafts the exact fix.</p></div>
      <div class="fcard reveal"><div class="ico">⛨</div><h3>Human-in-the-loop</h3><p>Consequential changes wait in an approval state, expire after 30 minutes, and require a fresh MFA challenge to run.</p></div>
      <div class="fcard reveal"><div class="ico">⛭</div><h3>tamper-evident audit</h3><p>An append-only, SHA-256 hash-chained log of every request, decision, and approval — verifiable end to end.</p></div>
      <div class="fcard reveal"><div class="ico">◎</div><h3>Framework scoring</h3><p>Live SOC 2, GDPR, and HIPAA readiness scored from real signals, with control-by-control evidence links.</p></div>
      <div class="fcard reveal"><div class="ico">✦</div><h3>Trust center</h3><p>Publish a live, current trust page and export signed evidence bundles for auditors and buyers in one click.</p></div>
    </div>
  </div>
</section>

<!-- MODULES DEEP DIVE -->
<section class="band-tight" style="background:var(--paper-2);border-top:1px solid var(--line);border-bottom:1px solid var(--line)">
  <div class="wrap">
    <div class="module reveal">
      <div class="m-copy">
        <span class="eyebrow">Layer 1 · In-line gateway</span>
        <h3>A safe path to every model.</h3>
        <p class="md">The gateway terminates HTTPS/gRPC from your apps, scrubs sensitive data, enforces policy, and forwards a clean payload to the provider — preserving the native API so nothing in your stack changes.</p>
        <ul class="mlist">
          <li><span class="tk">▸</span> Provider-agnostic request/response adapters</li>
          <li><span class="tk">▸</span> Masking, salted hashing, or synthetic replacement</li>
          <li><span class="tk">▸</span> Reversible, per-tenant tokenization maps</li>
        </ul>
      </div>
      <div class="m-visual">
        <div class="mv-head"><span><span class="dotpill"></span>gateway · live traffic</span><span>redaction on</span></div>
        <div class="rowline"><span>prompt · support-bot</span><span class="pill appr">2 fields masked</span></div>
        <div class="rowline"><span>prompt · billing-agent</span><span class="pill block">blocked · card number</span></div>
        <div class="rowline"><span>response · claims-llm</span><span class="pill appr">clean</span></div>
        <div class="rowline"><span>prompt · intake-form</span><span class="pill appr">1 field hashed</span></div>
      </div>
    </div>

    <div class="module rev reveal">
      <div class="m-copy">
        <span class="eyebrow">Layer 2 · Agentic engine</span>
        <h3>The agent proposes. A human decides.</h3>
        <p class="md">Ephemeral, scoped workers run cloud and SCM scans with short-lived tokens. The orchestrator explains each gap in plain language and drafts a Terraform or CLI diff that only executes after an approver clears an MFA check.</p>
        <ul class="mlist">
          <li><span class="tk">▸</span> Short-lived workers, minimum-scope tokens</li>
          <li><span class="tk">▸</span> Three-state model: read-only → plan → execute</li>
          <li><span class="tk">▸</span> Every action emits an audit record</li>
        </ul>
      </div>
      <div class="m-visual">
        <div class="mv-head"><span><span class="dotpill" style="background:var(--gold)"></span>remediation · pending</span><span>1 awaiting approval</span></div>
        <div class="rowline"><span>Restrict S3 bucket policy</span><span class="pill wait">awaiting approval</span></div>
        <div class="rowline"><span>Rotate exposed API key</span><span class="pill appr">approved · applied</span></div>
        <div class="rowline"><span>Enable audit logging</span><span class="pill appr">approved · applied</span></div>
        <div class="rowline"><span>Delete public snapshot</span><span class="pill wait">needs MFA</span></div>
      </div>
    </div>

    <div class="module reveal">
      <div class="m-copy">
        <span class="eyebrow">Layer 3 · Storage &amp; audit</span>
        <h3>Proof that cannot be quietly changed.</h3>
        <p class="md">Application state lives in PostgreSQL with strict multi-tenant isolation; the audit trail lives in ClickHouse as a high-volume, append-only, hash-chained log. Each record's integrity hash incorporates the prior record's, so any tampering is evident.</p>
        <ul class="mlist">
          <li><span class="tk">▸</span> Row-level tenant isolation</li>
          <li><span class="tk">▸</span> SHA-256 hash-chained, append-only records</li>
          <li><span class="tk">▸</span> Cryptographically verifiable export</li>
        </ul>
      </div>
      <div class="m-visual">
        <div class="mv-head"><span><span class="dotpill"></span>audit trail · verified</span><span>chain intact</span></div>
        <div class="rowline"><span class="code" style="font-size:12.5px">#4471 · redaction · gateway</span><span class="pill appr">✓ hash</span></div>
        <div class="rowline"><span class="code" style="font-size:12.5px">#4472 · approval · user</span><span class="pill appr">✓ hash</span></div>
        <div class="rowline"><span class="code" style="font-size:12.5px">#4473 · execute · agent</span><span class="pill appr">✓ hash</span></div>
        <div class="rowline"><span class="code" style="font-size:12.5px">#4474 · export · SOC 2</span><span class="pill appr">✓ signed</span></div>
      </div>
    </div>
  </div>
</section>

<!-- ARCHITECTURE / SPEC -->
<section class="band" id="architecture">
  <div class="wrap">
    <div class="sec-head reveal">
      <span class="eyebrow">Architecture</span>
      <h2>Decoupled, zero-trust, built for throughput.</h2>
      <p class="sub">Three layers map directly to the request lifecycle. The data plane is written for latency; the control plane for auditability. Sensitive credentials are envelope-encrypted and never held in workers.</p>
    </div>
    <div class="callout reveal">
      <span class="eyebrow">Reference stack</span>
      <table class="spec"><caption class="sr-only">AuthClaw architecture specifications</caption>
        <tr><td>Gateway proxy</td><td>Go / Rust · low-latency data plane</td></tr>
        <tr><td>Control-plane APIs</td><td>Python · FastAPI</td></tr>
        <tr><td>Agent framework</td><td>LangGraph orchestrator · TypeScript workers</td></tr>
        <tr><td>Sensitive-data detection</td><td>Microsoft Presidio + custom NER</td></tr>
        <tr><td>Policy engine</td><td>Open Policy Agent (OPA) + YAML policy-as-code</td></tr>
        <tr><td>Relational store</td><td>PostgreSQL · tenant config, RBAC, app state</td></tr>
        <tr><td>Audit store</td><td>ClickHouse · tamper-evident hash-chained traces</td></tr>
        <tr><td>Event backbone</td><td>Apache Kafka</td></tr>
        <tr><td>Secrets / KMS</td><td>AWS KMS or HashiCorp Vault · AES-256-GCM envelope</td></tr>
        <tr><td>Console</td><td>Next.js 15 admin experience</td></tr>
      </table>
    </div>
  </div>
</section>

<!-- INTEGRATIONS RAIL -->
<section class="rail band-tight">
  <div class="wrap grid2">
    <div class="reveal">
      <h3>Speaks every major model</h3>
      <div class="taglist">
        <span class="tag"><span class="d">◆</span>OpenAI</span>
        <span class="tag"><span class="d">◆</span>Anthropic</span>
        <span class="tag"><span class="d">◆</span>Azure OpenAI</span>
        <span class="tag"><span class="d">◆</span>Cohere</span>
        <span class="tag"><span class="d">◆</span>AWS Bedrock</span>
      </div>
      <h4 style="margin-top:26px">Connects your environment</h3>
      <div class="taglist">
        <span class="tag"><span class="d">◇</span>AWS</span>
        <span class="tag"><span class="d">◇</span>GCP</span>
        <span class="tag"><span class="d">◇</span>Azure</span>
        <span class="tag"><span class="d">◇</span>GitHub</span>
      </div>
    </div>
    <div class="reveal">
      <h3>Maps every framework</h3>
      <div class="taglist">
        <span class="tag">SOC 2</span><span class="tag">HIPAA</span><span class="tag">GDPR</span>
        <span class="tag">ISO 27001</span><span class="tag">ISO 42001</span><span class="tag">NIST AI RMF</span>
        <span class="tag">EU AI Act</span><span class="tag">PCI DSS</span>
      </div>
      <p style="color:var(--slate);font-size:15px;margin-top:18px">Upload any additional regulation or contract, and AuthClaw turns it into controls it can score and enforce.</p>
    </div>
  </div>
</section>

<!-- FINAL CTA -->
<section class="finalcta">
  <div class="wrap">
    <span class="eyebrow" style="color:var(--gold)">Get started</span>
    <h2>Put the whole platform in your path.</h2>
    <p>One in-line service for redaction, remediation, and proof. See it run on your traffic in a single walkthrough.</p>
    <div class="cta-row">
      <a class="btn btn-gold" href="{{trial}}">Start free trial</a>
      <a class="btn btn-light" href="{{demo}}">Book a demo</a>
    </div>
  </div>
</section>
`;

export const pricingContent = `
<!-- PAGE HEADER + TOGGLE -->
<section class="pagehead">
  <div class="wrap">
    <span class="eyebrow">Pricing</span>
    <h1>Priced on the value you protect, <br>not the tokens you spend.</h1>
    <p class="sub">AuthClaw meters on protected AI traffic and the frameworks you enforce — never a markup on model tokens. Bring your own provider keys. Start self-serve and expand to enterprise scale.</p>
    <div class="toggle-wrap">
      <div class="toggle annual" id="billToggle">
        <span class="slider"></span>
        <button id="billMonthly" type="button" aria-pressed="false">Monthly</button>
        <button id="billAnnual" class="on" type="button" aria-pressed="true">Annual</button>
      </div>
      <span class="save-badge">Save ~20% annually</span>
    </div>
  </div>
</section>

<!-- PLANS -->
<section class="band" style="padding-top:56px">
  <div class="wrap">
    <div class="plans">

      <div class="plan reveal">
        <div class="pname">Team</div>
        <p class="pdesc">For a first regulated AI workload going to production.</p>
        <div class="price"><span class="amt" data-m="$2,490" data-a="$1,990">$1,990</span><span class="per">/mo</span></div>
        <div class="billed" data-m="billed monthly" data-a="$23,880 billed annually">$23,880 billed annually</div>
        <a class="btn btn-ghost btn-block p-cta" href="{{trial}}">Start free trial</a>
        <div class="pfeat-label">Includes</div>
        <ul class="feat">
          <li><span class="ck">✓</span> 1 compliance framework (SOC 2, GDPR, or HIPAA)</li>
          <li><span class="ck">✓</span> Up to 5M protected calls / month</li>
          <li><span class="ck">✓</span> In-line gateway: redaction + policy enforcement</li>
          <li><span class="ck">✓</span> Hash-chained audit log &amp; trust center</li>
          <li><span class="ck">✓</span> Up to 5 seats · 1 connected environment</li>
          <li><span class="ck">✓</span> Email support · single region</li>
        </ul>
      </div>

      <div class="plan featured reveal">
        <div class="ptag">Most popular</div>
        <div class="pname">Growth</div>
        <p class="pdesc">For teams scaling AI across multiple products and frameworks.</p>
        <div class="price"><span class="amt" data-m="$5,500" data-a="$4,500">$4,500</span><span class="per">/mo</span></div>
        <div class="billed" data-m="billed monthly" data-a="$54,000 billed annually">$54,000 billed annually</div>
        <a class="btn btn-primary btn-block p-cta" href="{{trial}}">Start free trial</a>
        <div class="pfeat-label">Everything in Team, plus</div>
        <ul class="feat">
          <li><span class="ck">✓</span> All three frameworks: SOC 2 · GDPR · HIPAA</li>
          <li><span class="ck">✓</span> Up to 25M protected calls / month</li>
          <li><span class="ck">✓</span> Agentic remediation with HITL + MFA approvals</li>
          <li><span class="ck">✓</span> Real-time framework scoring &amp; evidence links</li>
          <li><span class="ck">✓</span> Up to 25 seats · 3 connected environments</li>
          <li><span class="ck">✓</span> SSO/SAML · priority support</li>
        </ul>
      </div>

      <div class="plan reveal">
        <div class="pname">Enterprise</div>
        <p class="pdesc">For regulated scale with custom volume, residency, and SLAs.</p>
        <div class="price"><span class="custom">Custom</span></div>
        <div class="billed">annual contract · volume-based</div>
        <a class="btn btn-ghost btn-block p-cta" href="{{contact}}">Contact sales</a>
        <div class="pfeat-label">Everything in Growth, plus</div>
        <ul class="feat">
          <li><span class="ck">✓</span> Unlimited frameworks + custom controls</li>
          <li><span class="ck">✓</span> Custom / uncapped protected volume</li>
          <li><span class="ck">✓</span> 99.99% SLA · multi-region active-active</li>
          <li><span class="ck">✓</span> Single-tenant, VPC, or air-gapped deployment</li>
          <li><span class="ck">✓</span> Unlimited seats &amp; environments</li>
          <li><span class="ck">✓</span> Dedicated CSM, SOC 2 support, custom DPA</li>
        </ul>
      </div>

    </div>
    <p class="pricenote">All plans include zero markup on model tokens — bring your own OpenAI, Anthropic, Azure, or Cohere keys. 14-day free trial, no card required.</p>
  </div>
</section>

<!-- ADD-ONS -->
<section class="band-tight" style="background:var(--paper-2);border-top:1px solid var(--line);border-bottom:1px solid var(--line)">
  <div class="wrap">
    <div class="sec-head center reveal" style="margin:0 auto">
      <span class="eyebrow">Expand as you grow</span>
      <h2>Usage &amp; add-ons</h2>
      <p class="sub" style="margin-left:auto;margin-right:auto">Every plan expands along the axes that map to real value — traffic, frameworks, and reach — so you only pay for what you actually protect.</p>
    </div>
    <div class="addons">
      <div class="addon reveal">
        <div class="ico">▤</div>
        <h3>Protected volume</h3>
        <p>Additional AI traffic beyond your plan's monthly allowance, billed per million protected calls. Predictable bands, hard caps available.</p>
        <div class="meta">from $180 / 1M calls</div>
      </div>
      <div class="addon reveal">
        <div class="ico">◈</div>
        <h3>Extra frameworks</h3>
        <p>Add ISO 27001, ISO 42001, NIST AI RMF, EU AI Act, or PCI DSS — or upload your own regulation or contract as enforceable controls.</p>
        <div class="meta">+$500 / mo per framework</div>
      </div>
      <div class="addon reveal">
        <div class="ico">◇</div>
        <h3>Seats &amp; environments</h3>
        <p>More approver seats and connected clouds (AWS, GCP, Azure, GitHub) as remediation coverage widens across your org.</p>
        <div class="meta">from $40 / seat · $250 / env</div>
      </div>
    </div>
  </div>
</section>

<!-- ENTERPRISE BAND -->
<section class="band">
  <div class="wrap">
    <div class="entband reveal">
      <div>
        <span class="eyebrow" style="color:var(--gold)">Enterprise</span>
        <h3>Built for the security review, not just the sale.</h3>
        <p>When AI traffic runs through the critical path, procurement asks hard questions. Enterprise answers them: your own tenancy, your region, your SLA, and evidence your auditors can verify cryptographically.</p>
        <ul class="ent-list">
          <li><span class="tk">◆</span> Single-tenant, VPC &amp; air-gapped options</li>
          <li><span class="tk">◆</span> 99.99% uptime SLA, multi-region</li>
          <li><span class="tk">◆</span> SSO/SAML, SCIM, granular RBAC</li>
          <li><span class="tk">◆</span> Custom DPA, BAA &amp; subprocessor terms</li>
          <li><span class="tk">◆</span> Volume-based, committed-use pricing</li>
          <li><span class="tk">◆</span> Dedicated CSM &amp; security engineer</li>
        </ul>
      </div>
      <div class="ent-cta">
        <a class="btn btn-gold btn-block" href="{{contact}}">Talk to sales</a>
        <a class="btn btn-light btn-block" href="/security">Review security</a>
        <span class="note">Typical enterprise agreements start at $120k / year</span>
      </div>
    </div>
  </div>
</section>

<!-- COMPARISON TABLE -->
<section class="band-tight">
  <div class="wrap">
    <div class="sec-head center reveal" style="margin:0 auto">
      <span class="eyebrow">Compare plans</span>
      <h2>Every capability, side by side.</h2>
    </div>
    <div class="ptable-wrap reveal">
      <table class="ptable"><caption class="sr-only">AuthClaw plan comparison</caption>
        <thead>
          <tr>
            <th scope="col" class="feat-col">Capability</th>
            <th scope="col">Team</th>
            <th scope="col" class="hi">Growth</th>
            <th scope="col">Enterprise</th>
          </tr>
        </thead>
        <tbody>
          <tr class="grouprow"><td colspan="4">In-line gateway</td></tr>
          <tr><td>Multi-model reverse proxy</td><td>✓</td><td class="hi">✓</td><td>✓</td></tr>
          <tr><td>Real-time PII / PHI redaction</td><td>✓</td><td class="hi">✓</td><td>✓</td></tr>
          <tr><td>Streaming, token-by-token filtering</td><td>✓</td><td class="hi">✓</td><td>✓</td></tr>
          <tr><td>Policy-as-code (YAML + OPA)</td><td>Standard</td><td class="hi">Advanced</td><td>Custom</td></tr>
          <tr><td>Protected calls / month</td><td>5M</td><td class="hi">25M</td><td>Custom</td></tr>
          <tr><td>Added latency target</td><td>&lt;50ms</td><td class="hi">&lt;50ms</td><td>&lt;50ms</td></tr>

          <tr class="grouprow"><td colspan="4">Agentic remediation</td></tr>
          <tr><td>Cloud &amp; SCM scanning</td><td class="no">—</td><td class="hi">✓</td><td>✓</td></tr>
          <tr><td>HITL approvals with MFA</td><td class="no">—</td><td class="hi">✓</td><td>✓</td></tr>
          <tr><td>Terraform / CLI remediation diffs</td><td class="no">—</td><td class="hi">✓</td><td>✓</td></tr>
          <tr><td>Connected environments</td><td>1</td><td class="hi">3</td><td>Unlimited</td></tr>

          <tr class="grouprow"><td colspan="4">Compliance &amp; audit</td></tr>
          <tr><td>Compliance frameworks</td><td>1</td><td class="hi">3</td><td>Unlimited</td></tr>
          <tr><td>Real-time framework scoring</td><td>Basic</td><td class="hi">✓</td><td>✓</td></tr>
          <tr><td>Hash-chained audit trail</td><td>✓</td><td class="hi">✓</td><td>✓</td></tr>
          <tr><td>Cryptographically verifiable export</td><td>✓</td><td class="hi">✓</td><td>✓</td></tr>
          <tr><td>Shareable trust center</td><td>✓</td><td class="hi">✓</td><td>✓</td></tr>
          <tr><td>Upload custom regulations</td><td class="no">—</td><td class="hi">✓</td><td>✓</td></tr>

          <tr class="grouprow"><td colspan="4">Platform &amp; security</td></tr>
          <tr><td>Seats included</td><td>5</td><td class="hi">25</td><td>Unlimited</td></tr>
          <tr><td>SSO / SAML &amp; SCIM</td><td class="no">—</td><td class="hi">✓</td><td>✓</td></tr>
          <tr><td>Deployment</td><td>Multi-tenant</td><td class="hi">Multi-tenant</td><td>VPC / air-gapped</td></tr>
          <tr><td>Uptime SLA</td><td>99.9%</td><td class="hi">99.95%</td><td>99.99%</td></tr>
          <tr><td>Support</td><td>Email</td><td class="hi">Priority</td><td>Dedicated CSM</td></tr>
          <tr><td>Custom DPA / BAA</td><td class="no">—</td><td class="hi">Add-on</td><td>✓</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</section>

<!-- FAQ -->
<section class="band-tight" style="background:var(--paper-2);border-top:1px solid var(--line);border-bottom:1px solid var(--line)">
  <div class="wrap">
    <div class="sec-head center reveal" style="margin:0 auto">
      <span class="eyebrow">FAQ</span>
      <h2>Pricing questions, answered.</h2>
    </div>
    <div class="faq">
      <div class="qa reveal"><button id="faq-button-1" type="button" aria-expanded="false" aria-controls="faq-panel-1">Do you mark up model tokens?<span class="ic" aria-hidden="true">+</span></button>
        <div class="ans" id="faq-panel-1" role="region" aria-labelledby="faq-button-1"><p>No. AuthClaw never marks up provider tokens. You bring your own OpenAI, Anthropic, Azure OpenAI, or Cohere keys and pay those providers directly at their rates. AuthClaw charges only for the protection layer — redaction, enforcement, remediation, and audit.</p></div></div>
      <div class="qa reveal"><button id="faq-button-2" type="button" aria-expanded="false" aria-controls="faq-panel-2">What counts as a "protected call"?<span class="ic" aria-hidden="true">+</span></button>
        <div class="ans" id="faq-panel-2" role="region" aria-labelledby="faq-button-2"><p>Any prompt or response that passes through the gateway and is inspected, redacted, or enforced. Both inbound prompts and outbound completions are counted. Health checks and blocked-before-egress requests are never double-billed.</p></div></div>
      <div class="qa reveal"><button id="faq-button-3" type="button" aria-expanded="false" aria-controls="faq-panel-3">What happens if I exceed my monthly volume?<span class="ic" aria-hidden="true">+</span></button>
        <div class="ans" id="faq-panel-3" role="region" aria-labelledby="faq-button-3"><p>Nothing breaks — protection never turns off to save money. Overage is billed in predictable bands per million protected calls, and you can set hard caps or alerts. If you consistently run over, we'll help you move to a better-fit tier or a committed-volume Enterprise agreement.</p></div></div>
      <div class="qa reveal"><button id="faq-button-4" type="button" aria-expanded="false" aria-controls="faq-panel-4">Is there a free trial?<span class="ic" aria-hidden="true">+</span></button>
        <div class="ans" id="faq-panel-4" role="region" aria-labelledby="faq-button-4"><p>Yes. Every self-serve plan starts with a 14-day free trial — no credit card required. You can put real traffic through the gateway, run a scan, and export a signed audit bundle before you pay anything.</p></div></div>
      <div class="qa reveal"><button id="faq-button-5" type="button" aria-expanded="false" aria-controls="faq-panel-5">How is Enterprise priced?<span class="ic" aria-hidden="true">+</span></button>
        <div class="ans" id="faq-panel-5" role="region" aria-labelledby="faq-button-5"><p>Enterprise is a committed-use annual agreement priced on protected volume, frameworks, deployment model, and SLA. Agreements typically start around $120k / year and scale with traffic and residency requirements. Talk to sales for a tailored quote.</p></div></div>
      <div class="qa reveal"><button id="faq-button-6" type="button" aria-expanded="false" aria-controls="faq-panel-6">Can I deploy in my own VPC or on-prem?<span class="ic" aria-hidden="true">+</span></button>
        <div class="ans" id="faq-panel-6" role="region" aria-labelledby="faq-button-6"><p>Yes, on the Enterprise plan. AuthClaw can run single-tenant inside your VPC, in a region you choose, or fully air-gapped — so request data can remain within your environment. Multi-tenant cloud is the default on Team and Growth.</p></div></div>
      <div class="qa reveal"><button id="faq-button-7" type="button" aria-expanded="false" aria-controls="faq-panel-7">Do you offer discounts for startups or multi-year deals?<span class="ic" aria-hidden="true">+</span></button>
        <div class="ans" id="faq-panel-7" role="region" aria-labelledby="faq-button-7"><p>Annual billing saves roughly 20% over monthly, and multi-year commitments unlock further discounts. Early-stage healthtech and fintech startups may qualify for our design-partner program — mention it when you book a demo.</p></div></div>
    </div>
  </div>
</section>

<!-- FINAL CTA -->
<section class="finalcta" id="demo">
  <div class="wrap">
    <span class="eyebrow" style="color:var(--gold)">Get started</span>
    <h2>See AuthClaw in your path.</h2>
    <p>Watch a live redaction, an approved remediation, and a verifiable audit export — then start a free trial the same day.</p>
    <div class="cta-row">
      <a class="btn btn-gold" href="{{trial}}">Start free trial</a>
      <a class="btn btn-light" href="{{demo}}">Book a demo</a>
    </div>
  </div>
</section>
`;

export const securityContent = `
<!-- PAGE HEADER -->
<section class="pagehead">
  <div class="wrap">
    <span class="eyebrow">Security &amp; trust</span>
    <h1>Security is not a feature here. <br>It is the product.</h1>
    <p class="sub">AuthClaw sits in the critical path of your AI traffic, so it is engineered as a zero-trust system from day one — least privilege, envelope-encrypted secrets, strict tenant isolation, and evidence that can be verified rather than trusted.</p>
    <div class="cta-row">
      <a class="btn btn-primary" href="{{trustReport}}">Request the trust report</a>
      <a class="btn btn-ghost" href="#data">How we handle data</a>
    </div>
  </div>
</section>

<!-- COMPLIANCE BADGES -->
<section class="band-tight">
  <div class="wrap">
    <div class="sec-head center reveal" style="margin:0 auto">
      <span class="eyebrow">Compliance readiness</span>
      <h2>Technical controls that support compliance readiness.</h2>
    </div>
    <div class="badges">
      <div class="cbadge reveal"><div class="ring"><span>SOC 2</span></div><h3>SOC 2 readiness</h3><p>Supporting controls</p></div>
      <div class="cbadge reveal"><div class="ring"><span>HIPAA</span></div><h3>HIPAA Security Rule</h3><p>Framework scoring</p></div>
      <div class="cbadge reveal"><div class="ring"><span>GDPR</span></div><h3>GDPR obligations</h3><p>Supporting controls</p></div>
      <div class="cbadge reveal"><div class="ring"><span>ISO</span></div><h3>ISO 42001</h3><p>Framework mapping</p></div>
    </div>
  </div>
</section>

<!-- SECURITY FEATURE GRID -->
<section class="band" style="background:var(--paper-2);border-top:1px solid var(--line);border-bottom:1px solid var(--line)">
  <div class="wrap">
    <div class="sec-head center reveal" style="margin:0 auto">
      <span class="eyebrow">Controls</span>
      <h2>Defense in depth, end to end.</h2>
      <p class="sub" style="margin-left:auto;margin-right:auto">Layered controls reduce the impact of individual component failures.</p>
    </div>
    <div class="fgrid">
      <div class="fcard reveal"><div class="ico">⛨</div><h3>Zero-trust by default</h3><p>Every service authenticates every call. No implicit trust between components, networks, or tenants.</p></div>
      <div class="fcard reveal"><div class="ico">🔑</div><h3>Envelope encryption</h3><p>Provider credentials and secrets are wrapped with AES-256-GCM via AWS KMS or HashiCorp Vault, encrypted at rest and in transit.</p></div>
      <div class="fcard reveal"><div class="ico">▦</div><h3>Strict tenant isolation</h3><p>Row-level security and, on Enterprise, physical isolation. Automated tests validate tenant-isolation boundaries.</p></div>
      <div class="fcard reveal"><div class="ico">◆</div><h3>Data minimization</h3><p>Sensitive data is redacted before egress. The least necessary context reaches any model — often nothing sensitive at all.</p></div>
      <div class="fcard reveal"><div class="ico">⌘</div><h3>Scoped, ephemeral access</h3><p>Remediation workers use short-lived, minimum-scope tokens that expire with the task. No long-lived cloud credentials.</p></div>
      <div class="fcard reveal"><div class="ico">⛭</div><h3>Tamper-evident audit</h3><p>A hash-chained, append-only log makes every action verifiable and any modification detectable.</p></div>
      <div class="fcard reveal"><div class="ico">◎</div><h3>Human-gated changes</h3><p>Consequential actions require a fresh MFA challenge bound to the specific action and approver — non-transferable, single-use.</p></div>
      <div class="fcard reveal"><div class="ico">↻</div><h3>Continuous red-teaming</h3><p>Adversarial probes for prompt injection, data disclosure, and harmful content run continuously against a vulnerability register.</p></div>
      <div class="fcard reveal"><div class="ico">◇</div><h3>Resilient by design</h3><p>Multi-region active-active with a 99.99% uptime target and regular failover and chaos testing.</p></div>
    </div>
  </div>
</section>

<!-- DATA HANDLING -->
<section class="band" id="data">
  <div class="wrap">
    <div class="sec-head reveal">
      <span class="eyebrow">Data handling</span>
      <h2>What we do with each kind of data.</h2>
      <p class="sub">Configured sensitive-data patterns can be detected and redacted before model-provider egress; retained data is minimized, encrypted, and isolated.</p>
    </div>
    <table class="dtable reveal"><caption class="sr-only">AuthClaw data handling</caption>
      <thead>
        <tr><th scope="col">Data type</th><th scope="col">How AuthClaw handles it</th><th scope="col">At rest</th></tr>
      </thead>
      <tbody>
        <tr><td>Configured PII / PHI patterns</td><td>Can be detected and masked, salt-hashed, or synthetically replaced before egress</td><td class="code">policy controlled</td></tr>
        <tr><td>Model prompts &amp; responses</td><td>Inspected in memory; only redacted metadata is retained for audit</td><td class="code">redacted only</td></tr>
        <tr><td>Provider API keys</td><td>Envelope-encrypted with per-tenant keys; decrypted only in the data plane</td><td class="code">AES-256-GCM</td></tr>
        <tr><td>Audit records</td><td>Append-only, hash-chained; integrity verifiable on export</td><td class="code">tamper-evident</td></tr>
        <tr><td>Cloud scan results</td><td>Gathered by ephemeral workers with read-only scoped tokens</td><td class="code">tenant-isolated</td></tr>
        <tr><td>User &amp; tenant config</td><td>Stored with row-level security and RBAC</td><td class="code">encrypted</td></tr>
      </tbody>
    </table>
    <div class="callout reveal">
      <span class="eyebrow">Deployment options</span>
      <p style="color:var(--slate);font-size:16px;margin-top:8px">Enterprise customers can run AuthClaw single-tenant inside their own VPC, in a chosen region, or fully air-gapped — so request data can remain within their perimeter. Multi-tenant cloud, with strict logical isolation, is the default for Team and Growth.</p>
    </div>
  </div>
</section>

<!-- RESPONSIBLE AI / SUBPROCESSORS -->
<section class="band-tight" style="background:var(--paper-2);border-top:1px solid var(--line);border-bottom:1px solid var(--line)">
  <div class="wrap grid2" style="display:grid;grid-template-columns:1fr 1fr;gap:40px">
    <div class="reveal">
      <span class="eyebrow">Responsible AI</span>
      <h3 style="font-size:24px;font-weight:600;margin-top:12px">Consequential changes require human approval.</h3>
      <p style="color:var(--slate);font-size:16px;margin-top:14px">The remediation agent can propose and explain, but it cannot make consequential changes on its own. Every destructive action is gated behind an explicit, expiring, MFA-backed human approval — and everything the agent reasons or does is written to the audit trail.</p>
    </div>
    <div class="reveal">
      <span class="eyebrow">Transparency</span>
      <h3 style="font-size:24px;font-weight:600;margin-top:12px">Subprocessors &amp; disclosure.</h3>
      <p style="color:var(--slate);font-size:16px;margin-top:14px">AuthClaw generates tamper-evident audit records and signed evidence exports.</p>
    </div>
  </div>
</section>

<!-- FINAL CTA -->
<section class="finalcta" id="demo">
  <div class="wrap">
    <span class="eyebrow" style="color:var(--gold)">Trust center</span>
    <h2>Bring us to your security review.</h2>
    <p>AuthClaw includes technical controls that support GDPR obligations and SOC 2 readiness.</p>
    <div class="cta-row">
      <a class="btn btn-gold" href="{{trustReport}}">Request the trust report</a>
      <a class="btn btn-light" href="{{contact}}">Talk to sales</a>
    </div>
  </div>
</section>
`;

export const companyContent = `
<!-- PAGE HEADER -->
<section class="pagehead">
  <div class="wrap">
    <span class="eyebrow">Company</span>
    <h1>Making AI safe to ship <br>in regulated markets.</h1>
    <p class="sub">AuthClaw exists because compliance tooling stops at describing risk. We built the layer that removes it in the path — so teams in healthcare, finance, and the public sector can adopt AI without betting the company on it.</p>
  </div>
</section>

<!-- MISSION / STATS -->
<section class="contrast band-tight">
  <div class="wrap">
    <div class="reveal">
      <span class="eyebrow" style="color:var(--violet-300)">Our mission</span>
      <h2>Every prompt governed. Every fix approved. <span class="kv">Every record provable.</span></h2>
      <p class="lead">The next decade of software runs through models. We are building the enforcement point that makes that safe by default — where configured sensitive-data patterns can be redacted, consequential remediation requires human approval, and evidence can be verified.</p>
    </div>
    <div class="stat-grid reveal">
      <div class="stat"><div class="n">2026</div><div class="l">founded, from the AgentsArchitects studio</div></div>
      <div class="stat"><div class="n">3</div><div class="l">coupled pillars: gateway, agent, audit</div></div>
      <div class="stat"><div class="n">&lt;50<span class="u">ms</span></div><div class="l">the latency budget we hold ourselves to</div></div>
      <div class="stat"><div class="n">100<span class="u">%</span></div><div class="l">human-approved consequential changes</div></div>
    </div>
  </div>
</section>

<!-- VALUES -->
<section class="band">
  <div class="wrap">
    <div class="sec-head center reveal" style="margin:0 auto">
      <span class="eyebrow">What we believe</span>
      <h2>Principles we build on.</h2>
    </div>
    <div class="vgrid">
      <div class="vcard reveal"><div class="vn">01</div><h3>In the path, not the report</h3><p>Value comes from acting on every request in real time — not from describing what already happened. We earn our place in the critical path by being fast and safe.</p></div>
      <div class="vcard reveal"><div class="vn">02</div><h3>A human always decides</h3><p>Agents propose and explain; people approve. We design for accountable autonomy, never unattended risk.</p></div>
      <div class="vcard reveal"><div class="vn">03</div><h3>Proof over promises</h3><p>Trust should be verifiable. Everything we do leaves tamper-evident evidence a customer or auditor can check themselves.</p></div>
      <div class="vcard reveal"><div class="vn">04</div><h3>Security is the product</h3><p>Zero-trust, least privilege, and encryption are not hardening we add later — they are the starting point of every design.</p></div>
      <div class="vcard reveal"><div class="vn">05</div><h3>Meet teams where they are</h3><p>Native API compatibility, your own keys, your own region. Adopting AuthClaw should never mean re-architecting your stack.</p></div>
      <div class="vcard reveal"><div class="vn">06</div><h3>Clarity for regulated buyers</h3><p>We write plainly, price transparently, and answer the security review before it is asked.</p></div>
    </div>
  </div>
</section>

<!-- STORY / TIMELINE -->
<section class="band-tight" style="background:var(--paper-2);border-top:1px solid var(--line);border-bottom:1px solid var(--line)">
  <div class="wrap">
    <div class="sec-head center reveal" style="margin:0 auto">
      <span class="eyebrow">Our story</span>
      <h2>From a delivery studio to a category.</h2>
    </div>
    <div class="timeline">
      <div class="tl reveal"><div class="yr">The origin</div><h3>Built inside AgentsArchitects.ai</h3><p>Delivering agentic systems for regulated clients, we kept hitting the same wall: teams needed controls that could detect and redact configured sensitive-data patterns before model-provider egress. So we built one.</p></div>
      <div class="tl reveal"><div class="yr">The insight</div><h3>Enforcement belongs in the request path</h3><p>Posture platforms prove yesterday; testing tools probe in a lab. Neither sits where the risk actually happens — on the live call to the model. AuthClaw does.</p></div>
      <div class="tl reveal"><div class="yr">2026</div><h3>AuthClaw becomes a product</h3><p>The gateway, the agentic remediation engine, and the continuous audit trail come together as a single in-line service and support SOC 2 readiness.</p></div>
      <div class="tl reveal"><div class="yr">Now</div><h3>Scaling with regulated teams</h3><p>Working alongside healthtech, fintech, and public-sector teams to make AI adoption safe by default.</p></div>
    </div>
  </div>
</section>

<!-- TEAM -->
<section class="band">
  <div class="wrap">
    <div class="sec-head center reveal" style="margin:0 auto">
      <span class="eyebrow">Team</span>
      <h2>Builders from compliance, security, and AI.</h2>
    </div>
    <div class="team">
      <div class="member reveal"><div class="av">BK</div><h3>Binod Kumar</h3><div class="role">Founder &amp; Chief AI Officer</div><p>Sets the product and technical direction for AuthClaw and the AgentsArchitects studio.</p></div>
      <div class="member reveal"><div class="av">◈</div><h3>Head of Gateway</h3><div class="role">Data plane &amp; latency</div><p>Owns the low-latency proxy, redaction pipeline, and streaming filter.</p></div>
      <div class="member reveal"><div class="av">⛨</div><h3>Head of Security</h3><div class="role">Zero-trust &amp; compliance</div><p>Leads the security program, audits, and customer trust.</p></div>
      <div class="member reveal"><div class="av">◎</div><h3>Head of Agent</h3><div class="role">Remediation &amp; HITL</div><p>Builds the orchestrator, scoped workers, and approval workflow.</p></div>
    </div>
    <p class="center muted" style="margin-top:26px;font-size:14.5px">A product of <b style="color:var(--navy-800)">AgentsArchitects.ai</b> — agentic systems, compliance, and delivery.</p>
  </div>
</section>

<!-- CAREERS CTA -->
<section class="finalcta">
  <div class="wrap">
    <span class="eyebrow" style="color:var(--gold)">Careers</span>
    <h2>Help us make AI safe to ship.</h2>
    <p>We're hiring across gateway engineering, security, and applied AI. If putting enforcement in the path sounds like your kind of problem, we'd like to meet you.</p>
    <div class="cta-row">
      <a class="btn btn-gold" href="{{careers}}">View open roles</a>
      <a class="btn btn-light" href="{{contact}}">Get in touch</a>
    </div>
  </div>
</section>
`;
