// Builds "Auth0 AI Sentinel.pptx" from the project README.
const path = require("path");
const pptxgen = require("pptxgenjs");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const sharp = require("sharp");
const Lu = require("react-icons/lu");
const SKILL = process.env.PPTX_SKILL;
const { applyTheme } = require(path.join(SKILL, "scripts/apply_theme.js"));

const OUT = path.resolve(__dirname, "..", "auth0-ai-sentinel.pptx");

const THEME = {
  name: "Sentinel",
  headFontFace: "Arial",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "0F1B2D", lt1: "FFFFFF", dk2: "526075", lt2: "F1F4F8",
    accent1: "EB5424", accent2: "0EA5A4", accent3: "5B5BD6",
    accent4: "E8A317", accent5: "8A94A6", accent6: "1C2B42",
    hlink: "5B5BD6", folHlink: "526075",
  },
};
const H = THEME.colors; // hex, for hex-only options

const pres = new pptxgen();
pres.layout = "LAYOUT_16x9"; // 10 x 5.625
pres.title = "Auth0 AI Sentinel";
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
const C = pres.SchemeColor;

// ---------- icons ----------
async function icon(name, hex) {
  const Comp = Lu[name];
  if (!Comp) throw new Error("missing icon " + name);
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(Comp, { color: "#" + hex, size: 256 }));
  const buf = await sharp(Buffer.from(svg)).resize(256, 256).png().toBuffer();
  return "image/png;base64," + buf.toString("base64");
}
async function iconCircle(slide, name, x, y, d, fill, fg, id) {
  slide.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { type: "none" }, objectName: id + " circle" });
  const p = d * 0.22;
  slide.addImage({ data: await icon(name, fg), x: x + p, y: y + p, w: d - 2 * p, h: d - 2 * p, altText: id, objectName: id + " icon" });
}
function txt(slide, text, opts) {
  slide.addText(text, Object.assign({ isTextBox: true, margin: 0, valign: "top", fontSize: 14, color: C.text1 }, opts));
}
function card(slide, x, y, w, h, id, fill) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.08, fill: { color: fill || C.background2 }, line: { type: "none" }, objectName: id });
}

// ---------- layouts ----------
pres.defineSlideMaster({
  title: "TITLE",
  background: { color: C.text1 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 1.55, w: 5.6, h: 1.0, align: "left", fontSize: 44, bold: true, color: C.background1, fontFace: THEME.headFontFace, valign: "bottom", margin: 0 }, text: "" } },
    { placeholder: { options: { name: "body", type: "body", align: "left", x: 0.6, y: 2.75, w: 5.4, h: 1.0, fontSize: 18, color: "CBD5E1", valign: "top", margin: 0 }, text: "" } },
  ],
});
pres.defineSlideMaster({
  title: "CONTENT",
  background: { color: C.background1 },
  margin: [0.5, 0.5, 0.5, 0.5],
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.5, y: 0.35, w: 9.0, h: 0.7, align: "left", fontSize: 28, bold: true, color: C.text1, fontFace: THEME.headFontFace, valign: "middle", margin: 0 }, text: "" } },
    { text: { text: "Auth0 AI Sentinel", options: { x: 0.5, y: 5.25, w: 4, h: 0.22, fontSize: 9, color: C.text2, margin: 0 } } },
  ],
  slideNumber: { x: 9.0, y: 5.25, w: 0.5, h: 0.22, fontSize: 9, color: H.dk2, align: "right", margin: 0 },
});
pres.defineSlideMaster({
  title: "CONTENT_DARK",
  background: { color: C.text1 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.5, y: 0.35, w: 9.0, h: 0.7, align: "left", fontSize: 28, bold: true, color: C.background1, fontFace: THEME.headFontFace, valign: "middle", margin: 0 }, text: "" } },
    { text: { text: "Auth0 AI Sentinel", options: { x: 0.5, y: 5.25, w: 4, h: 0.22, fontSize: 9, color: "94A3B8", margin: 0 } } },
  ],
  slideNumber: { x: 9.0, y: 5.25, w: 0.5, h: 0.22, fontSize: 9, color: "94A3B8", align: "right", margin: 0 },
});

let section = "";
function newSlide(master, title, notes) {
  const s = pres.addSlide({ masterName: master, sectionTitle: section });
  s.addText(title, { placeholder: "title" });
  if (notes) s.addNotes(notes);
  return s;
}
function addSection(t) { section = t; pres.addSection({ title: t }); }

(async () => {
  // ===== 1. Title =====
  addSection("Overview");
  {
    const s = pres.addSlide({ masterName: "TITLE", sectionTitle: section });
    s.addText("Auth0 AI Sentinel", { placeholder: "title" });
    s.addText("A security agent that watches your Auth0 tenant logs and flags when an AI system is calling your tenant", { placeholder: "body" });
    s.addShape(pres.shapes.OVAL, { x: 6.85, y: 1.35, w: 2.6, h: 2.6, fill: { color: C.accent6 }, line: { type: "none" }, objectName: "Halo" });
    await iconCircle(s, "LuShieldAlert", 7.35, 1.85, 1.6, C.accent1, "FFFFFF", "Shield");
    s.addNotes("Auth0 AI Sentinel watches tenant logs and flags traffic from AI systems: agents, frameworks, MCP servers, browser agents, Token Vault apps, and LLM-run code.");
  }

  // ===== 2. What it catches =====
  {
    const s = newSlide("CONTENT", "It flags six kinds of AI caller",
      "These are the caller types the detector is built to recognise. Each maps to one or more heuristic signals.");
    const items = [
      ["LuBot", "LLM agents", "Clients built on the Anthropic, OpenAI and similar SDKs"],
      ["LuWorkflow", "Agent frameworks", "LangChain and other orchestration stacks"],
      ["LuPlug", "MCP servers", "Model Context Protocol connectors and SDKs"],
      ["LuMousePointerClick", "Browser agents", "Headless browsers and computer-use agents"],
      ["LuKeyRound", "Token Vault apps", "Auth0 for AI Agents token exchanges"],
      ["LuTerminal", "Code an LLM is running", "Scripted HTTP clients calling your tenant"],
    ];
    for (let i = 0; i < items.length; i++) {
      const [ic, head, body] = items[i];
      const x = 0.5 + (i % 3) * 3.1, y = 1.4 + Math.floor(i / 3) * 1.85, w = 2.8, h = 1.6;
      card(s, x, y, w, h, "Card " + head);
      await iconCircle(s, ic, x + 0.25, y + 0.25, 0.5, C.accent1, "FFFFFF", head);
      txt(s, head, { x: x + 0.25, y: y + 0.85, w: w - 0.5, h: 0.3, fontSize: 14, bold: true });
      txt(s, body, { x: x + 0.25, y: y + 1.13, w: w - 0.5, h: 0.4, fontSize: 11, color: C.text2 });
    }
  }

  // ===== 3. Pipeline =====
  {
    const s = newSlide("CONTENT", "Every log event runs through the same pipeline",
      "Logs arrive by push (Log Stream webhook) or pull (Management API poller). The detector scores them, Claude triages the high scorers, and alerts go to stdout or Slack. Containment is optional.");
    const by = 1.75, bh = 1.5;
    txt(s, "AUTH0 TENANT LOGS", { x: 0.5, y: by - 0.35, w: 1.9, h: 0.25, fontSize: 10, bold: true, color: C.text2, charSpacing: 1 });
    // sources
    [["Log Stream webhook", "push"], ["Management API poller", "pull"]].forEach(([a, b], i) => {
      const y = by + i * 0.8;
      card(s, 0.5, y, 1.9, 0.7, "Source " + a);
      txt(s, [{ text: a, options: { bold: true, breakLine: true } }, { text: b, options: { color: C.text2, fontSize: 11 } }],
        { x: 0.62, y: y + 0.1, w: 1.7, h: 0.5, fontSize: 12, valign: "middle" });
    });
    const stages = [
      { x: 2.9, n: "1", head: "Detector", sub: "Heuristics score each event 0 to 1", file: "detector.py", fill: C.text1 },
      { x: 5.2, n: "2", head: "Claude triage", sub: "Verdict plus a short why", file: "analyst.py", fill: C.accent3 },
      { x: 7.5, n: "3", head: "Alert", sub: "JSON log, Slack", file: "sentinel.py", fill: C.accent1 },
    ];
    const arrow = (x1, x2, y) => s.addShape(pres.shapes.LINE, { x: x1, y, w: x2 - x1, h: 0, line: { color: H.accent5, width: 1.5, endArrowType: "triangle" }, objectName: "Arrow" });
    arrow(2.45, 2.85, by + bh / 2);
    for (let i = 0; i < stages.length; i++) {
      const st = stages[i], w = i === 2 ? 2.0 : 1.85;
      txt(s, "STAGE " + st.n, { x: st.x, y: by - 0.35, w, h: 0.25, fontSize: 10, bold: true, color: C.text2, charSpacing: 1 });
      s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: st.x, y: by, w, h: bh, rectRadius: 0.08, fill: { color: st.fill }, line: { type: "none" }, objectName: st.head });
      txt(s, st.head, { x: st.x + 0.15, y: by + 0.15, w: w - 0.3, h: 0.35, fontSize: 14, bold: true, color: C.background1 });
      txt(s, st.sub, { x: st.x + 0.15, y: by + 0.52, w: w - 0.3, h: 0.45, fontSize: 12, color: C.background1 });
      txt(s, st.file, { x: st.x + 0.15, y: by + 1.1, w: w - 0.3, h: 0.25, fontSize: 10, fontFace: "Courier New", color: "E2E8F0" });
      if (i < 2) arrow(st.x + w + 0.05, stages[i + 1].x - 0.05, by + bh / 2);
    }
    // containment
    s.addShape(pres.shapes.LINE, { x: 8.5, y: by + bh + 0.05, w: 0, h: 0.4, line: { color: H.accent5, width: 1.5, endArrowType: "triangle", dashType: "dash" }, objectName: "Arrow down" });
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 7.5, y: by + bh + 0.5, w: 2.0, h: 0.6, rectRadius: 0.08, fill: { color: C.background1 }, line: { color: H.accent1, width: 1.25, dashType: "dash" }, objectName: "Containment" });
    txt(s, "Optional containment", { x: 7.6, y: by + bh + 0.5, w: 1.8, h: 0.6, fontSize: 12, bold: true, color: C.accent1, align: "center", valign: "middle" });
    txt(s, "Only events at or above TRIAGE_THRESHOLD reach Claude. Everything else stops at the detector.",
      { x: 0.5, y: 4.35, w: 6.6, h: 0.5, fontSize: 12, italic: true, color: C.text2 });
  }

  // ===== 4. Heuristic weights =====
  addSection("Detection");
  {
    const s = newSlide("CONTENT", "AI client user agents carry the most weight",
      "Each signal adds weight toward a 0-to-1 score. Ranges show signals whose weight depends on the specific grant or condition.");
    const rows = [
      ["AI client user agent", "Anthropic/Python, OpenAI/Python, langchain, mcp-python-sdk", 0.75, 0.75],
      ["Headless / automated browser", "HeadlessChrome 131.0.0 / Linux", 0.6, 0.6],
      ["Delegated agent OAuth grant", "Token Vault exchange, ID-JAG, token exchange, JWT bearer, client credentials", 0.3, 0.55],
      ["Machine timing", "Steady gaps between requests", 0.45, 0.45],
      ["Burst rate / API enumeration", "20+ events a minute, or 25+ distinct /api/v2 paths", 0.4, 0.4],
      ["AI-named Auth0 application", "\"Claude MCP Connector\", \"Support AI Agent\"", 0.35, 0.35],
      ["Scripted HTTP client", "python-httpx, requests, axios, curl", 0.35, 0.35],
      ["Non-browser client", "Auth0 summary Other 0.0.0 / Other 0.0.0", 0.3, 0.3],
      ["Weaker supporting signals", "Retries after errors, limit_*, low risk confidence, Management API call", 0.15, 0.25],
    ];
    const y0 = 1.45, rh = 0.39, bx = 7.35, bw = 1.5, max = 0.8;
    txt(s, "SIGNAL", { x: 0.5, y: 1.15, w: 2.6, h: 0.22, fontSize: 9, bold: true, color: C.text2, charSpacing: 1 });
    txt(s, "EXAMPLE", { x: 3.2, y: 1.15, w: 3.9, h: 0.22, fontSize: 9, bold: true, color: C.text2, charSpacing: 1 });
    txt(s, "WEIGHT", { x: bx, y: 1.15, w: 2.1, h: 0.22, fontSize: 9, bold: true, color: C.text2, charSpacing: 1 });
    rows.forEach(([sig, ex, lo, hi], i) => {
      const y = y0 + i * rh;
      if (i % 2 === 0) s.addShape(pres.shapes.RECTANGLE, { x: 0.4, y, w: 9.2, h: rh, fill: { color: C.background2 }, line: { type: "none" }, objectName: "Row band " + (i + 1) });
      txt(s, sig, { x: 0.5, y, w: 2.65, h: rh, fontSize: 12, bold: true, valign: "middle" });
      txt(s, ex, { x: 3.2, y, w: 3.95, h: rh, fontSize: 10, color: C.text2, valign: "middle" });
      const hot = i === 0;
      if (hi > lo) s.addShape(pres.shapes.RECTANGLE, { x: bx, y: y + 0.12, w: bw * hi / max, h: rh - 0.24, fill: { color: H.accent1, transparency: 65 }, line: { type: "none" }, objectName: "Range " + sig });
      s.addShape(pres.shapes.RECTANGLE, { x: bx, y: y + 0.12, w: bw * lo / max, h: rh - 0.24, fill: { color: hot ? C.accent1 : C.text2 }, line: { type: "none" }, objectName: "Bar " + sig });
      const label = hi > lo ? lo.toFixed(2) + "–" + hi.toFixed(2) : lo.toFixed(2);
      txt(s, label, { x: bx + bw * hi / max + 0.08, y, w: 0.85, h: rh, fontSize: 10, bold: hot, color: hot ? C.accent1 : C.text1, valign: "middle" });
    });
  }

  // ===== 5. User-agent handling =====
  {
    const s = newSlide("CONTENT", "Raw user agents count; known tools barely do",
      "Auth0 normally stores a parsed user agent. Management API logs carry the raw string, which is far more revealing.");
    const cards = [
      ["LuFileSearch", "Raw beats parsed", [
        { text: "Auth0 stores a parsed agent such as ", options: {} },
        { text: "Chrome 131.0.0 / Mac OS X", options: { fontFace: "Courier New", fontSize: 11 } },
        { text: ". When a log includes the raw one in ", options: {} },
        { text: "details.request.userAgent", options: { fontFace: "Courier New", fontSize: 11 } },
        { text: ", the detector uses that instead.", options: {} },
      ]],
      ["LuBadgeCheck", "Official tools score low", [
        { text: "Official Auth0 SDKs, the Deploy CLI and the Terraform provider get a low weight, so routine tooling doesn't trip alerts.", options: {} },
      ]],
      ["LuListChecks", "Allowlist always wins", [
        { text: "Anything on ", options: {} },
        { text: "ALLOWLIST", options: { fontFace: "Courier New", fontSize: 11 } },
        { text: " is ignored entirely, whatever its score.", options: {} },
      ]],
    ];
    for (let i = 0; i < cards.length; i++) {
      const [ic, head, body] = cards[i];
      const x = 0.5 + i * 3.1, y = 1.4, w = 2.8, h = 3.3;
      card(s, x, y, w, h, "Card " + head);
      await iconCircle(s, ic, x + 0.3, y + 0.3, 0.6, C.text1, "FFFFFF", head);
      txt(s, head, { x: x + 0.3, y: y + 1.1, w: w - 0.6, h: 0.35, fontSize: 16, bold: true });
      txt(s, body, { x: x + 0.3, y: y + 1.55, w: w - 0.6, h: 1.55, fontSize: 13, color: C.text2, paraSpaceAfter: 4 });
    }
  }

  // ===== 6. Claude triage =====
  {
    const s = newSlide("CONTENT", "Claude reviews high scorers in context",
      "Model: claude-opus-5-5. Claude sees the event plus the actor's recent timeline and returns a verdict, confidence, recommended action and a short rationale.");
    // input
    card(s, 0.5, 1.4, 3.3, 2.3, "Input card");
    txt(s, "SENT TO CLAUDE", { x: 0.75, y: 1.6, w: 2.8, h: 0.22, fontSize: 9, bold: true, color: C.text2, charSpacing: 1 });
    txt(s, [
      { text: "Events at or above TRIAGE_THRESHOLD", options: { bullet: { indent: 14 }, breakLine: true } },
      { text: "The actor's recent timeline", options: { bullet: { indent: 14 }, breakLine: true } },
      { text: "Model: claude-opus-5-5", options: { bullet: { indent: 14 } } },
    ], { x: 0.75, y: 1.95, w: 2.9, h: 1.6, fontSize: 13, paraSpaceAfter: 6 });
    s.addShape(pres.shapes.LINE, { x: 3.95, y: 2.55, w: 0.5, h: 0, line: { color: H.accent5, width: 1.5, endArrowType: "triangle" }, objectName: "Arrow" });
    // output
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 4.6, y: 1.4, w: 4.9, h: 2.3, rectRadius: 0.08, fill: { color: C.accent3 }, line: { type: "none" }, objectName: "Output card" });
    txt(s, "CLAUDE RETURNS A VERDICT", { x: 4.85, y: 1.6, w: 4.4, h: 0.22, fontSize: 9, bold: true, color: "E0E0FF", charSpacing: 1 });
    const verdicts = [["ai_agent", C.accent1], ["automation", C.accent4], ["human", C.accent2], ["inconclusive", C.accent5]];
    verdicts.forEach(([v, col], i) => {
      const x = 4.85 + i * 1.12;
      s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 1.95, w: 1.04, h: 0.4, rectRadius: 0.2, fill: { color: col }, line: { type: "none" }, objectName: "Verdict " + v });
      txt(s, v, { x, y: 1.95, w: 1.04, h: 0.4, fontSize: 9, bold: true, fontFace: "Courier New", color: C.background1, align: "center", valign: "middle" });
    });
    txt(s, "plus a confidence, a recommended action and a short rationale",
      { x: 4.85, y: 2.6, w: 4.4, h: 0.8, fontSize: 14, color: C.background1 });
    // safeguards
    const guards = [
      ["LuEraser", "Secrets stay home", "Request bodies and tokens are stripped before anything is sent."],
      ["LuShieldOff", "Logs are untrusted data", "User agents and names are attacker-controlled, so fields go in as delimited data."],
    ];
    for (let i = 0; i < guards.length; i++) {
      const [ic, head, body] = guards[i];
      const x = 0.5 + i * 4.6;
      await iconCircle(s, ic, x, 4.0, 0.5, C.background2, H.dk1, head);
      txt(s, head, { x: x + 0.65, y: 3.98, w: 3.7, h: 0.28, fontSize: 13, bold: true });
      txt(s, body, { x: x + 0.65, y: 4.27, w: 3.7, h: 0.5, fontSize: 11, color: C.text2 });
    }
  }

  // ===== 7. Alert & respond =====
  addSection("Response");
  {
    const s = newSlide("CONTENT", "It only flags unless four conditions all hold",
      "By default Sentinel never acts. With AUTO_RESPONSE set to revoke_sessions or block, it contains a user only when every gate passes.");
    card(s, 0.5, 1.4, 3.6, 3.4, "Default card");
    txt(s, "DEFAULT: FLAG ONLY", { x: 0.75, y: 1.6, w: 3.1, h: 0.22, fontSize: 9, bold: true, color: C.text2, charSpacing: 1 });
    await iconCircle(s, "LuBellRing", 0.75, 1.95, 0.6, C.accent1, "FFFFFF", "Alert");
    txt(s, [
      { text: "JSON alerts to stdout", options: { bullet: { indent: 14 }, breakLine: true } },
      { text: "Slack, if SLACK_WEBHOOK_URL is set", options: { bullet: { indent: 14 }, breakLine: true } },
      { text: "No change to users or apps", options: { bullet: { indent: 14 } } },
    ], { x: 0.75, y: 2.75, w: 3.2, h: 1.8, fontSize: 14, paraSpaceAfter: 6 });

    txt(s, [
      { text: "OPT-IN CONTAINMENT  ", options: { bold: true, color: C.text2 } },
      { text: "AUTO_RESPONSE=revoke_sessions|block", options: { fontFace: "Courier New", color: C.accent1, bold: true } },
    ], { x: 4.5, y: 1.4, w: 5.0, h: 0.3, fontSize: 10 });
    const gates = [
      ["The target is a user", "never an application"],
      ["Claude's verdict is ai_agent", "not automation, human or inconclusive"],
      ["Claude recommends contain", "the recommended action must say so"],
      ["Confidence clears the bar", "at or above AUTO_RESPONSE_MIN_CONFIDENCE"],
    ];
    gates.forEach(([head, sub], i) => {
      const y = 1.85 + i * 0.75;
      s.addShape(pres.shapes.OVAL, { x: 4.5, y: y + 0.05, w: 0.5, h: 0.5, fill: { color: C.text1 }, line: { type: "none" }, objectName: "Gate " + (i + 1) });
      txt(s, String(i + 1), { x: 4.5, y: y + 0.05, w: 0.5, h: 0.5, fontSize: 16, bold: true, color: C.background1, align: "center", valign: "middle" });
      txt(s, head, { x: 5.2, y, w: 4.3, h: 0.3, fontSize: 14, bold: true });
      txt(s, sub, { x: 5.2, y: y + 0.3, w: 4.3, h: 0.3, fontSize: 11, color: C.text2 });
    });
  }

  // ===== 8. Setup =====
  addSection("Deployment");
  {
    const s = newSlide("CONTENT", "Setup takes five commands on Python 3.10+",
      "Python 3.10 or later is required because the current Anthropic SDK no longer supports 3.9. The tests are fully offline.");
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.5, y: 1.4, w: 5.6, h: 3.4, rectRadius: 0.08, fill: { color: C.text1 }, line: { type: "none" }, objectName: "Terminal" });
    ["EB5424", "E8A317", "0EA5A4"].forEach((c, i) => s.addShape(pres.shapes.OVAL, { x: 0.75 + i * 0.22, y: 1.6, w: 0.12, h: 0.12, fill: { color: c }, line: { type: "none" }, objectName: "Dot" }));
    const lines = [
      ["python3 -m venv .venv && source .venv/bin/activate", null],
      ["pip install -r requirements.txt", null],
      ["cp .env.example .env", "# fill in, then load it"],
      ["pytest -q", "# offline, no Auth0 or Claude calls"],
      ["python -m auth0_ai_sentinel replay samples/logs.json", null],
    ];
    const runs = [];
    lines.forEach(([cmd, cmt], i) => {
      runs.push({ text: "$ ", options: { color: H.accent1 } });
      runs.push({ text: cmd, options: { color: "E2E8F0", breakLine: !cmt && i < lines.length - 1 } });
      if (cmt) runs.push({ text: "  " + cmt, options: { color: "8A94A6", breakLine: i < lines.length - 1 } });
    });
    txt(s, runs, { x: 0.75, y: 1.95, w: 5.2, h: 2.7, fontSize: 11, fontFace: "Courier New", paraSpaceAfter: 14 });

    const notes = [
      ["LuPackageCheck", "Python 3.10+", "The current Anthropic SDK doesn't support 3.9"],
      ["LuFlaskConical", "Tests run offline", "No Auth0 or Claude calls during pytest"],
      ["LuHistory", "Replay sample logs", "See alerts before you connect a tenant"],
    ];
    for (let i = 0; i < notes.length; i++) {
      const [ic, head, body] = notes[i];
      const y = 1.45 + i * 1.12;
      await iconCircle(s, ic, 6.5, y, 0.55, C.background2, H.dk1, head);
      txt(s, head, { x: 7.2, y: y + 0.0, w: 2.3, h: 0.3, fontSize: 14, bold: true });
      txt(s, body, { x: 7.2, y: y + 0.3, w: 2.3, h: 0.55, fontSize: 11, color: C.text2 });
    }
  }

  // ===== 9. Credentials =====
  {
    const s = newSlide("CONTENT", "Its M2M app needs one scope to start",
      "Create a Machine to Machine application authorised for the Auth0 Management API. Grant read:logs. The three write scopes are needed only when AUTO_RESPONSE is on.");
    const steps = ["Applications", "Create Application", "Machine to Machine", "Authorize the Auth0 Management API"];
    txt(s, "IN THE AUTH0 DASHBOARD", { x: 0.5, y: 1.35, w: 9, h: 0.22, fontSize: 9, bold: true, color: C.text2, charSpacing: 1 });
    const sw = [1.6, 2.0, 2.05, 2.6];
    let x = 0.5;
    steps.forEach((st, i) => {
      card(s, x, 1.65, sw[i], 0.6, "Step " + st);
      txt(s, st, { x: x + 0.1, y: 1.65, w: sw[i] - 0.2, h: 0.6, fontSize: 12, bold: true, align: "center", valign: "middle" });
      x += sw[i];
      if (i < steps.length - 1) {
        s.addShape(pres.shapes.LINE, { x: x + 0.04, y: 1.95, w: 0.17, h: 0, line: { color: H.accent5, width: 1.25, endArrowType: "triangle" }, objectName: "Arrow" });
        x += 0.25;
      }
    });
    // scope groups
    const chip = (sc, cx, cy, w, fill, fg) => {
      s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: cx, y: cy, w, h: 0.45, rectRadius: 0.22, fill: { color: fill }, line: { type: "none" }, objectName: "Scope " + sc });
      txt(s, sc, { x: cx, y: cy, w, h: 0.45, fontSize: 12, bold: true, fontFace: "Courier New", color: fg, align: "center", valign: "middle" });
    };
    card(s, 0.5, 2.65, 3.4, 2.15, "Always card");
    txt(s, "ALWAYS", { x: 0.75, y: 2.85, w: 3, h: 0.22, fontSize: 9, bold: true, color: C.text2, charSpacing: 1 });
    chip("read:logs", 0.75, 3.2, 1.6, C.accent1, C.background1);
    txt(s, "Enough for detection and alerts", { x: 0.75, y: 3.85, w: 3, h: 0.6, fontSize: 13, color: C.text2 });

    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 4.2, y: 2.65, w: 5.3, h: 2.15, rectRadius: 0.08, fill: { color: C.background1 }, line: { color: H.accent5, width: 1, dashType: "dash" }, objectName: "Auto response card" });
    txt(s, [{ text: "ONLY WITH ", options: {} }, { text: "AUTO_RESPONSE", options: { fontFace: "Courier New" } }],
      { x: 4.45, y: 2.85, w: 4.8, h: 0.22, fontSize: 9, bold: true, color: C.text2, charSpacing: 1 });
    chip("update:users", 4.45, 3.2, 1.65, C.background2, C.text1);
    chip("delete:sessions", 6.2, 3.2, 1.75, C.background2, C.text1);
    chip("delete:refresh_tokens", 4.45, 3.75, 2.45, C.background2, C.text1);
    txt(s, "Lets it revoke sessions or block a user", { x: 4.45, y: 4.35, w: 4.8, h: 0.3, fontSize: 13, color: C.text2 });
  }

  // ===== 10. Ingest options =====
  {
    const s = newSlide("CONTENT", "Stream logs in real time, or poll the API",
      "Option A is recommended: a Custom Webhook Log Stream pushes logs as they happen. Option B polls the Management API on an interval.");
    // A
    card(s, 0.5, 1.4, 5.3, 3.45, "Option A");
    txt(s, "OPTION A", { x: 0.75, y: 1.6, w: 1.5, h: 0.22, fontSize: 9, bold: true, color: C.text2, charSpacing: 1 });
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 4.25, y: 1.55, w: 1.35, h: 0.32, rectRadius: 0.16, fill: { color: C.accent1 }, line: { type: "none" }, objectName: "Recommended badge" });
    txt(s, "Recommended", { x: 4.25, y: 1.55, w: 1.35, h: 0.32, fontSize: 10, bold: true, color: C.background1, align: "center", valign: "middle" });
    txt(s, "Real-time Log Stream", { x: 0.75, y: 1.9, w: 4.8, h: 0.35, fontSize: 16, bold: true });
    const mono = (t) => ({ text: t, options: { fontFace: "Courier New", fontSize: 10.5 } });
    txt(s, [
      { text: "Deploy ", options: { bullet: { type: "number", indent: 16 } } }, mono("serve --port 8080"), { text: " behind HTTPS", options: { breakLine: true } },
      { text: "Monitoring → Streams → Custom Webhook", options: { bullet: { type: "number", indent: 16 }, breakLine: true } },
      { text: "Payload URL ", options: { bullet: { type: "number", indent: 16 } } }, mono("https://<your-host>/auth0/logs"), { text: "", options: { breakLine: true } },
      { text: "Auth token: ", options: { bullet: { type: "number", indent: 16 } } }, mono("AUTH0_LOG_STREAM_SECRET"), { text: "", options: { breakLine: true } },
      { text: "Content type ", options: { bullet: { type: "number", indent: 16 } } }, mono("application/json"), { text: "; JSON Array, Lines or Object", options: { breakLine: true } },
      { text: "Filter: all, or at least Login, Token Exchange, Management API, Signup, Attack Protection, Errors", options: { bullet: { type: "number", indent: 16 } } },
    ], { x: 0.75, y: 2.35, w: 4.85, h: 2.4, fontSize: 12, color: C.text1, paraSpaceAfter: 3 });
    // B
    card(s, 6.1, 1.4, 3.4, 3.45, "Option B");
    txt(s, "OPTION B", { x: 6.35, y: 1.6, w: 2.9, h: 0.22, fontSize: 9, bold: true, color: C.text2, charSpacing: 1 });
    txt(s, "Poll the Management API", { x: 6.35, y: 1.9, w: 3.0, h: 0.35, fontSize: 16, bold: true });
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 6.35, y: 2.4, w: 2.9, h: 0.7, rectRadius: 0.06, fill: { color: C.text1 }, line: { type: "none" }, objectName: "Poll command" });
    txt(s, "python -m auth0_ai_sentinel poll --interval 60", { x: 6.47, y: 2.4, w: 2.7, h: 0.7, fontSize: 10, fontFace: "Courier New", color: "E2E8F0", valign: "middle" });
    txt(s, "Seeds from the latest 100 logs, then reads forward from that log_id checkpoint.",
      { x: 6.35, y: 3.3, w: 2.9, h: 1.2, fontSize: 13, color: C.text2 });
  }

  // ===== 11. Tuning =====
  addSection("Operations");
  {
    const s = newSlide("CONTENT", "Tune on your own logs before trusting the alerts",
      "Allowlist known automation, optionally run heuristics alone, and replay a real export to measure false positives before going live.");
    const rows = [
      ["LuUserCheck", "Allowlist sanctioned automation", [{ text: "Add CI deploys, SCIM and backend services to " }, { text: "ALLOWLIST", options: { fontFace: "Courier New" } }, { text: " by user_id, email or client_id." }]],
      ["LuSlidersHorizontal", "Run on heuristics alone if needed", [{ text: "CLAUDE_TRIAGE=false", options: { fontFace: "Courier New" } }, { text: " skips Claude and alerts at " }, { text: "FLAG_THRESHOLD", options: { fontFace: "Courier New" } }, { text: "." }]],
      ["LuHistory", "Measure false positives first", [{ text: "Run " }, { text: "replay", options: { fontFace: "Courier New" } }, { text: " on an export of your own tenant logs before switching anything on." }]],
    ];
    for (let i = 0; i < rows.length; i++) {
      const [ic, head, body] = rows[i];
      const y = 1.45 + i * 1.2;
      card(s, 0.5, y, 9.0, 1.0, "Row " + head);
      await iconCircle(s, ic, 0.75, y + 0.2, 0.6, C.accent1, "FFFFFF", head);
      txt(s, head, { x: 1.6, y: y + 0.17, w: 7.7, h: 0.32, fontSize: 15, bold: true });
      txt(s, body, { x: 1.6, y: y + 0.52, w: 7.7, h: 0.35, fontSize: 13, color: C.text2 });
    }
  }

  // ===== 12. Limits =====
  {
    const s = newSlide("CONTENT_DARK", "Detection covers only what Auth0 logs",
      "Four known limits: what Auth0 logs, missing network data, spoofable user agents, and per-process state.");
    const lims = [
      ["LuEyeOff", "Some calls are never logged", "Logins, token exchanges, signups and Management API writes are logged. Read-only Management API calls and calls to your own APIs are not."],
      ["LuGlobe", "No network data", "Auth0 logs carry no ASN or ISP, so cloud-hosted sources can't be flagged by network. Enrich ip with a GeoIP/ASN database."],
      ["LuVenetianMask", "User agents can be spoofed", "A careful agent in a real browser is caught only by its behavior and by Claude's review of its timeline."],
      ["LuDatabase", "State lives in one process", "Detector history is in memory per process. Run a single instance, or move history to Redis."],
    ];
    for (let i = 0; i < lims.length; i++) {
      const [ic, head, body] = lims[i];
      const x = 0.5 + (i % 2) * 4.6, y = 1.35 + Math.floor(i / 2) * 1.9, w = 4.4, h = 1.7;
      card(s, x, y, w, h, "Limit " + head, C.accent6);
      await iconCircle(s, ic, x + 0.25, y + 0.25, 0.5, C.accent1, "FFFFFF", head);
      txt(s, head, { x: x + 0.9, y: y + 0.3, w: w - 1.15, h: 0.4, fontSize: 15, bold: true, color: C.background1, valign: "middle" });
      txt(s, body, { x: x + 0.25, y: y + 0.88, w: w - 0.5, h: 0.75, fontSize: 11.5, color: "CBD5E1" });
    }
  }

  await pres.writeFile({ fileName: OUT });
  await applyTheme(OUT, THEME);
  console.log("wrote", OUT);
})().catch((e) => { console.error(e); process.exit(1); });
