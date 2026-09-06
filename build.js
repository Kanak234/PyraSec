// PyraSec — HackLabify V1.0 pitch deck (Team CipherStack)
const pptxgen = require("pptxgenjs");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const sharp = require("sharp");
const fa = require("react-icons/fa");

// ---------- palette ----------
const BG = "0B132B";        // deep midnight
const PANEL = "141E3C";     // card fill
const PANEL_LINE = "263457";// card border
const TEAL = "5BC0BE";
const MINT = "6FFFE9";
const RED = "EF476F";
const AMBER = "FFD166";
const GREEN = "06D6A0";
const WHITE = "FFFFFF";
const MUTED = "9FB0CB";
const DIM = "44536F";
const FONT = "Arial";

const W = 13.33, H = 7.5;

// ---------- icon helper ----------
async function iconPng(name, hex) {
  const el = React.createElement(fa[name], { size: 256 });
  let svg = ReactDOMServer.renderToStaticMarkup(el);
  svg = svg.replace(/currentColor/g, "#" + hex);
  if (!svg.includes("xmlns")) svg = svg.replace("<svg ", '<svg xmlns="http://www.w3.org/2000/svg" ');
  const buf = await sharp(Buffer.from(svg)).resize(256, 256).png().toBuffer();
  return "image/png;base64," + buf.toString("base64");
}

const shadow = () => ({ type: "outer", color: "000000", opacity: 0.45, blur: 8, offset: 3, angle: 90 });
const softShadow = () => ({ type: "outer", color: "000000", opacity: 0.3, blur: 10, offset: 2, angle: 90 });

function kickerAndTitle(slide, kicker, title) {
  slide.addShape("triangle", { x: 0.85, y: 0.6, w: 0.16, h: 0.14, fill: { color: TEAL } });
  slide.addText(kicker, { x: 1.08, y: 0.47, w: 8, h: 0.4, fontFace: FONT, fontSize: 11, bold: true, color: MINT, charSpacing: 3, margin: 0 });
  slide.addText(title, { x: 0.83, y: 0.88, w: 11.7, h: 0.7, fontFace: FONT, fontSize: 30, bold: true, color: WHITE, margin: 0 });
}

function footer(slide, n) {
  slide.addText("PyraSec — Team CipherStack", { x: 0.85, y: 7.02, w: 3.5, h: 0.3, fontFace: FONT, fontSize: 9, color: DIM, margin: 0 });
  slide.addText(`0${n} / 09`, { x: 11.6, y: 7.02, w: 0.9, h: 0.3, fontFace: FONT, fontSize: 9, color: DIM, align: "right", margin: 0 });
}

function pyramid(slide, cx, baseY, scale, withShadow = true) {
  // 3-layer pyramid centered at cx; baseY = bottom edge of base layer
  const bw = 3.6 * scale, bh = 1.02 * scale;   // base trapezoid
  const mw = 2.7 * scale, mh = 0.95 * scale;   // middle trapezoid
  const tw = 1.8 * scale, th = 1.28 * scale;   // top triangle
  const gap = 0.1 * scale;
  const sh1 = withShadow ? { shadow: shadow() } : {};
  slide.addShape("trapezoid", { x: cx - bw / 2, y: baseY - bh, w: bw, h: bh, fill: { color: GREEN }, ...(withShadow ? { shadow: shadow() } : {}) });
  slide.addShape("trapezoid", { x: cx - mw / 2, y: baseY - bh - gap - mh, w: mw, h: mh, fill: { color: AMBER }, ...(withShadow ? { shadow: shadow() } : {}) });
  slide.addShape("triangle", { x: cx - tw / 2, y: baseY - bh - gap - mh - gap - th, w: tw, h: th, fill: { color: RED }, ...(withShadow ? { shadow: shadow() } : {}) });
}

function deco(slide, spots) {
  spots.forEach(([x, y, w]) => {
    slide.addShape("triangle", { x, y, w, h: w * 0.82, fill: { color: "0B132B", transparency: 100 }, line: { color: "22335C", width: 1 } });
  });
}

(async () => {
  // ---------- pre-render icons ----------
  const I = {};
  const need = [
    ["FaEyeSlash", WHITE], ["FaHourglassHalf", WHITE], ["FaUserGraduate", WHITE],
    ["FaExclamationTriangle", AMBER], ["FaCube", WHITE], ["FaBrain", WHITE],
    ["FaTachometerAlt", WHITE], ["FaSearch", WHITE], ["FaCrosshairs", WHITE],
    ["FaWrench", WHITE], ["FaFileCode", WHITE], ["FaKey", WHITE],
    ["FaLockOpen", WHITE], ["FaFolderOpen", WHITE], ["FaHistory", WHITE],
    ["FaGitAlt", WHITE], ["FaReact", WHITE], ["FaPython", WHITE],
    ["FaUsers", WHITE], ["FaChalkboardTeacher", WHITE], ["FaRocket", WHITE],
    ["FaFlag", WHITE], ["FaGithub", WHITE], ["FaPuzzlePiece", WHITE],
    ["FaShieldAlt", "0B132B"],
  ];
  for (const [n, c] of need) I[`${n}_${c}`] = await iconPng(n, c);
  const ic = (n, c = WHITE) => I[`${n}_${c}`];

  const pptx = new pptxgen();
  pptx.layout = "LAYOUT_WIDE";

  // ============ SLIDE 1 — TITLE ============
  {
    const s = pptx.addSlide();
    s.background = { color: BG };
    deco(s, [[0.5, 6.3, 0.55], [12.35, 0.55, 0.5], [7.1, 6.75, 0.35]]);

    s.addText("TEAM CIPHERSTACK  ×  HACKLABIFY V1.0", { x: 0.9, y: 1.35, w: 7, h: 0.4, fontFace: FONT, fontSize: 12, bold: true, color: MINT, charSpacing: 3, margin: 0 });
    s.addText([
      { text: "Pyra", options: { color: WHITE } },
      { text: "Sec", options: { color: MINT } },
    ], { x: 0.83, y: 1.75, w: 7, h: 1.3, fontFace: FONT, fontSize: 66, bold: true, margin: 0 });
    s.addText("Visualize. Detect. Secure.", { x: 0.9, y: 3.15, w: 6.5, h: 0.5, fontFace: FONT, fontSize: 24, italic: true, color: TEAL, margin: 0 });
    s.addText("An AI-powered tool that turns your project's file architecture into a color-coded 3D pyramid — and tells you exactly how to harden it.", { x: 0.9, y: 3.85, w: 6.3, h: 1.1, fontFace: FONT, fontSize: 15, color: MUTED, lineSpacing: 22, margin: 0 });
    s.addText("Security Track  ·  Master's Union, Gurugram  ·  1–2 Aug 2026", { x: 0.9, y: 6.55, w: 7, h: 0.4, fontFace: FONT, fontSize: 12, color: DIM, margin: 0 });

    pyramid(s, 10.35, 6.05, 1.25);
    // legend under pyramid
    const leg = [["CRITICAL", RED], ["WARNING", AMBER], ["SECURE", GREEN]];
    let lx = 8.55;
    leg.forEach(([t, c]) => {
      s.addShape("ellipse", { x: lx, y: 6.42, w: 0.14, h: 0.14, fill: { color: c } });
      s.addText(t, { x: lx + 0.2, y: 6.3, w: 1.1, h: 0.36, fontFace: FONT, fontSize: 9.5, bold: true, color: MUTED, charSpacing: 1, margin: 0 });
      lx += 1.28;
    });
    s.addNotes("PyraSec by Team CipherStack — AI-powered 3D file architecture security analyzer. Built for the Security track at HackLabify V1.0.");
  }

  // ============ SLIDE 2 — PROBLEM ============
  {
    const s = pptx.addSlide();
    s.background = { color: BG };
    kickerAndTitle(s, "THE PROBLEM", "Security risks hide in plain sight");

    s.addText("A modern project spans hundreds of files. One exposed .env, one hardcoded key, or one world-writable folder is all it takes for a breach — yet none of this shows up in a code review.\n\nStructure and permissions stay invisible until an attacker finds them first.", { x: 0.85, y: 1.95, w: 5.35, h: 2.7, fontFace: FONT, fontSize: 15, color: WHITE, lineSpacing: 23, valign: "top", margin: 0 });

    // OWASP callout
    s.addShape("roundRect", { x: 0.85, y: 5.0, w: 5.35, h: 1.45, rectRadius: 0.1, fill: { color: PANEL }, line: { color: PANEL_LINE, width: 1 }, shadow: softShadow() });
    s.addImage({ data: ic("FaExclamationTriangle", AMBER), x: 1.15, y: 5.5, w: 0.42, h: 0.42 });
    s.addText("OWASP Top 10 (A05:2021) lists Security Misconfiguration among the most common web application risks.", { x: 1.8, y: 5.2, w: 4.2, h: 1.05, fontFace: FONT, fontSize: 12.5, italic: true, color: MUTED, lineSpacing: 17, valign: "middle", margin: 0 });

    // right cards
    const cards = [
      ["FaEyeSlash", RED, "Invisible risk", "Misplaced files and loose permissions never show up in diffs."],
      ["FaHourglassHalf", AMBER, "Slow manual audits", "Checking structure and permissions by hand doesn't scale."],
      ["FaUserGraduate", TEAL, "Steep learning curve", "Beginners ship secrets without ever knowing the rules."],
    ];
    let cy = 1.95;
    cards.forEach(([icn, col, t, d]) => {
      s.addShape("roundRect", { x: 6.75, y: cy, w: 5.7, h: 1.45, rectRadius: 0.1, fill: { color: PANEL }, line: { color: PANEL_LINE, width: 1 }, shadow: softShadow() });
      s.addShape("ellipse", { x: 7.05, y: cy + 0.42, w: 0.62, h: 0.62, fill: { color: col } });
      s.addImage({ data: ic(icn), x: 7.2, y: cy + 0.57, w: 0.32, h: 0.32 });
      s.addText(t, { x: 7.9, y: cy + 0.24, w: 4.4, h: 0.4, fontFace: FONT, fontSize: 15, bold: true, color: WHITE, margin: 0 });
      s.addText(d, { x: 7.9, y: cy + 0.66, w: 4.4, h: 0.68, fontFace: FONT, fontSize: 11.5, color: MUTED, lineSpacing: 15, valign: "top", margin: 0 });
      cy += 1.68;
    });
    footer(s, 2);
    s.addNotes("Pain point: file-structure risks are invisible in normal workflows. Anchor with OWASP A05 Security Misconfiguration.");
  }

  // ============ SLIDE 3 — SOLUTION ============
  {
    const s = pptx.addSlide();
    s.background = { color: BG };
    kickerAndTitle(s, "OUR SOLUTION", "Your architecture as a living 3D pyramid");

    pyramid(s, 2.95, 5.5, 1.0);
    s.addText("Folders become layers · files become blocks", { x: 0.9, y: 5.72, w: 4.1, h: 0.35, fontFace: FONT, fontSize: 11.5, italic: true, color: MUTED, align: "center", margin: 0 });
    // legend row
    const leg = [["Critical", RED], ["Warning", AMBER], ["Secure", GREEN]];
    let lx = 1.15;
    leg.forEach(([t, c]) => {
      s.addShape("ellipse", { x: lx, y: 6.28, w: 0.15, h: 0.15, fill: { color: c } });
      s.addText(t, { x: lx + 0.21, y: 6.15, w: 1.0, h: 0.4, fontFace: FONT, fontSize: 11, color: MUTED, margin: 0 });
      lx += 1.25;
    });

    s.addText("See your whole security posture at a single glance.", { x: 6.6, y: 1.9, w: 5.85, h: 0.6, fontFace: FONT, fontSize: 17, italic: true, color: MINT, margin: 0 });

    const rows = [
      ["FaCube", "Interactive 3D view", "Rotate, hover and click any block to inspect the file behind it."],
      ["FaBrain", "AI explanations", "Every finding described in plain language — what, why, and how bad."],
      ["FaTachometerAlt", "Security score", "One 0–100 number for the project, recalculated after every fix."],
    ];
    let ry = 2.8;
    rows.forEach(([icn, t, d]) => {
      s.addShape("ellipse", { x: 6.65, y: ry, w: 0.6, h: 0.6, fill: { color: "1C2A50" }, line: { color: TEAL, width: 1.25 } });
      s.addImage({ data: ic(icn), x: 6.8, y: ry + 0.15, w: 0.3, h: 0.3 });
      s.addText(t, { x: 7.45, y: ry - 0.04, w: 5.0, h: 0.4, fontFace: FONT, fontSize: 15.5, bold: true, color: WHITE, margin: 0 });
      s.addText(d, { x: 7.45, y: ry + 0.36, w: 5.0, h: 0.65, fontFace: FONT, fontSize: 11.5, color: MUTED, lineSpacing: 15, valign: "top", margin: 0 });
      ry += 1.35;
    });
    footer(s, 3);
    s.addNotes("Core idea: make security posture visual. Pyramid = whole project; colors = risk level; AI explains and scores.");
  }

  // ============ SLIDE 4 — HOW IT WORKS ============
  {
    const s = pptx.addSlide();
    s.background = { color: BG };
    kickerAndTitle(s, "HOW IT WORKS", "From folder to fortress in four steps");

    const steps = [
      ["01", "FaSearch", "Scan", "A directory walker maps every file, folder and permission."],
      ["02", "FaCrosshairs", "Detect", "Rule engine + AI flag exposed secrets and weak spots."],
      ["03", "FaCube", "Visualize", "Three.js renders the color-coded pyramid in the browser."],
      ["04", "FaWrench", "Fix", "AI suggests exact fixes and re-scores the project."],
    ];
    const xs = [0.85, 3.9, 6.95, 10.0];
    steps.forEach(([num, icn, t, d], i) => {
      const x = xs[i];
      s.addShape("roundRect", { x, w: 2.5, y: 2.2, h: 3.5, rectRadius: 0.12, fill: { color: PANEL }, line: { color: PANEL_LINE, width: 1 }, shadow: softShadow() });
      s.addText(num, { x: x + 0.25, y: 2.42, w: 1, h: 0.4, fontFace: FONT, fontSize: 13, bold: true, color: MINT, margin: 0 });
      s.addShape("ellipse", { x: x + 0.88, y: 2.95, w: 0.74, h: 0.74, fill: { color: "1C2A50" }, line: { color: TEAL, width: 1.25 } });
      s.addImage({ data: ic(icn), x: x + 1.06, y: 3.13, w: 0.38, h: 0.38 });
      s.addText(t, { x, y: 3.95, w: 2.5, h: 0.45, fontFace: FONT, fontSize: 17, bold: true, color: WHITE, align: "center", margin: 0 });
      s.addText(d, { x: x + 0.22, y: 4.45, w: 2.06, h: 1.1, fontFace: FONT, fontSize: 11.5, color: MUTED, align: "center", lineSpacing: 15, valign: "top", margin: 0 });
      if (i < 3) s.addShape("chevron", { x: x + 2.58, y: 3.72, w: 0.28, h: 0.46, fill: { color: TEAL, transparency: 25 } });
    });
    s.addText("Re-scan after every fix — and watch the pyramid turn green.", { x: 0.85, y: 6.15, w: 11.63, h: 0.4, fontFace: FONT, fontSize: 13, italic: true, color: TEAL, align: "center", margin: 0 });
    footer(s, 4);
    s.addNotes("Pipeline: scan → detect → visualize → fix. Emphasize the feedback loop: re-scan turns the pyramid green.");
  }

  // ============ SLIDE 5 — WHAT WE DETECT ============
  {
    const s = pptx.addSlide();
    s.background = { color: BG };
    kickerAndTitle(s, "DETECTION ENGINE", "What PyraSec catches");

    const cards = [
      ["FaFileCode", RED, "Exposed configs", ".env and config files reachable from public folders."],
      ["FaKey", RED, "Hardcoded secrets", "API keys and passwords sitting inside source code."],
      ["FaLockOpen", AMBER, "Weak permissions", "World-writable files and over-permissive folders."],
      ["FaFolderOpen", AMBER, "Risky placement", "Sensitive files stored in public or static directories."],
      ["FaHistory", AMBER, "Leftover files", ".bak, .old and dump files attackers love to find."],
      ["FaGitAlt", RED, "Git exposure", "Secrets missing from .gitignore, about to be committed."],
    ];
    const cw = 3.7, ch = 2.15, gx = 0.265, gy = 0.25;
    cards.forEach(([icn, sev, t, d], i) => {
      const col = i % 3, row = Math.floor(i / 3);
      const x = 0.85 + col * (cw + gx), y = 1.9 + row * (ch + gy);
      s.addShape("roundRect", { x, y, w: cw, h: ch, rectRadius: 0.1, fill: { color: PANEL }, line: { color: PANEL_LINE, width: 1 }, shadow: softShadow() });
      s.addShape("ellipse", { x: x + 0.28, y: y + 0.28, w: 0.6, h: 0.6, fill: { color: "1C2A50" }, line: { color: TEAL, width: 1.25 } });
      s.addImage({ data: ic(icn), x: x + 0.43, y: y + 0.43, w: 0.3, h: 0.3 });
      s.addShape("ellipse", { x: x + cw - 0.42, y: y + 0.26, w: 0.16, h: 0.16, fill: { color: sev } });
      s.addText(t, { x: x + 0.28, y: y + 1.02, w: cw - 0.56, h: 0.4, fontFace: FONT, fontSize: 14.5, bold: true, color: WHITE, margin: 0 });
      s.addText(d, { x: x + 0.28, y: y + 1.42, w: cw - 0.56, h: 0.62, fontFace: FONT, fontSize: 11, color: MUTED, lineSpacing: 14.5, valign: "top", margin: 0 });
    });
    footer(s, 5);
    s.addNotes("Six concrete detection categories. Dots show default severity: red = critical, amber = warning.");
  }

  // ============ SLIDE 6 — TECH STACK ============
  {
    const s = pptx.addSlide();
    s.background = { color: BG };
    kickerAndTitle(s, "UNDER THE HOOD", "Three layers, one pipeline");

    const cols = [
      ["FaReact", "Frontend", "React + Three.js", "Interactive 3D pyramid — rotate, hover, click any block."],
      ["FaPython", "Scan engine", "Python", "Walks the file tree, reads permissions, applies security rules."],
      ["FaBrain", "AI layer", "LLM API", "Explains each risk, scores the project, generates fixes."],
    ];
    const cw = 3.7, gx = 0.265;
    cols.forEach(([icn, role, tech, d], i) => {
      const x = 0.85 + i * (cw + gx), y = 1.95, h = 3.85;
      s.addShape("roundRect", { x, y, w: cw, h, rectRadius: 0.12, fill: { color: PANEL }, line: { color: PANEL_LINE, width: 1 }, shadow: softShadow() });
      s.addShape("ellipse", { x: x + cw / 2 - 0.45, y: y + 0.4, w: 0.9, h: 0.9, fill: { color: "1C2A50" }, line: { color: TEAL, width: 1.5 } });
      s.addImage({ data: ic(icn), x: x + cw / 2 - 0.24, y: y + 0.61, w: 0.48, h: 0.48 });
      s.addText(role, { x, y: y + 1.5, w: cw, h: 0.45, fontFace: FONT, fontSize: 16.5, bold: true, color: WHITE, align: "center", margin: 0 });
      s.addText(tech, { x, y: y + 1.98, w: cw, h: 0.4, fontFace: FONT, fontSize: 13, bold: true, color: MINT, align: "center", margin: 0 });
      s.addText(d, { x: x + 0.35, y: y + 2.5, w: cw - 0.7, h: 1.1, fontFace: FONT, fontSize: 11.5, color: MUTED, align: "center", lineSpacing: 15.5, valign: "top", margin: 0 });
    });

    const chips = ["React", "Three.js", "Python", "FastAPI", "LLM API"];
    let chx = (W - (chips.length * 1.55 + (chips.length - 1) * 0.2)) / 2;
    chips.forEach((c) => {
      s.addShape("roundRect", { x: chx, y: 6.15, w: 1.55, h: 0.42, rectRadius: 0.21, fill: { color: "1C2A50" }, line: { color: TEAL, width: 1 } });
      s.addText(c, { x: chx, y: 6.15, w: 1.55, h: 0.42, fontFace: FONT, fontSize: 11, color: WHITE, align: "center", valign: "middle", margin: 0 });
      chx += 1.75;
    });
    footer(s, 6);
    s.addNotes("Stack: React + Three.js frontend, Python scan engine, LLM API for explanations and scoring. FastAPI glues it together.");
  }

  // ============ SLIDE 7 — IMPACT ============
  {
    const s = pptx.addSlide();
    s.background = { color: BG };
    kickerAndTitle(s, "WHY IT MATTERS", "Built for everyone who ships code");

    const cards = [
      ["FaUserGraduate", "Students", "Learn security by seeing it — not by memorizing checklists."],
      ["FaUsers", "Dev teams", "A one-look audit before every deployment."],
      ["FaChalkboardTeacher", "Educators", "A visual teaching aid for secure-by-design thinking."],
      ["FaRocket", "Startups & hackathons", "Ship fast without shipping your secrets."],
    ];
    const cw = 5.7, ch = 2.0, gx = 0.23, gy = 0.3;
    cards.forEach(([icn, t, d], i) => {
      const col = i % 2, row = Math.floor(i / 2);
      const x = 0.85 + col * (cw + gx), y = 2.1 + row * (ch + gy);
      s.addShape("roundRect", { x, y, w: cw, h: ch, rectRadius: 0.12, fill: { color: PANEL }, line: { color: PANEL_LINE, width: 1 }, shadow: softShadow() });
      s.addShape("ellipse", { x: x + 0.35, y: y + 0.62, w: 0.76, h: 0.76, fill: { color: "1C2A50" }, line: { color: TEAL, width: 1.25 } });
      s.addImage({ data: ic(icn), x: x + 0.54, y: y + 0.81, w: 0.38, h: 0.38 });
      s.addText(t, { x: x + 1.35, y: y + 0.45, w: cw - 1.65, h: 0.45, fontFace: FONT, fontSize: 15.5, bold: true, color: WHITE, margin: 0 });
      s.addText(d, { x: x + 1.35, y: y + 0.92, w: cw - 1.65, h: 0.75, fontFace: FONT, fontSize: 11.5, color: MUTED, lineSpacing: 15.5, valign: "top", margin: 0 });
    });
    footer(s, 7);
    s.addNotes("Audience fit: students, teams, educators, startups. Security becomes visual and beginner-friendly.");
  }

  // ============ SLIDE 8 — ROADMAP ============
  {
    const s = pptx.addSlide();
    s.background = { color: BG };
    kickerAndTitle(s, "ROADMAP", "Where PyraSec goes next");

    s.addShape("line", { x: 1.3, y: 3.05, w: 10.75, h: 0, line: { color: "2A3A5E", width: 2.5 } });
    const stops = [
      [2.62, "V1.0", "FaFlag", "Hackathon MVP", "Scanner, 3D pyramid, AI score — built in 2 days."],
      [6.67, "V2.0", "FaGithub", "GitHub & CI/CD", "Scan any repo; block risky merges automatically."],
      [10.72, "V3.0", "FaPuzzlePiece", "IDE & teams", "VS Code extension, team dashboards, compliance reports."],
    ];
    stops.forEach(([cx, v, icn, t, d]) => {
      s.addShape("ellipse", { x: cx - 0.11, y: 2.94, w: 0.22, h: 0.22, fill: { color: MINT } });
      s.addText(v, { x: cx - 0.75, y: 2.3, w: 1.5, h: 0.45, fontFace: FONT, fontSize: 15, bold: true, color: MINT, align: "center", margin: 0 });
      const x = cx - 1.7, y = 3.55;
      s.addShape("roundRect", { x, y, w: 3.4, h: 2.35, rectRadius: 0.12, fill: { color: PANEL }, line: { color: PANEL_LINE, width: 1 }, shadow: softShadow() });
      s.addShape("ellipse", { x: x + 0.3, y: y + 0.3, w: 0.6, h: 0.6, fill: { color: "1C2A50" }, line: { color: TEAL, width: 1.25 } });
      s.addImage({ data: ic(icn), x: x + 0.45, y: y + 0.45, w: 0.3, h: 0.3 });
      s.addText(t, { x: x + 0.3, y: y + 1.02, w: 2.8, h: 0.4, fontFace: FONT, fontSize: 15, bold: true, color: WHITE, margin: 0 });
      s.addText(d, { x: x + 0.3, y: y + 1.44, w: 2.8, h: 0.8, fontFace: FONT, fontSize: 11.5, color: MUTED, lineSpacing: 15, valign: "top", margin: 0 });
    });
    footer(s, 8);
    s.addNotes("Roadmap: MVP this weekend → GitHub/CI-CD integration → IDE extension and team features.");
  }

  // ============ SLIDE 9 — CLOSE ============
  {
    const s = pptx.addSlide();
    s.background = { color: BG };
    deco(s, [[0.6, 0.6, 0.5], [12.3, 6.35, 0.55], [1.1, 6.6, 0.32]]);

    s.addShape("ellipse", { x: W / 2 - 0.5, y: 1.35, w: 1.0, h: 1.0, fill: { color: MINT }, shadow: shadow() });
    s.addImage({ data: ic("FaShieldAlt", "0B132B"), x: W / 2 - 0.27, y: 1.61, w: 0.54, h: 0.54 });
    s.addText("Let's make security visible.", { x: 1, y: 2.75, w: 11.33, h: 0.8, fontFace: FONT, fontSize: 38, bold: true, color: WHITE, align: "center", margin: 0 });
    s.addText("PyraSec — built by Team CipherStack", { x: 1, y: 3.75, w: 11.33, h: 0.5, fontFace: FONT, fontSize: 16, color: TEAL, align: "center", margin: 0 });
    s.addText("HackLabify V1.0  ·  Security Track  ·  Master's Union, Gurugram  ·  1–2 Aug 2026", { x: 1, y: 4.45, w: 11.33, h: 0.4, fontFace: FONT, fontSize: 12, color: MUTED, align: "center", margin: 0 });
    s.addText("github.com/Kanak234", { x: 1, y: 5.15, w: 11.33, h: 0.4, fontFace: FONT, fontSize: 12, bold: true, color: MINT, align: "center", margin: 0 });
    s.addNotes("Close with the mission line. Q&A. Demo available on request.");
  }

  await pptx.writeFile({ fileName: "/home/claude/pyrasec/PyraSec_HackLabify_Pitch.pptx" });
  console.log("deck written");
})().catch((e) => { console.error(e); process.exit(1); });
