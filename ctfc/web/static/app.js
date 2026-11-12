// ctfc web UI. Plain JavaScript, no framework, no build step.
//
// Flow: the user pastes text or drops a file -> clicks Run (or Ctrl+Enter)
// -> we POST the input to /api/<tab> -> we draw the JSON answer as cards.
//
// Safety: data from samples is only ever inserted with textContent, never innerHTML,
// so a malicious sample cannot inject HTML/JS into this page.

"use strict";

// ---------------------------------------------------------------- state
const state = {
  strings: {},      // UI labels from /api/strings
  tab: "auto",      // active tab
  file: null,       // {name, b64, size} when a file was dropped (the first one)
  files: [],        // every dropped file: Workspace and Timeline read them all
  job: null,        // id of the background job currently running
  session: "",      // the session runs are recorded in ("" = not recording)
  // Volatility tab: the cheat sheet data, and how the user wants it shown.
  vol: { data: null, engine: "vol3", os: "all" },
};

// Tabs that are built, and how they run: "sync" waits for the answer,
// "job" runs in the background with progress and a Cancel button.
const TOOLS = {
  auto: "job",
  solve: "job",
  detect: "sync",
  xor: "job",
  sym: "job",
  lens: "sync",
  rsa: "job",
  hash: "sync",
  pipeline: "sync",
  keys: "job",
  radius: "sync",
  jwt: "sync",
  prng: "sync",
  extend: "sync",
  file: "sync",
  timeline: "job",
  workspace: "job",
  crc: "sync",
  classical: "job",
  sig: "sync",
};

// API route of a tab, when it is not /api/<tab>.
const API_PATH = { pipeline: "/api/recipe" };

// Tabs that have their own options panel (#options-<tab>).
const OPTION_PANELS = [
  "xor", "sym", "rsa", "hash", "pipeline", "keys", "lens", "radius", "volatility", "jwt", "prng", "extend",
  "file", "classical", "crc", "sig", "docs", "solve", "timeline", "workspace",
];

// Tabs that are reference pages, not tools: opening them shows the page and
// there is nothing to Run.
const REFERENCE_TABS = ["cheatsheet", "volatility", "docs"];

// Tabs after which the "Suggested tools" strip is computed (data tabs, not scripts).
const SUGGEST_TABS = ["auto", "detect", "xor", "sym", "hash", "file"];

// "Add a step" buttons of the Pipeline tab. `args` is a template the user edits;
// `ask` prompts for one argument (the XOR key) before adding the step, with the
// question `prompt` (default: the string "web_pipeline_ask_<ask>").
const PIPELINE_STEPS = [
  { op: "base64" },
  { op: "hex" },
  { op: "base32" },
  { op: "base58" },
  { op: "base85" },
  { op: "url" },
  { op: "html" },
  { op: "zlib" },
  { op: "gzip" },
  { op: "deflate" },
  { op: "bz2" },
  { op: "lzma" },
  { op: "reverse" },
  { op: "rot13" },
  { op: "rot47" },
  { op: "xor", ask: "key" },
  { op: "caesar", ask: "shift" },
  { op: "vigenere", ask: "key", prompt: "web_pipeline_ask_key_vigenere" },
  { op: "atbash" },
  { op: "affine", args: { a: 5, b: 8 } },
  { op: "railfence", args: { rails: 3, offset: 0 } },
  {
    op: "cipher",
    args: { cipher: "aes", mode: "cbc", key: "<hex key>", iv: "<hex iv>", unpad: "pkcs7" },
  },
];

const $ = (id) => document.getElementById(id);

// Translate a key using the strings sent by the server (ctfc/strings.py).
function T(key, params) {
  let text = state.strings[key] || key;
  for (const [name, value] of Object.entries(params || {})) {
    text = text.replace("{" + name + "}", value);
  }
  return text;
}

// Create an element with a class and text content.
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// ---------------------------------------------------------------- bytes helpers
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

// Classic hexdump: offset, 16 hex bytes, ASCII column.
function hexdump(bytes, limit) {
  const lines = [];
  const end = Math.min(bytes.length, limit);
  for (let offset = 0; offset < end; offset += 16) {
    const chunk = bytes.subarray(offset, Math.min(offset + 16, end));
    const hex = Array.from(chunk, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(chunk, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    lines.push(offset.toString(16).padStart(8, "0") + "  " + hex.padEnd(47) + "  " + ascii);
  }
  if (bytes.length > limit) lines.push("... (" + (bytes.length - limit) + " more bytes)");
  return lines.join("\n");
}

// True if the text is mostly readable characters.
function isReadable(text) {
  if (!text.length) return false;
  let good = 0;
  for (const ch of text) {
    if (ch === "\n" || ch === "\t" || ch === "\r" || (ch >= " " && ch !== "�" && ch !== "\x7f")) good++;
  }
  return good / text.length >= 0.85;
}

// ---------------------------------------------------------------- server calls
// Tabs that take every dropped file, not only the first.
const MULTI_FILE_TABS = ["workspace", "timeline"];

function currentPayload() {
  if (state.files.length > 1 && MULTI_FILE_TABS.includes(state.tab)) {
    return { files: state.files.map((f) => ({ name: f.name, data_b64: f.b64 })) };
  }
  if (state.file) return { data_b64: state.file.b64, name: state.file.name };
  // Code Lens and Hash want the raw text: neither a script nor a hash is decoded.
  const format = state.tab === "lens" || state.tab === "hash" ? "text" : $("format").value;
  return { input: $("input-text").value, format };
}

// The "your own wordlist" fields shared by the Symmetric, Hash and JWT tabs.
// The path is read by the server, which runs on this machine (--wordlist).
function wordlistOptions(tab) {
  return {
    wordlist: $(tab + "-wordlist").value,
    wordlist_limit: $(tab + "-wordlist-limit").value,
  };
}

// Options of the active tab.
function currentOptions() {
  if (state.tab === "xor") {
    return {
      key: $("xor-key").value,
      keylen: $("xor-keylen").value,
      crib: $("xor-crib").value,
      other: $("xor-other").value,
      hashed: $("xor-hashed").checked,
    };
  }
  if (state.tab === "rsa") {
    return {
      key: $("rsa-key").value,
      n: $("rsa-n").value,
      e: $("rsa-e").value,
      d: $("rsa-d").value,
      p: $("rsa-p").value,
      q: $("rsa-q").value,
      other: $("rsa-other").value,
      also: $("rsa-also").value,
      relation: $("rsa-relation").value,
      attack: $("rsa-attack").checked,
      seconds: $("rsa-seconds").value,
    };
  }
  if (state.tab === "hash") {
    return { no_passwords: $("hash-no-passwords").checked, ...wordlistOptions("hash") };
  }
  if (state.tab === "pipeline") {
    return { recipe: $("pipeline-recipe").value };
  }
  if (state.tab === "lens") {
    return { against: $("lens-against").value };
  }
  if (state.tab === "radius") {
    return { authenticator: $("radius-authenticator").value, secret: $("radius-secret").value };
  }
  if (state.tab === "jwt") {
    return { no_secrets: $("jwt-no-secrets").checked, ...wordlistOptions("jwt") };
  }
  if (state.tab === "extend") {
    return {
      digest: $("extend-digest").value,
      append: $("extend-append").value,
      secret_length: $("extend-length").value,
      algo: $("extend-algo").value,
      secret: $("extend-secret").value,
    };
  }
  if (state.tab === "sig") {
    return {
      curve: $("sig-curve").value,
      order: $("sig-order").value,
      hash: $("sig-hash").value,
    };
  }
  if (state.tab === "file") {
    return { reader: $("file-reader").value, wordlist: $("file-wordlist").value };
  }
  if (state.tab === "solve") {
    return { seconds: $("solve-seconds").value, depth: $("solve-depth").value };
  }
  if (state.tab === "workspace") {
    return { seconds: $("workspace-seconds").value };
  }
  if (state.tab === "timeline") {
    return {
      since: $("timeline-since").value,
      until: $("timeline-until").value,
      seconds: $("timeline-seconds").value,
    };
  }
  if (state.tab === "classical") {
    return {
      cipher: $("classical-cipher").value,
      key: $("classical-key").value,
      seconds: $("classical-seconds").value,
    };
  }
  if (state.tab === "crc") {
    return {
      length: $("crc-length").value,
      pattern: $("crc-pattern").value,
      seconds: $("crc-seconds").value,
      solve: $("crc-solve").checked,
    };
  }
  if (state.tab === "prng") {
    return {
      generator: $("prng-generator").value,
      forward: $("prng-forward").value,
      backward: $("prng-backward").value,
    };
  }
  if (state.tab === "keys") {
    return {
      against: $("keys-against").value,
      cipher: $("keys-cipher").value,
      mode: $("keys-mode").value,
      seconds: $("keys-seconds").value,
    };
  }
  if (state.tab === "sym") {
    return {
      key: $("sym-key").value,
      iv: $("sym-iv").value,
      blob: $("sym-blob").value,
      passphrase: $("sym-pass").value,
      cipher: $("sym-cipher").value,
      mode: $("sym-mode").value,
      seconds: $("sym-seconds").value,
      passwords: $("sym-passwords").checked,
      ...wordlistOptions("sym"),
    };
  }
  return {};
}

async function post(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const json = await response.json().catch(() => ({ error: "HTTP " + response.status }));
  if (!response.ok) throw new Error(json.error || "HTTP " + response.status);
  return json;
}

function setStatus(text, isError) {
  $("status").textContent = text || "";
  $("status").classList.toggle("error", Boolean(isError));
}

// Show the parsed input (length, notes, hexdump) on the left.
function showInput(input) {
  const notes = input.notes.length ? " - " + input.notes.join("; ") : "";
  $("input-info").textContent = input.length + " " + T("web_bytes") + " (" + input.source + ")" + notes;
  $("hexdump").textContent = hexdump(hexToBytes(input.preview_hex), 512);
}

let previewTimer = null;
function schedulePreview() {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(async () => {
    // The hexdump shows one input: the first dropped file, even on the tabs
    // that send them all (a list of files has no single hexdump).
    const payload = state.file ? { data_b64: state.file.b64, name: state.file.name } : currentPayload();
    if (!payload.data_b64 && !payload.input) {
      $("input-info").textContent = "";
      $("hexdump").textContent = "";
      return;
    }
    try {
      showInput((await post("/api/parse", payload)).input);
    } catch (error) {
      $("input-info").textContent = error.message;
      $("hexdump").textContent = "";
    }
  }, 300);
}

// ---------------------------------------------------------------- run
async function run() {
  if (!TOOLS[state.tab] || state.job) return;
  const payload = currentPayload();
  if (!payload.data_b64 && !payload.input && !payload.files) {
    setStatus(T("web_empty_input"), true);
    return;
  }
  payload.options = currentOptions();
  if (state.session) payload.session = state.session;
  const tab = state.tab;
  $("run").disabled = true;
  setStatus(T("web_running"));
  $("results").replaceChildren();
  hideSuggestions();
  try {
    const path = API_PATH[tab] || "/api/" + tab;
    const answer = TOOLS[tab] === "job" ? await runJob(tab, payload) : await post(path, payload);
    if (answer) showAnswer(tab, answer);
    if (answer && SUGGEST_TABS.includes(tab)) loadSuggestions(payload);
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    $("run").disabled = false;
    $("cancel").classList.add("hidden");
    $("progress").classList.add("hidden");
    state.job = null;
  }
}

// Start a background job, then poll it until it is finished (or cancelled).
async function runJob(kind, payload) {
  const { job } = await post("/api/jobs/" + kind, payload);
  state.job = job;
  $("cancel").classList.remove("hidden");
  $("progress").classList.remove("hidden");
  while (true) {
    await new Promise((resolve) => setTimeout(resolve, 250));
    const response = await fetch("/api/jobs/" + job);
    const status = await response.json();
    if (!response.ok) throw new Error(status.error || "job lost");
    $("progress-bar").style.width = Math.round(status.progress * 100) + "%";
    setStatus(T("web_running") + " " + status.attempts + " " + T("web_attempts"));
    if (status.state === "error") throw new Error(status.error);
    if (status.state === "done") return status.result;
    if (status.state === "cancelled") {
      status.result.cancelled = true;
      return status.result;
    }
  }
}

async function cancelJob() {
  if (state.job) await fetch("/api/jobs/" + state.job + "/cancel", { method: "POST" });
}

function showAnswer(tab, answer) {
  if (answer.input) showInput(answer.input);
  if (tab === "detect") {
    renderDetect(answer.report);
    setStatus("");
    return;
  }
  if (tab === "lens") {
    renderLens(answer);
    setStatus("");
    return;
  }
  if (tab === "hash") {
    renderHash(answer);
    setStatus("");
    return;
  }
  if (tab === "jwt") {
    renderJwt(answer);
    setStatus("");
    return;
  }
  if (tab === "extend") {
    renderExtend(answer);
    setStatus("");
    return;
  }
  if (tab === "prng") {
    renderPrng(answer);
    setStatus("");
    return;
  }
  if (tab === "solve") {
    renderSolve(answer);
    setStatus(answer.budget || "");
    return;
  }
  if (tab === "file") {
    renderFile(answer);
    setStatus("");
    loadPieces(answer.reader);
    return;
  }
  if (tab === "timeline" || tab === "workspace") {
    // Same display shape as the Files tab (formats.timeline / formats.workspace).
    renderFile(answer);
    setStatus(answer.budget || "");
    return;
  }
  if (tab === "crc") {
    renderCrc(answer);
    setStatus("");
    return;
  }
  if (tab === "sig") {
    renderSignatures(answer);
    setStatus("");
    return;
  }
  if (tab === "rsa") {
    renderRsa(answer);
    setStatus(answer.budget || "");
    return;
  }
  if (tab === "keys") {
    renderKeys(answer);
    setStatus(answer.cancelled ? T("web_cancelled") + " " + answer.budget : answer.budget);
    return;
  }
  if (tab === "pipeline") {
    renderPipeline(answer);
    setStatus(answer.ok ? "" : T("web_pipeline_failed"), !answer.ok);
    return;
  }
  if (answer.notes && answer.notes.length) renderNotes(answer.notes);
  if (answer.key_lengths && answer.key_lengths.length) renderKeyLengths(answer.key_lengths);
  renderCandidates(answer.candidates);
  setStatus(answer.cancelled ? T("web_cancelled") + " " + answer.budget : answer.budget);
}

// ---------------------------------------------------------------- rendering
function levelClass(score) {
  if (score >= 0.85) return "good";
  if (score >= 0.5) return "mid";
  return "";
}

function copyButton(label, getText) {
  const button = el("button", "small", label);
  button.addEventListener("click", async () => {
    await navigator.clipboard.writeText(getText());
    button.textContent = T("web_copied");
    setTimeout(() => (button.textContent = label), 1000);
  });
  return button;
}

// What the search detected and tried (header found, budget, missing material...).
function renderNotes(notes) {
  const list = el("ul", "notes");
  for (const note of notes) list.append(el("li", "", note));
  $("results").append(list);
}

function renderCandidates(candidates) {
  const results = $("results");
  if (!candidates.length) {
    results.append(el("p", "dim", T("web_no_result")));
    return;
  }
  for (const candidate of candidates) results.append(candidateCard(candidate));
}

function candidateCard(candidate) {
  const card = el("div", "card " + levelClass(candidate.score));
  const head = el("div", "card-head");
  head.append(el("span", "score", candidate.score.toFixed(2)), el("span", "label", candidate.label));
  card.append(head);

  const reasons = el("ul");
  for (const reason of candidate.reasons) reasons.append(el("li", "", reason));
  card.append(reasons);

  const view = outputView(candidate.data_hex, candidate.data_text);
  const readable = view.readable;
  card.append(view.output);

  const actions = el("div", "actions");
  actions.append(copyButton(T("web_copy"), view.currentText), view.button);

  if (candidate.python) {
    const code = el("pre", "code hidden", candidate.python);
    const codeButton = el("button", "small", T("web_show_python"));
    codeButton.addEventListener("click", () => {
      const hidden = code.classList.toggle("hidden");
      codeButton.textContent = hidden ? T("web_show_python") : T("web_hide_python");
    });
    actions.append(codeButton);
    card.append(actions, code);
  } else {
    card.append(actions);
  }
  if (candidate.cyberchef) {
    actions.append(copyButton(T("web_copy_cyberchef"), () => candidate.cyberchef));
    const chef = el("button", "small", T("web_open_cyberchef"));
    chef.addEventListener("click", () => openCyberChef(candidate.cyberchef));
    actions.append(chef);
  }
  // A result found by a chain of steps (Auto) can be replayed and edited as a recipe.
  const chain = candidate.params && candidate.params.chain;
  if (Array.isArray(chain) && chain.length) {
    const toPipeline = el("button", "small", T("web_open_pipeline"));
    toPipeline.addEventListener("click", () => openInPipeline(chain));
    actions.append(toPipeline);
  }

  const nextButton = el("button", "small", T("web_next_input"));
  nextButton.addEventListener("click", () => useAsInput(candidate, readable));
  actions.append(nextButton);
  return card;
}

// Output of a result: text view if readable, otherwise hexdump; a button switches.
function outputView(dataHex, dataText) {
  const bytes = hexToBytes(dataHex);
  const readable = isReadable(dataText);
  const output = el("pre", "output");
  let showingHex = !readable;
  const draw = () => {
    output.textContent = showingHex ? hexdump(bytes, 4096) : dataText;
  };
  draw();
  const button = el("button", "small", showingHex ? T("web_view_text") : T("web_view_hex"));
  button.addEventListener("click", () => {
    showingHex = !showingHex;
    button.textContent = showingHex ? T("web_view_text") : T("web_view_hex");
    draw();
  });
  return { output, button, readable, currentText: () => (showingHex ? dataHex : dataText) };
}

// Put a block of text back into the input box. The sections of the Files tab
// and the CRC candidates are plain text, not candidates with both views.
function useTextAsInput(text) {
  clearFile();
  $("input-text").value = text;
  $("format").value = "text";
  schedulePreview();
  $("input-text").focus();
}

// Put a result back into the input box, to keep working on it.
function useAsInput(candidate, readable) {
  clearFile();
  if (readable) {
    $("input-text").value = candidate.data_text;
    $("format").value = "text";
  } else {
    $("input-text").value = candidate.data_hex;
    $("format").value = "hex";
  }
  schedulePreview();
  $("input-text").focus();
}

// Small table: which XOR key lengths look likely, and why.
function renderKeyLengths(lengths) {
  const results = $("results");
  results.append(el("h3", "", T("web_key_lengths")));
  const table = el("table", "facts");
  const head = el("tr");
  head.append(el("td", "", "length"), el("td", "", "Hamming"), el("td", "", "ratio"));
  table.append(head);
  for (const guess of lengths) {
    const row = el("tr");
    row.append(
      el("td", "", String(guess.length)),
      el("td", "", guess.hamming.toFixed(2)),
      el("td", "", guess.ratio.toFixed(1)),
    );
    table.append(row);
  }
  results.append(table);
}

// Small helper: a table with a header row and a list of rows (all textContent).
function simpleTable(headers, rows) {
  const table = el("table", "facts");
  const head = el("tr");
  for (const header of headers) head.append(el("td", "th", header));
  table.append(head);
  for (const row of rows) {
    const line = el("tr");
    for (const cell of row) line.append(el("td", "", cell));
    table.append(line);
  }
  return table;
}

// Code Lens: what the script does, what was extracted, and how to undo it.
function renderLens(report) {
  const results = $("results");

  // With the encrypted file: what the script's literals decrypted, first.
  if (report.against && report.against.length) {
    results.append(el("h3", "", T("web_lens_against_results")));
    for (const candidate of report.against) results.append(candidateCard(candidate));
  }

  const card = el("div", "card good");
  const head = el("div", "card-head");
  head.append(el("span", "label", T("web_lens_language") + ": " + report.language));
  card.append(head);
  const summary = el("ul");
  if (!report.summary.length) summary.append(el("li", "dim", T("web_lens_nothing")));
  for (const line of report.summary) summary.append(el("li", "", line));
  card.append(summary);
  results.append(card);

  // The chain applied to every embedded blob: usually where the answer is.
  if (report.peeled && report.peeled.length) {
    results.append(el("h3", "", T("web_lens_peeled")));
    for (const peeled of report.peeled) {
      const peel = el("div", "card " + levelClass(peeled.score));
      const head = el("div", "card-head");
      head.append(
        el("span", "score", peeled.score.toFixed(2)),
        el("span", "label", peeled.label + (peeled.line ? " (line " + peeled.line + ")" : "")),
      );
      peel.append(head);
      const reasons = el("ul");
      for (const reason of peeled.reasons.slice(0, 4)) reasons.append(el("li", "", reason));
      peel.append(reasons);
      peel.append(el("pre", "output", peeled.data_text));
      const actions = el("div", "actions");
      actions.append(copyButton(T("web_copy"), () => peeled.data_text));
      const next = el("button", "small", T("web_next_input"));
      next.addEventListener("click", () => {
        clearFile();
        $("input-text").value = peeled.data_text;
        $("format").value = "text";
        schedulePreview();
      });
      actions.append(next);
      peel.append(actions);
      results.append(peel);
    }
  }

  if (report.operations.length) {
    results.append(el("h3", "", T("web_lens_operations")));
    results.append(
      simpleTable(
        ["#", "line", "step", "what", "rule"],
        report.operations.map((operation, index) => [
          String(index + 1),
          String(operation.line),
          operation.kind || "-",
          operation.label,
          operation.rule,
        ]),
      ),
    );
  }

  if (report.artifacts.length) {
    results.append(el("h3", "", T("web_lens_artifacts")));
    results.append(
      simpleTable(
        ["kind", "line", "name", "value", "how"],
        report.artifacts.map((artifact) => [
          artifact.kind,
          String(artifact.line),
          artifact.name || "-",
          artifact.preview,
          artifact.how,
        ]),
      ),
    );
  }

  if (report.behaviours.length) {
    results.append(el("h3", "", T("web_lens_behaviour")));
    results.append(
      simpleTable(
        ["kind", "line", "what"],
        report.behaviours.map((behaviour) => [
          behaviour.kind,
          String(behaviour.line),
          behaviour.label,
        ]),
      ),
    );
  }

  if (report.notes.length) renderNotes(report.notes);

  if (report.recovery) {
    const recovery = el("div", "card " + (report.recovery.complete ? "good" : "mid"));
    const title = el("div", "card-head");
    title.append(
      el("span", "label", T("web_lens_recovery") + ": " + report.recovery.label),
      el(
        "span",
        "rule",
        report.recovery.complete ? T("web_lens_complete") : T("web_lens_partial"),
      ),
    );
    recovery.append(title);
    const code = el("pre", "code", report.recovery.python);
    const actions = el("div", "actions");
    actions.append(copyButton(T("web_copy"), () => report.recovery.python));
    recovery.append(actions, code);
    results.append(recovery);
  }
}

// RSA: the key, what the attacks found, then the decryptions.
function renderRsa(report) {
  const results = $("results");
  if (report.key) {
    results.append(el("h3", "", T("web_rsa_facts")));
    results.append(simpleTable(["", ""], report.key.facts));
  }
  if (report.attacks) {
    const attacks = report.attacks;
    const found = attacks.factorisation || attacks.private_exponent;
    const card = el("div", "card " + (found ? "good" : ""));
    const head = el("div", "card-head");
    head.append(el("span", "label", found ? found.method : T("web_rsa_no_weakness")));
    card.append(head);
    const list = el("ul");
    if (found) list.append(el("li", "", found.explanation));
    if (attacks.factorisation) {
      list.append(el("li", "", "p = " + attacks.factorisation.p));
      list.append(el("li", "", "q = " + attacks.factorisation.q));
    }
    if (attacks.private_exponent) list.append(el("li", "", "d = " + attacks.private_exponent.d));
    list.append(el("li", "dim", T("web_rsa_tried") + ": " + attacks.tried.join(", ")));
    for (const note of attacks.notes) list.append(el("li", "", note));
    card.append(list);
    results.append(card);
  }
  if (report.notes && report.notes.length) renderNotes(report.notes);
  renderCandidates(report.candidates);
}

// Hash: the facts, then one card per possible format with its command.
function renderHash(report) {
  const results = $("results");
  results.append(el("h3", "", T("web_facts")));
  results.append(simpleTable(["", ""], report.facts));
  if (report.notes && report.notes.length) renderNotes(report.notes);
  if (!report.matches.length) {
    results.append(el("p", "dim", T("web_hash_none")));
    return;
  }
  results.append(el("h3", "", T("web_hash_formats")));
  for (const match of report.matches) {
    const card = el("div", "card " + levelClass(match.confidence));
    const head = el("div", "card-head");
    head.append(
      el("span", "score", match.confidence.toFixed(2)),
      el("span", "label", match.name),
      el("span", "rule", match.hashcat_mode !== null ? "-m " + match.hashcat_mode : match.john_format || ""),
    );
    card.append(head);
    const list = el("ul");
    // The "found in the list" line is already the first reason: no need to repeat it.
    for (const reason of match.reasons) list.append(el("li", "", reason));
    if (match.notes) list.append(el("li", "dim", match.notes));
    card.append(list);
    const actions = el("div", "actions");
    for (const [label, command] of [["hashcat", match.hashcat], ["john", match.john]]) {
      if (!command) continue;
      const line = el("pre", "code", command);
      card.append(line);
      actions.append(copyButton(T("web_copy") + " " + label, () => command));
    }
    card.append(actions);
    results.append(card);
  }
}

// A Detect guess that knows which tab solves it: switch there, pre-fill, run.
// The option ids follow the "<tab>-<option>" convention of index.html.
function applyGuess(action) {
  const tab = document.querySelector('.tab[data-tab="' + action.tab + '"]');
  if (!tab || tab.disabled) return;
  selectTab(tab);
  for (const [name, value] of Object.entries(action.options || {})) {
    const field = $(action.tab + "-" + name.replace(/_/g, "-"));
    if (!field) continue;
    if (field.type === "checkbox") {
      field.checked = Boolean(value);
    } else if (typeof value === "string" && value.startsWith("<")) {
      // A placeholder like "<this input>": the input panel already holds it.
      continue;
    } else {
      field.value = value;
    }
  }
  run();
}

function renderDetect(report) {
  const results = $("results");

  results.append(el("h3", "", T("web_facts")));
  const facts = el("table", "facts");
  for (const [name, value] of report.facts) {
    const row = el("tr");
    row.append(el("td", "", name), el("td", "", value));
    facts.append(row);
  }
  results.append(facts);

  if (report.entropy_windows.length > 1) results.append(entropyChart(report.entropy_windows));

  results.append(el("h3", "", T("web_guesses")));
  if (!report.guesses.length) {
    results.append(el("p", "dim", T("web_no_guess")));
    return;
  }
  for (const guess of report.guesses) {
    const card = el("div", "card " + levelClass(guess.confidence));
    const head = el("div", "card-head");
    head.append(
      el("span", "score", guess.confidence.toFixed(2)),
      el("span", "label", guess.label),
      el("span", "rule", guess.rule),
    );
    card.append(head);
    const reasons = el("ul");
    for (const reason of guess.reasons) reasons.append(el("li", "", reason));
    card.append(reasons);
    if (guess.next_step) {
      const next = el("div", "next", T("web_next_step") + ": ");
      next.append(el("code", "", guess.next_step));
      card.append(next);
    }
    if (guess.apply) {
      const target = document.querySelector('.tab[data-tab="' + guess.apply.tab + '"]');
      if (target && !target.disabled) {
        const actions = el("div", "actions");
        const button = el("button", "small", T("web_apply") + " " + target.textContent);
        button.addEventListener("click", () => applyGuess(guess.apply));
        actions.append(button);
        card.append(actions);
      }
    }
    results.append(card);
  }
}

// Bar chart of entropy per window: tall bars = random-looking (encrypted/compressed).
function entropyChart(windows) {
  const wrap = el("div", "entropy-chart");
  wrap.append(el("h3", "", T("web_entropy_chart")));
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 " + windows.length + " 8");
  svg.setAttribute("preserveAspectRatio", "none");
  windows.forEach((value, index) => {
    const bar = document.createElementNS(ns, "rect");
    bar.setAttribute("x", index);
    bar.setAttribute("y", 8 - value);
    bar.setAttribute("width", 0.9);
    bar.setAttribute("height", value);
    bar.setAttribute("fill", value > 7.5 ? "#ef6b73" : value > 5 ? "#e5c07b" : "#5fb3f9");
    const title = document.createElementNS(ns, "title");
    title.textContent = "offset " + index * 256 + ": " + value;
    bar.append(title);
    svg.append(bar);
  });
  wrap.append(svg);
  return wrap;
}

// ---------------------------------------------------------------- CyberChef
// Ask the server for the deep link (it knows whether the embedded copy exists
// and whether offline mode forbids the public one), then open it.
async function openCyberChef(recipe) {
  const payload = currentPayload();
  payload.options = { recipe };
  try {
    openLink(await post("/api/cyberchef", payload));
  } catch (error) {
    setStatus(error.message, true);
  }
}

function openLink(link) {
  if (!link || !link.url) {
    setStatus(link ? link.note : T("web_no_cyberchef"), true);
    return;
  }
  // The public instance receives the data: say so, and let the user decline.
  if (link.public && !window.confirm(T("web_cyberchef_confirm", { note: link.note }))) return;
  if (link.truncated) setStatus(T("web_cyberchef_truncated"));
  window.open(link.url, "_blank", "noopener");
}

// ---------------------------------------------------------------- pipeline
function readRecipe() {
  const text = $("pipeline-recipe").value.trim();
  if (!text) return { name: "recipe", steps: [] };
  const recipe = JSON.parse(text); // throws on bad JSON: the caller reports it
  return Array.isArray(recipe) ? { name: "recipe", steps: recipe } : recipe;
}

function writeRecipe(recipe) {
  $("pipeline-recipe").value = JSON.stringify(recipe, null, 2);
}

function addPipelineStep(template) {
  let recipe;
  try {
    recipe = readRecipe();
  } catch (error) {
    setStatus(T("web_pipeline_bad_json") + " " + error.message, true);
    return;
  }
  const step = { op: template.op };
  if (template.ask) {
    const value = window.prompt(T(template.prompt || "web_pipeline_ask_" + template.ask));
    if (value === null) return;
    const text = value.trim();
    // Numbers stay numbers in the JSON (a Caesar shift), keys stay text.
    step.args = { [template.ask]: /^-?\d+$/.test(text) && template.op !== "xor" ? Number(text) : text };
  } else if (template.args) {
    step.args = { ...template.args };
  }
  recipe.steps = recipe.steps || [];
  recipe.steps.push(step);
  writeRecipe(recipe);
  setStatus("");
}

// From an Auto result: load its chain as a recipe, on the same input, and run it.
function openInPipeline(chain) {
  const steps = chain.map((step) => {
    const entry = { op: step.name };
    if (step.params && Object.keys(step.params).length) entry.args = step.params;
    return entry;
  });
  // Named after its operations ("base64_zlib_xor"): also the file name on Save.
  writeRecipe({ name: steps.map((step) => step.op).join("_").slice(0, 40), steps });
  selectTab(document.querySelector('.tab[data-tab="pipeline"]'));
  run();
}

function savePipeline() {
  let recipe;
  try {
    recipe = readRecipe();
  } catch (error) {
    setStatus(T("web_pipeline_bad_json") + " " + error.message, true);
    return;
  }
  const blob = new Blob([JSON.stringify(recipe, null, 2) + "\n"], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = (recipe.name || "recipe") + ".json";
  link.click();
  URL.revokeObjectURL(link.href);
}

function loadPipelineFile(file) {
  const reader = new FileReader();
  reader.onload = () => {
    $("pipeline-recipe").value = reader.result;
    $("pipeline-file").value = "";
    setStatus("");
  };
  reader.readAsText(file);
}

// One card per step, each with its own output: you see where a recipe goes wrong.
function renderPipeline(answer) {
  const results = $("results");
  if (answer.notes.length) renderNotes(answer.notes);
  answer.steps.forEach((step, index) => {
    if (index) results.append(el("div", "step-arrow", "↓"));
    const card = el("div", "card " + (step.error ? "failed" : levelClass(step.score)));
    const head = el("div", "card-head");
    head.append(
      el("span", "score", step.error ? "✗" : step.score.toFixed(2)),
      el("span", "label", T("web_pipeline_step") + " " + step.index + ": " + step.label),
      el("span", "rule", step.error ? "" : step.length + " " + T("web_bytes")),
    );
    card.append(head);
    if (step.comment) card.append(el("div", "step-comment", step.comment));
    if (step.error) {
      card.append(el("div", "step-error", step.error));
      results.append(card);
      return;
    }
    const reasons = el("ul");
    for (const reason of step.reasons.slice(0, 3)) reasons.append(el("li", "", reason));
    card.append(reasons);
    const view = outputView(step.data_hex, step.data_text);
    card.append(view.output);
    const actions = el("div", "actions");
    actions.append(copyButton(T("web_copy"), view.currentText), view.button);
    const next = el("button", "small", T("web_next_input"));
    next.addEventListener("click", () =>
      useAsInput({ data_text: step.data_text, data_hex: step.data_hex }, view.readable),
    );
    actions.append(next);
    card.append(actions);
    results.append(card);
  });

  // The whole recipe, exported: Python script, CyberChef, JSON.
  const card = el("div", "card " + (answer.ok ? "good" : "mid"));
  const head = el("div", "card-head");
  head.append(el("span", "label", T("web_pipeline_export")));
  card.append(head);
  const actions = el("div", "actions");
  if (answer.python) actions.append(copyButton(T("web_copy") + " Python", () => answer.python));
  if (answer.cyberchef) {
    actions.append(copyButton(T("web_copy_cyberchef"), () => answer.cyberchef));
    const chef = el("button", "small", T("web_open_cyberchef"));
    chef.addEventListener("click", () => openLink(answer.cyberchef_link));
    actions.append(chef);
  } else if (answer.python) {
    actions.append(el("span", "dim", T("web_pipeline_no_cyberchef")));
  }
  actions.append(copyButton(T("web_copy") + " JSON", () => answer.recipe_json));
  card.append(actions);
  if (answer.python) card.append(el("pre", "code", answer.python));
  results.append(card);
}

// ---------------------------------------------------------------- keys
// Key hunting: where each candidate key was found, then what it decrypted.
function renderKeys(report) {
  const results = $("results");
  if (report.notes.length) renderNotes(report.notes);
  if (report.winner) {
    const card = el("div", "card good");
    const head = el("div", "card-head");
    head.append(el("span", "label", T("web_keys_winner") + " 0x" + report.winner.offset.toString(16)));
    card.append(head);
    card.append(el("div", "step-comment", report.winner.how));
    card.append(el("pre", "code", report.winner.key_hex));
    const actions = el("div", "actions");
    actions.append(copyButton(T("web_copy") + " hex", () => report.winner.key_hex));
    card.append(actions);
    results.append(card);
  }
  for (const candidate of report.results) results.append(candidateCard(candidate));
  if (report.candidates.length) {
    results.append(el("h3", "", T("web_keys_candidates") + " (" + report.candidate_count + ")"));
    results.append(
      simpleTable(
        ["offset", "kind", "len", "key", "how"],
        report.candidates.map((c) => [
          c.offset_hex,
          c.kind.replace(/_/g, " ") + (c.role !== "key" ? " (" + c.role + ")" : ""),
          String(c.length),
          isPrintableAscii(c.key_text) ? c.key_text : c.key_hex,
          c.how,
        ]),
      ),
    );
  }
}

function isPrintableAscii(text) {
  return Boolean(text) && /^[\x20-\x7e]+$/.test(text);
}

// A ciphertext is often a file: read it and put it in the box as b64:...
// `prefix` is the tab ("keys" or "lens"): the ids are <prefix>-against etc.
function loadCiphertextFile(prefix, file) {
  const reader = new FileReader();
  reader.onload = () => {
    $(prefix + "-against").value = "b64:" + bytesToBase64(new Uint8Array(reader.result));
    $(prefix + "-file-name").textContent = file.name;
    $(prefix + "-file").value = "";
  };
  reader.readAsArrayBuffer(file);
}

// ---------------------------------------------------------------- suggested tools
function hideSuggestions() {
  $("suggested").classList.add("hidden");
  $("suggested").replaceChildren();
}

// Computed after the main result, so it never delays it. Shows nothing at all
// when no rule fired confidently: no noise during a timed CTF.
async function loadSuggestions(payload) {
  let answer;
  try {
    answer = await post("/api/tools", { ...payload, options: {} });
  } catch (error) {
    return; // the suggestions are a bonus: never turn them into an error
  }
  if (!answer.suggestions.length) return;
  const strip = $("suggested");
  strip.replaceChildren(el("h3", "", T("web_suggested")));
  for (const tool of answer.suggestions) strip.append(toolRow(tool, payload));
  strip.classList.remove("hidden");
}

function toolRow(tool, payload) {
  const row = el("div", "tool");
  const head = el("div", "card-head");
  let state = tool.kind === "online" ? T("web_tool_online") : T("web_tool_local");
  if (tool.kind === "local") state = tool.available ? T("web_tool_installed") : T("web_tool_missing");
  head.append(el("span", "label", tool.name), el("span", "dim", tool.reason), el("span", "rule", state));
  row.append(head);
  if (tool.notes) row.append(el("div", "step-comment", tool.notes));
  if (tool.warning) row.append(el("div", "warning", "⚠ " + tool.warning));

  const actions = el("div", "actions");
  if (tool.command.length) {
    row.append(el("pre", "code", tool.command_line));
    actions.append(copyButton(T("web_tool_copy_command"), () => tool.command_line));
  }
  if (tool.url) {
    const open = el("button", "small", T("web_tool_open"));
    open.addEventListener("click", () => {
      if (!tool.offline_safe && !window.confirm(T("web_cyberchef_confirm", { note: tool.warning }))) return;
      window.open(tool.url, "_blank", "noopener");
    });
    actions.append(open);
  }
  if (tool.kind === "local" && !tool.available && tool.install) {
    actions.append(el("span", "dim", T("web_tool_install") + ": " + tool.install));
  }
  if (tool.kind === "local" && tool.gui) {
    actions.append(el("span", "dim", T("web_tool_gui")));
  } else if (tool.kind === "local" && tool.available && !payload) {
    actions.append(el("span", "dim", T("web_next_tool_piece")));
  }
  if (tool.kind === "local" && tool.available && payload && !tool.gui) {
    // {input} is filled by the server (a temporary copy of the input); the
    // other placeholders the user types here.
    const fields = {};
    for (const name of tool.placeholders) {
      if (name === "{input}") continue;
      const key = name.replace(/[{}]/g, "");
      const field = el("input");
      field.type = key === "password" ? "password" : "text";
      field.placeholder = key;
      field.size = key === "wordlist" ? 28 : 12;
      fields[key] = field;
      actions.append(field);
    }
    const output = el("pre", "run-output hidden");
    const runButton = el("button", "small", T("web_tool_run"));
    runButton.addEventListener("click", async () => {
      const options = { tool: tool.id };
      for (const [key, field] of Object.entries(fields)) options[key] = field.value;
      runButton.disabled = true;
      output.classList.remove("hidden");
      output.textContent = T("web_running");
      try {
        const result = await post("/api/tools/run", { ...payload, options });
        output.textContent =
          "$ " + result.command_line + "\n" +
          (result.error ? result.error + "\n" : "exit code " + result.returncode + "\n") +
          result.stdout + (result.stderr ? "\n--- stderr ---\n" + result.stderr : "");
      } catch (error) {
        output.textContent = error.message;
      } finally {
        runButton.disabled = false;
      }
    });
    actions.append(runButton);
    row.append(actions, output);
    return row;
  }
  row.append(actions);
  return row;
}

// ---------------------------------------------------------------- cheat sheet
async function showCheatsheet() {
  try {
    const answer = await (await fetch("/api/cheatsheet")).json();
    $("results").replaceChildren(renderMarkdown(answer.markdown));
  } catch (error) {
    setStatus(error.message, true);
  }
}

// ---------------------------------------------------------------- JWT
function renderJwt(report) {
  const results = $("results");
  const facts = el("table", "facts");
  const rows = [
    ["algorithm", report.algorithm || "(none)"],
    ["signature", report.signature_bytes + " bytes"],
  ];
  if (report.secret !== null && report.secret !== undefined) rows.push(["secret", report.secret]);
  for (const [name, value] of rows) {
    const row = el("tr");
    row.append(el("td", "dim", name), el("td", "", String(value)));
    facts.append(row);
  }
  results.append(facts);
  if (report.notes && report.notes.length) renderNotes(report.notes);

  for (const finding of report.findings) {
    const card = el("div", "card " + (finding.severity === "high" ? "good" : ""));
    const head = el("div", "card-head");
    head.append(el("span", "score", finding.severity), el("span", "label", finding.rule));
    card.append(head, el("p", "", finding.what));
    if (finding.next_step) card.append(el("p", "vol-tip", "\u2192 " + finding.next_step));
    results.append(card);
  }
  for (const [title, value] of [["header", report.header], ["payload", report.payload]]) {
    results.append(el("h3", "", title));
    results.append(el("pre", "code", JSON.stringify(value, null, 2)));
  }
  if (report.times.length) {
    results.append(el("h3", "", "times"));
    const list = el("ul", "notes");
    for (const line of report.times) list.append(el("li", "", line));
    results.append(list);
  }
  if (report.forged) {
    results.append(el("h3", "", "a token you can send instead"));
    const box = el("pre", "code", report.forged);
    results.append(box);
    results.append(copyButton(T("web_copy"), () => report.forged));
  }
  if (report.python) {
    results.append(el("h3", "", "reproduce it"));
    results.append(el("pre", "code", report.python));
  }
}

// -------------------------------------------------------- length extension
function renderExtend(answer) {
  const results = $("results");
  const best = answer.candidates[0];
  const table = el("table", "facts");
  for (const [name, value] of [
    ["hash", best.algorithm],
    ["secret length", best.secret_length + (best.verified ? " (verified)" : "")],
    ["forged digest", best.digest],
  ]) {
    const row = el("tr");
    row.append(el("td", "dim", name), el("td", "", String(value)));
    table.append(row);
  }
  results.append(table);

  results.append(el("h3", "", T("web_extend_message")));
  results.append(el("pre", "code", best.message_hex));
  results.append(copyButton(T("web_copy"), () => best.message_hex));
  results.append(el("h3", "", T("web_extend_url")));
  results.append(el("pre", "code", best.message_url));
  results.append(copyButton(T("web_copy"), () => best.message_url));

  if (answer.candidates.length > 1) {
    const list = el("table", "facts");
    for (const candidate of answer.candidates) {
      const row = el("tr");
      row.append(
        el("td", "dim", "len " + candidate.secret_length),
        el("td", "", candidate.digest),
        el("td", "dim", candidate.message_url),
      );
      list.append(row);
    }
    results.append(el("h3", "", "every candidate length"));
    results.append(list);
  }
  if (answer.notes && answer.notes.length) renderNotes(answer.notes);
  if (best.python) {
    results.append(el("h3", "", "reproduce it"));
    results.append(el("pre", "code", best.python));
  }
}

// ---------------------------------------------------------------------- PRNG
function renderPrng(report) {
  const results = $("results");
  const facts = el("table", "facts");
  const rows = [["cloned", report.generator], ["values used", report.used]];
  if (report.confirmed) rows.push(["confirmed on", report.confirmed + " further value(s)"]);
  if (report.seed !== null && report.seed !== undefined) rows.push(["seed", report.seed]);
  for (const [name, value] of rows) {
    const row = el("tr");
    row.append(el("td", "dim", name), el("td", "", String(value)));
    facts.append(row);
  }
  results.append(facts);

  const sections = [
    [T("web_prng_next"), report.next_values],
    [T("web_prng_previous"), report.previous_values],
  ];
  for (const [title, values] of sections) {
    if (!values || !values.length) continue;
    results.append(el("h3", "", title));
    const text = values.join("\n");
    results.append(el("pre", "code", text));
    results.append(copyButton(T("web_copy"), () => text));
  }
  if (report.next_floats && report.next_floats.length) {
    results.append(el("h3", "", T("web_prng_floats")));
    results.append(el("pre", "code", report.next_floats.join("\n")));
  }
  if (report.notes && report.notes.length) renderNotes(report.notes);
  if (report.python) {
    results.append(el("h3", "", "reproduce it"));
    results.append(el("pre", "code", report.python));
  }
}

// ---------------------------------------------------------------- Volatility
// A reference page, not a tool: ctfc never runs Volatility. The point is that
// every command is already filled in with YOUR file name and profile, so it can
// be copied and pasted as it stands.
//
// The commands in data/volatility.toml assume the user's aliases:
//   vol  = volatility3 -f      vol2 = volatility2.4 -f

async function showVolatility() {
  if (state.vol.data === null) {
    try {
      state.vol.data = await (await fetch("/api/volatility")).json();
    } catch (error) {
      setStatus(error.message, true);
      return;
    }
  }
  renderVolatility();
}

// Put the user's file name / profile into a command from the table.
function volCommand(cmd) {
  const image = $("vol-image").value.trim() || "mem.raw";
  const profile = $("vol-profile").value.trim();
  return cmd
    .replaceAll("<image>", image)
    .replaceAll("<profile>", profile || "<profile>")
    .replaceAll("<LinuxProfile>", profile || "<LinuxProfile>");
}

function renderVolatility() {
  const data = state.vol.data;
  const root = el("div", "markdown vol");
  const needle = $("vol-filter").value.trim().toLowerCase();

  // "What do I have?" - the file-type triage, always shown (it is what decides
  // whether Volatility is even the right tool).
  if (!needle) {
    root.append(el("h2", "", T("web_vol_have")));
    const table = el("table", "facts vol-types");
    for (const item of data.filetype || []) {
      const row = el("tr");
      row.append(el("td", "vol-type-name", item.name));
      const right = el("td");
      right.append(el("div", "dim", item.how), el("div", "", item.what));
      if (item.start) right.append(el("div", "vol-start", "→ " + item.start));
      row.append(right);
      table.append(row);
    }
    root.append(table);
  }

  // Then the phases of the chosen tool, in order.
  let shown = 0;
  for (const section of data.section || []) {
    if (section.engine !== state.vol.engine) continue;
    if (state.vol.os !== "all" && section.os !== "any" && section.os !== state.vol.os) continue;
    const steps = (section.step || []).filter((step) => matchesVolFilter(step, section, needle));
    if (!steps.length) continue;
    shown += steps.length;
    root.append(el("h2", "", section.title));
    if (section.intro && !needle) root.append(el("p", "dim", section.intro));
    for (const step of steps) root.append(volStepRow(step));
  }
  if (!shown) root.append(el("p", "dim", T("web_vol_nomatch")));
  $("results").replaceChildren(root);
}

function matchesVolFilter(step, section, needle) {
  if (!needle) return true;
  const haystack = [step.cmd, step.desc, step.tip || "", section.title, section.group]
    .join(" ")
    .toLowerCase();
  return haystack.includes(needle);
}

// One command: the line itself, a Copy button, what it does, and the decision.
function volStepRow(step) {
  const row = el("div", "vol-step");
  const command = volCommand(step.cmd);
  const head = el("div", "vol-cmd-line");
  head.append(el("code", "vol-cmd", command));
  head.append(copyButton(T("web_copy"), () => command));
  row.append(head);
  row.append(el("div", "vol-desc", step.desc));
  if (step.tip) row.append(el("div", "vol-tip", "→ " + step.tip));
  return row;
}

// A very small Markdown renderer for the cheat sheet: headings, paragraphs, lists,
// tables, code blocks, `code` and **bold**. Every piece of text goes through
// textContent, so nothing in the file can become HTML.
function renderMarkdown(text) {
  const root = el("div", "markdown");
  const lines = text.split("\n");
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith("```")) {
      const code = [];
      for (i++; i < lines.length && !lines[i].startsWith("```"); i++) code.push(lines[i]);
      root.append(el("pre", "code", code.join("\n")));
      i++;
    } else if (/^#{1,3} /.test(line)) {
      const level = line.indexOf(" ");
      root.append(inline(el("h" + level), line.slice(level + 1)));
      i++;
    } else if (line.startsWith("|")) {
      const table = el("table", "facts");
      for (; i < lines.length && lines[i].startsWith("|"); i++) {
        if (/^\|[-| ]+\|$/.test(lines[i])) continue; // the |---|---| separator
        const row = el("tr");
        for (const cell of lines[i].slice(1, -1).split("|")) row.append(inline(el("td"), cell.trim()));
        table.append(row);
      }
      root.append(table);
    } else if (line.startsWith("- ")) {
      const list = el("ul");
      for (; i < lines.length && (lines[i].startsWith("- ") || lines[i].startsWith("  ")); i++) {
        if (lines[i].startsWith("- ")) list.append(inline(el("li"), lines[i].slice(2)));
        else list.lastChild.append(" ", ...inline(el("span"), lines[i].trim()).childNodes);
      }
      root.append(list);
    } else if (line.trim()) {
      const paragraph = [];
      for (; i < lines.length && lines[i].trim() && !/^(#|\||- |```)/.test(lines[i]); i++) {
        paragraph.push(lines[i]);
      }
      root.append(inline(el("p"), paragraph.join(" ")));
    } else {
      i++;
    }
  }
  return root;
}

// `code` and **bold** inside a line, appended to `node` as safe text nodes.
function inline(node, text) {
  for (const part of text.split(/(`[^`]+`|\*\*[^*]+\*\*)/)) {
    if (part.startsWith("`") && part.endsWith("`") && part.length > 1) {
      node.append(el("code", "", part.slice(1, -1)));
    } else if (part.startsWith("**") && part.endsWith("**") && part.length > 3) {
      node.append(el("strong", "", part.slice(2, -2)));
    } else if (part) {
      node.append(document.createTextNode(part));
    }
  }
  return node;
}

// ---------------------------------------------------------------- sessions
async function loadSessions(select) {
  const answer = await (await fetch("/api/sessions")).json();
  const box = $("session-select");
  box.replaceChildren(el("option", "", T("web_session_none")));
  box.firstChild.value = "";
  for (const item of answer.sessions) {
    const option = el("option", "", item.name + (item.title ? " - " + item.title : ""));
    option.value = item.name;
    box.append(option);
  }
  const wanted = select !== undefined ? select : answer.current || "";
  box.value = wanted;
  state.session = box.value;
}

async function newSession() {
  const name = window.prompt(T("web_session_ask_name"));
  if (!name) return;
  const title = window.prompt(T("web_session_ask_title")) || "";
  try {
    const answer = await post("/api/sessions", { name: name.trim(), title });
    await loadSessions(answer.name);
    setStatus(T("web_session_created", { name: answer.name }));
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function addNote() {
  const text = $("session-note").value.trim();
  if (!state.session || !text) {
    setStatus(T("web_session_pick_first"), true);
    return;
  }
  try {
    await post("/api/sessions/" + encodeURIComponent(state.session) + "/note", { text });
    $("session-note").value = "";
    setStatus(T("web_session_noted"));
  } catch (error) {
    setStatus(error.message, true);
  }
}

function downloadReport() {
  if (!state.session) {
    setStatus(T("web_session_pick_first"), true);
    return;
  }
  const lang = window.confirm(T("web_session_ask_french")) ? "fr" : "en";
  window.location.href = "/api/sessions/" + encodeURIComponent(state.session) + "/report?lang=" + lang;
}

// ---------------------------------------------------------------- file input
// Read every dropped file. The first one is `state.file`, which every tab
// uses; Workspace and Timeline send them all (MULTI_FILE_TABS).
async function loadFiles(fileList) {
  const files = Array.from(fileList);
  if (!files.length) return;
  const read = (file) => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
  state.files = [];
  for (const file of files) {
    const bytes = await read(file);
    state.files.push({ name: file.name, b64: bytesToBase64(bytes), size: bytes.length });
  }
  state.file = state.files[0];
  let label = state.file.name + " (" + state.file.size + " " + T("web_bytes") + ")";
  if (state.files.length > 1) {
    label = state.files.length + " " + T("web_files_dropped") + ": "
      + state.files.map((f) => f.name).join(", ") + ". " + T("web_files_first_only");
  }
  $("file-name").textContent = label;
  $("file-info").classList.remove("hidden");
  $("input-text").disabled = true;
  schedulePreview();
}

function clearFile() {
  state.file = null;
  state.files = [];
  $("file-input").value = "";
  $("file-info").classList.add("hidden");
  $("input-text").disabled = false;
}

// ---------------------------------------------------------------- tabs
function selectTab(button) {
  if (button.dataset.milestone) return;
  state.tab = button.dataset.tab;
  for (const tab of document.querySelectorAll(".tab")) tab.classList.toggle("active", tab === button);
  for (const name of OPTION_PANELS) {
    $("options-" + name).classList.toggle("hidden", state.tab !== name);
  }
  $("tab-help").textContent = T("web_" + state.tab + "_help");
  $("results").replaceChildren();
  hideSuggestions();
  setStatus("");
  // A reference tab is not a tool: it is shown as soon as it is opened.
  $("run").classList.toggle("hidden", REFERENCE_TABS.includes(state.tab));
  if (state.tab === "cheatsheet") showCheatsheet();
  if (state.tab === "docs") showDoc($("docs-pick").value);
  if (state.tab === "volatility") showVolatility();
}

// ---------------------------------------------------------------- start-up
async function init() {
  try {
    state.strings = await (await fetch("/api/strings")).json();
  } catch (error) {
    state.strings = {};
  }
  for (const node of document.querySelectorAll("[data-t]")) node.textContent = T(node.dataset.t);
  for (const node of document.querySelectorAll("[data-t-placeholder]")) {
    node.placeholder = T(node.dataset.tPlaceholder);
  }

  // Tabs not built yet are disabled, with a tooltip saying when they arrive.
  for (const tab of document.querySelectorAll(".tab")) {
    if (tab.dataset.milestone) {
      tab.disabled = true;
      tab.title = T("web_coming", { milestone: tab.dataset.milestone });
    }
    tab.addEventListener("click", () => selectTab(tab));
  }
  $("tab-help").textContent = T("web_auto_help");

  // Search: a regex over the bytes, or a flag hunt. Enter in the pattern box
  // runs the regex; the button next to it hunts for a flag instead.
  $("search-run").addEventListener("click", () => runSearch(false));
  $("search-flags").addEventListener("click", () => runSearch(true));
  $("search-pattern").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      runSearch(false);
    }
  });

  // Docs tab: the menu is filled from the server, and changing it reloads.
  fetch("/api/docs").then((r) => r.json()).then((answer) => {
    const select = $("docs-pick");
    for (const doc of answer.docs || []) {
      const option = el("option", "", doc.title);
      option.value = doc.id;
      if (doc.id === "how-it-works") option.selected = true;
      select.append(option);
    }
    select.addEventListener("change", () => showDoc(select.value));
  }).catch(() => {});

  // Files tab: the reader dropdown is filled from the server, so a reader added
  // to ctfc/web/formats.py appears here with no change to this file.
  fetch("/api/file/readers").then((r) => r.json()).then((answer) => {
    const select = $("file-reader");
    for (const reader of answer.readers || []) {
      const option = el("option", "", reader.label + "  (" + reader.command + ")");
      option.value = reader.name;
      select.append(option);
    }
  }).catch(() => {});

  fetch("/api/health").then((r) => r.json()).then((health) => {
    $("version").textContent = "v" + health.version;
    $("offline-badge").classList.toggle("hidden", !health.offline);
  });

  // Pipeline tab: one button per common operation, plus load / save / clear.
  for (const template of PIPELINE_STEPS) {
    const button = el("button", "small", template.op === "cipher" ? "aes/cipher" : template.op);
    button.addEventListener("click", () => addPipelineStep(template));
    $("pipeline-add").append(button);
  }
  for (const prefix of ["keys", "lens"]) {
    $(prefix + "-load").addEventListener("click", () => $(prefix + "-file").click());
    $(prefix + "-file").addEventListener("change", (event) => {
      if (event.target.files[0]) loadCiphertextFile(prefix, event.target.files[0]);
    });
  }
  $("pipeline-load").addEventListener("click", () => $("pipeline-file").click());
  $("pipeline-file").addEventListener("change", (event) => {
    if (event.target.files[0]) loadPipelineFile(event.target.files[0]);
  });
  $("pipeline-save").addEventListener("click", savePipeline);
  $("pipeline-clear").addEventListener("click", () => {
    $("pipeline-recipe").value = "";
    $("results").replaceChildren();
  });

  // Volatility tab: every control re-renders the page, so the commands shown
  // always carry the current file name, profile, tool and filter.
  for (const button of document.querySelectorAll(".vol-engine")) {
    button.addEventListener("click", () => {
      state.vol.engine = button.dataset.engine;
      for (const other of document.querySelectorAll(".vol-engine")) {
        other.classList.toggle("active", other === button);
      }
      renderVolatility();
    });
  }
  for (const button of document.querySelectorAll(".vol-os")) {
    button.addEventListener("click", () => {
      state.vol.os = button.dataset.os;
      for (const other of document.querySelectorAll(".vol-os")) {
        other.classList.toggle("active", other === button);
      }
      renderVolatility();
    });
  }
  for (const id of ["vol-image", "vol-profile", "vol-filter"]) {
    $(id).addEventListener("input", () => {
      if (state.vol.data) renderVolatility();
    });
  }

  loadSessions().catch(() => {});
  $("session-select").addEventListener("change", (event) => (state.session = event.target.value));
  $("session-new").addEventListener("click", newSession);
  $("session-note-add").addEventListener("click", addNote);
  $("session-note").addEventListener("keydown", (event) => {
    if (event.key === "Enter") addNote();
  });
  $("session-report").addEventListener("click", downloadReport);
  // The same session, as the script that re-does the solve (ctfc replay).
  $("session-replay").addEventListener("click", () => {
    if (!state.session) {
      setStatus(T("web_session_pick_first"), true);
      return;
    }
    window.location.href = "/api/sessions/" + encodeURIComponent(state.session) + "/replay";
  });

  $("run").addEventListener("click", run);
  $("cancel").addEventListener("click", cancelJob);
  $("input-text").addEventListener("input", schedulePreview);
  $("format").addEventListener("change", schedulePreview);
  document.addEventListener("keydown", (event) => {
    if (event.ctrlKey && event.key === "Enter") {
      event.preventDefault();
      run();
    }
  });

  const zone = $("drop-zone");
  zone.addEventListener("click", () => $("file-input").click());
  zone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") $("file-input").click();
  });
  $("file-input").addEventListener("change", (event) => {
    loadFiles(event.target.files);
  });
  zone.addEventListener("dragover", (event) => {
    event.preventDefault();
    zone.classList.add("over");
  });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (event) => {
    event.preventDefault();
    zone.classList.remove("over");
    loadFiles(event.dataTransfer.files);
  });
  $("file-clear").addEventListener("click", () => {
    clearFile();
    schedulePreview();
  });
}

init();

// --------------------------------------------------------------------- Files
// One renderer for every file-format reader. The server (ctfc/web/formats.py)
// turns each report into the same shape - a list of sections, each a facts
// table, a table or a block of text - so a reader added later shows up here
// without a line of JavaScript.
function renderSolve(answer) {
  // The point of this tab is that it shows *one* thing when it worked: the
  // flag, with the commands that reproduce it. The walk itself is behind a
  // checkbox, because it is the thing you read when it did not work.
  const results = $("results");
  const head = el("div", "file-head");
  head.append(el("strong", "", answer.path || T("web_tab_solve")));
  const detail = [];
  if (answer.read_as) detail.push(T("web_solve_read_as") + " " + answer.read_as);
  detail.push(answer.pieces + " " + T("web_solve_pieces"));
  head.append(el("span", "dim", "  " + detail.join("  -  ")));
  results.append(head);

  if ($("solve-steps") && $("solve-steps").checked) {
    const steps = el("ul", "steps");
    for (const step of answer.steps || []) steps.append(el("li", "dim", step));
    results.append(steps);
  }

  for (const flag of answer.flags || []) {
    const box = el("div", "flag");
    box.append(el("strong", "", flag.text));
    box.append(copyButton(T("web_copy"), () => flag.text));
    box.append(
      el("div", "dim", T("web_solve_found_in") + " " + flag.where + "  (" + flag.how + ")"),
    );
    for (const command of flag.trail || []) {
      const line = el("div", "command");
      line.append(el("code", "", command));
      line.append(copyButton(T("web_copy"), () => command));
      box.append(line);
    }
    results.append(box);
  }

  if (!(answer.flags || []).length && (answer.leads || []).length) {
    results.append(el("p", "", T("web_solve_leads")));
    const table = el("table", "ranked");
    const header = el("tr");
    for (const name of ["score", "piece", "why"]) header.append(el("th", "", name));
    table.append(header);
    for (const lead of answer.leads) {
      const row = el("tr");
      row.append(el("td", levelClass(lead.score), lead.score.toFixed(2)));
      row.append(el("td", "", lead.title));
      row.append(el("td", "dim", lead.why));
      table.append(row);
    }
    results.append(table);
    for (const lead of answer.leads) {
      const line = el("div", "command");
      line.append(el("code", "", lead.command));
      line.append(copyButton(T("web_copy"), () => lead.command));
      if (lead.preview) line.append(el("div", "dim", lead.preview));
      results.append(line);
    }
  }
  // Parts of a flag (a start with no end, an end with no start): the clue that
  // sends you to the other half. Hidden when they are inside the flag above.
  const flagTexts = (answer.flags || []).map((flag) => flag.text);
  const loose = (answer.fragments || []).filter(
    (fragment) => !flagTexts.some((text) => text.includes(fragment.text)),
  );
  if (loose.length) {
    results.append(el("p", "", T("web_solve_fragments")));
    for (const fragment of loose.slice(0, 8)) {
      const line = el("div", "command");
      line.append(el("code", "", fragment.text));
      line.append(copyButton(T("web_copy"), () => fragment.text));
      line.append(
        el("div", "dim", fragment.side + ", " + fragment.how + " - " + fragment.where),
      );
      results.append(line);
    }
  }
  renderNextSteps(answer.next_steps || []);
  if (answer.notes && answer.notes.length) renderNotes(answer.notes);
}

// No flag: one card per finding (core/nextsteps.py + data/leads.toml) - what
// was found, what it usually means, the ctfc commands, then the external tools
// with their command filled in. A tool can be run from here only when the
// finding is about the input itself: a piece found inside it is not on the
// server's disk, so its command is for copying.
function renderNextSteps(steps) {
  if (!steps.length) return;
  const results = $("results");
  results.append(el("h3", "", T("web_solve_next")));
  steps.forEach((step, index) => {
    const card = el("div", "card next-step");
    const head = el("div", "card-head");
    head.append(el("span", "label", index + 1 + ". " + step.found));
    card.append(head);
    if (step.also && step.also.length) {
      card.append(el("div", "dim", T("web_next_also") + ": " + step.also.slice(0, 3).join(", ")));
    }
    card.append(el("div", "step-comment", T("web_next_means") + ": " + step.meaning));
    if (step.trail && step.trail.length) {
      card.append(el("div", "dim", T("web_next_trail") + ":"));
      for (const command of step.trail) card.append(commandLine(command));
    }
    for (const command of step.ctfc || []) card.append(commandLine(command));
    const payload = step.on_input ? currentPayload() : null;
    if (!step.on_input) {
      // The piece is inside the input: fetch it, and it becomes the input -
      // then every tab (and the Run buttons) works on it.
      const load = el("button", "small", T("web_piece_load"));
      load.addEventListener("click", () => loadSolvePiece(step.piece, load));
      card.append(load);
    }
    for (const tool of step.tools || []) card.append(toolRow(tool, payload));
    for (const text of step.by_hand || []) {
      card.append(el("div", "step-comment", T("web_next_by_hand") + ": " + text));
    }
    results.append(card);
  });
}

// ---------------------------------------------------------------- pieces
// What `--extract` does in the terminal: the files a reader found inside the
// input, each one downloadable or usable as the next input. Listed after the
// main result, so a big capture never delays it.
async function loadPieces(reader) {
  const payload = currentPayload();
  if (!payload.data_b64 && !payload.input) return;
  let answer;
  try {
    answer = await post("/api/file/pieces", { ...payload, options: { reader } });
  } catch (error) {
    return; // the list is a bonus: the report above is already there
  }
  if (!answer.pieces.length) return;
  const results = $("results");
  results.append(el("h3", "", T("web_pieces_title", { count: answer.total })));
  const table = el("table", "facts pieces");
  for (const piece of answer.pieces) {
    const row = el("tr");
    row.append(el("td", "", piece.name), el("td", "dim", piece.size + " " + T("web_bytes")));
    row.append(el("td", "dim", piece.origin));
    const actions = el("td");
    const download = el("button", "small", T("web_piece_download"));
    download.addEventListener("click", () => fetchPiece(reader, piece.index, false, download));
    const open = el("button", "small", T("web_piece_open"));
    open.addEventListener("click", () => fetchPiece(reader, piece.index, true, open));
    actions.append(download, open);
    row.append(actions);
    table.append(row);
  }
  results.append(table);
}

async function fetchPiece(reader, index, asInput, button) {
  button.disabled = true;
  try {
    const piece = await post("/api/file/piece", { ...currentPayload(), options: { reader, index } });
    asInput ? adoptPiece(piece) : saveBytes(piece);
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    button.disabled = false;
  }
}

async function loadSolvePiece(name, button) {
  button.disabled = true;
  setStatus(T("web_running"));
  try {
    const options = { piece: name, depth: $("solve-depth").value, seconds: $("solve-seconds").value };
    adoptPiece(await post("/api/solve/piece", { ...currentPayload(), options }));
    setStatus(T("web_piece_loaded", { name }));
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    button.disabled = false;
  }
}

// A piece becomes the input, exactly as if it had been dropped in the box.
function adoptPiece(piece) {
  state.file = { name: piece.name, b64: piece.data_b64, size: piece.size };
  state.files = [state.file];
  $("file-name").textContent = piece.name + " (" + piece.size + " " + T("web_bytes") + ")";
  $("file-info").classList.remove("hidden");
  $("input-text").disabled = true;
  schedulePreview();
}

function saveBytes(piece) {
  const binary = atob(piece.data_b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  link.download = piece.name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function commandLine(command) {
  const line = el("div", "command");
  line.append(el("code", "", command));
  line.append(copyButton(T("web_copy"), () => command));
  return line;
}


function renderFile(answer) {
  const results = $("results");
  const head = el("div", "file-head");
  head.append(el("strong", "", answer.label || answer.reader));
  head.append(
    el("span", "dim", "  " + T("web_file_read_by") + " " + (answer.command || answer.reader)
      + (answer.sniffed ? "" : " (forced)")),
  );
  results.append(head);

  for (const flag of answer.flags || []) {
    const line = el("div", "flag");
    line.append(el("strong", "", "flag: "), el("span", "", flag));
    line.append(copyButton(T("web_copy"), () => flag));
    results.append(line);
  }
  for (const section of answer.sections || []) renderSection(section);
  if (answer.notes && answer.notes.length) renderNotes(answer.notes);
  for (const command of answer.commands || []) {
    const line = el("div", "command");
    line.append(el("code", "", command));
    line.append(copyButton(T("web_copy"), () => command));
    results.append(line);
  }
}

function renderSection(section) {
  const results = $("results");
  if (section.title) results.append(el("h3", "", section.title));
  if (section.kind === "facts") {
    const facts = el("table", "facts");
    for (const [name, value] of section.rows) {
      const row = el("tr");
      row.append(el("td", "dim", name), el("td", "", value));
      facts.append(row);
    }
    results.append(facts);
    return;
  }
  if (section.kind === "table") {
    if (!section.rows.length) return;
    const node = el("table", "grid");
    const header = el("tr");
    for (const column of section.columns) header.append(el("th", "", column));
    node.append(header);
    for (const cells of section.rows) {
      const row = el("tr");
      for (const cell of cells) row.append(el("td", "", cell));
      node.append(row);
    }
    results.append(node);
    if (section.total > section.rows.length) {
      results.append(el("div", "dim", T("web_file_total")
        .replace("{shown}", section.rows.length).replace("{total}", section.total)));
    }
    return;
  }
  // "text": a block, with the button that makes it the next input.
  const block = el("pre", section.code ? "code" : "", section.text);
  results.append(block);
  const buttons = el("div", "row");
  buttons.append(copyButton(T("web_copy"), () => section.text));
  const next = el("button", "small", T("web_next_input"));
  next.addEventListener("click", () => useTextAsInput(section.text));
  buttons.append(next);
  results.append(buttons);
}

// --------------------------------------------------------------------- CRC32
function renderCrc(report) {
  const results = $("results");
  results.append(el("h3", "", "CRC32 " + report.target
    + (report.length ? " of " + report.length + " byte(s)" : "")));
  if (report.results && report.results.length) {
    const node = el("table", "grid");
    const header = el("tr");
    for (const column of ["content", "hex", T("web_crc_found_by"), "why"]) {
      header.append(el("th", "", column));
    }
    node.append(header);
    for (const result of report.results) {
      const row = el("tr");
      const first = el("td", result.exact ? "good" : "maybe", result.text);
      row.append(first, el("td", "", result.hex), el("td", "", result.method), el("td", "", result.note));
      node.append(row);
    }
    results.append(node);
    const best = report.results[0];
    const buttons = el("div", "row");
    buttons.append(copyButton(T("web_copy"), () => best.text));
    const next = el("button", "small", T("web_next_input"));
    next.addEventListener("click", () => useTextAsInput(best.text));
    buttons.append(next);
    results.append(buttons);
  }
  if (report.notes && report.notes.length) renderNotes(report.notes);
}

// ---------------------------------------------------------------------- Docs
// The documents ship inside the package (ctfc/data/*.md), not in docs/, so this
// works from an installed copy with no network and no repository - which is the
// only state that matters on the day of a CTF.
async function showDoc(name) {
  try {
    const answer = await (await fetch("/api/docs/" + encodeURIComponent(name || "how-it-works"))).json();
    const root = el("div", "");
    root.append(renderMarkdown(answer.markdown));
    const terminal = el("p", "dim", T("web_docs_terminal"));
    root.append(el("h3", "", T("web_tab_docs")), terminal);
    $("results").replaceChildren(root);
    renderToolList(root);
  } catch (error) {
    setStatus(error.message, true);
  }
}

// `ctfc tools --list` in the page: every external tool the advice can name,
// whether this machine has it, and how to get it.
async function renderToolList(root) {
  let answer;
  try {
    answer = await (await fetch("/api/tools/list")).json();
  } catch (error) {
    return;
  }
  root.append(el("h3", "", T("web_tools_list")));
  const table = el("table", "facts");
  for (const tool of answer.tools || []) {
    const row = el("tr");
    let state = tool.kind === "online" ? T("web_tool_online") : T("web_tool_local");
    if (tool.kind === "local") state = tool.available ? T("web_tool_installed") : T("web_tool_missing");
    row.append(el("td", "", tool.name), el("td", tool.available ? "" : "dim", state));
    row.append(el("td", "dim", tool.available ? tool.notes : tool.install || tool.notes));
    table.append(row);
  }
  root.append(table);
}

// ---------------------------------------------------------------- Signatures
function renderSignatures(report) {
  const results = $("results");
  const facts = el("table", "facts");
  for (const [name, value] of [
    ["signatures read", report.signatures],
    ["group", report.curve || report.order],
    ["reused nonces", (report.groups || []).length],
  ]) {
    if (value === undefined || value === null || value === "") continue;
    const row = el("tr");
    row.append(el("td", "dim", name), el("td", "", String(value)));
    facts.append(row);
  }
  results.append(facts);
  for (const recovery of report.recoveries || []) {
    const card = el("div", "card good");
    card.append(el("div", "label", "private key recovered"));
    card.append(el("pre", "code", recovery.private_key));
    if (recovery.nonce) card.append(el("div", "dim", "nonce k = " + recovery.nonce));
    if (recovery.verified) card.append(el("div", "dim", "verified against the public key"));
    card.append(copyButton(T("web_copy"), () => recovery.private_key));
    results.append(card);
  }
  if (report.notes && report.notes.length) renderNotes(report.notes);
  if (report.python) {
    results.append(el("h3", "", "reproduce it"));
    results.append(el("pre", "code", report.python));
  }
}

// -------------------------------------------------------------------- Search
// A regex over the bytes, or a flag hunt - which is deliberately not the same
// request: a flag may be base64 at any of three alignments, so the server goes
// through find_flags rather than matching the text you typed.
async function runSearch(flagsOnly) {
  const pattern = flagsOnly ? "" : $("search-pattern").value.trim();
  const scope = $("search-scope").value;
  const options = { pattern, ignore_case: $("search-case").checked };
  if (scope === "result") {
    const text = $("results").textContent || "";
    if (!text.trim()) {
      setStatus(T("web_search_none"), true);
      return;
    }
    options.text = text;
  }
  setStatus("...");
  try {
    const answer = await post("/api/search", { ...currentPayload(), options });
    renderSearch(answer);
    setStatus("");
  } catch (error) {
    setStatus(error.message, true);
  }
}

function renderSearch(answer) {
  const results = $("results");
  results.replaceChildren();
  results.append(el("h3", "", T("web_search") + " — " + answer.source + " (" + answer.length + " bytes)"));
  if (answer.searched && answer.searched.length) {
    results.append(el("div", "dim", T("web_search_searched") + ": " + answer.searched.join("  |  ")));
  }
  if (!answer.matches.length) {
    results.append(el("p", "", T("web_search_none")));
  } else {
    const table = el("table", "grid");
    const header = el("tr");
    for (const column of [T("web_search_offset"), "how", "match", "context"]) {
      header.append(el("th", "", column));
    }
    table.append(header);
    for (const match of answer.matches) {
      const row = el("tr");
      row.append(
        el("td", "", match.hex_offset),
        el("td", "dim", match.how),
        el("td", "good", match.text),
        el("td", "", match.context),
      );
      table.append(row);
    }
    results.append(table);
    const first = answer.matches[0];
    results.append(copyButton(T("web_copy"), () => answer.matches.map((m) => m.text).join("\n")));
    const next = el("button", "small", T("web_next_input"));
    next.addEventListener("click", () => useTextAsInput(first.text));
    results.append(next);
  }
  if (answer.notes && answer.notes.length) renderNotes(answer.notes);
}
