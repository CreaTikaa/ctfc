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
  file: null,       // {name, b64, size} when a file was dropped
  job: null,        // id of the background job currently running
};

// Tabs that are built, and how they run: "sync" waits for the answer,
// "job" runs in the background with progress and a Cancel button.
const TOOLS = {
  auto: "job",
  detect: "sync",
  xor: "job",
  sym: "job",
  lens: "sync",
  rsa: "job",
  hash: "sync",
};

// Tabs that have their own options panel (#options-<tab>).
const OPTION_PANELS = ["xor", "sym", "rsa", "hash"];

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
function currentPayload() {
  if (state.file) return { data_b64: state.file.b64, name: state.file.name };
  // Code Lens and Hash want the raw text: neither a script nor a hash is decoded.
  const format = state.tab === "lens" || state.tab === "hash" ? "text" : $("format").value;
  return { input: $("input-text").value, format };
}

// Options of the active tab.
function currentOptions() {
  if (state.tab === "xor") {
    return {
      key: $("xor-key").value,
      keylen: $("xor-keylen").value,
      crib: $("xor-crib").value,
      other: $("xor-other").value,
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
      attack: $("rsa-attack").checked,
      seconds: $("rsa-seconds").value,
    };
  }
  if (state.tab === "hash") {
    return { no_passwords: $("hash-no-passwords").checked };
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
    const payload = currentPayload();
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
  if (!payload.data_b64 && !payload.input) {
    setStatus(T("web_empty_input"), true);
    return;
  }
  payload.options = currentOptions();
  const tab = state.tab;
  $("run").disabled = true;
  setStatus(T("web_running"));
  $("results").replaceChildren();
  try {
    const answer = TOOLS[tab] === "job" ? await runJob(tab, payload) : await post("/api/" + tab, payload);
    if (answer) showAnswer(tab, answer);
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
  if (tab === "rsa") {
    renderRsa(answer);
    setStatus(answer.budget || "");
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

  // Output: text view if readable, otherwise hexdump. A button switches views.
  const bytes = hexToBytes(candidate.data_hex);
  const readable = isReadable(candidate.data_text);
  const output = el("pre", "output");
  let showingHex = !readable;
  const drawOutput = () => {
    output.textContent = showingHex ? hexdump(bytes, 4096) : candidate.data_text;
  };
  drawOutput();
  card.append(output);

  const actions = el("div", "actions");
  actions.append(copyButton(T("web_copy"), () => (showingHex ? candidate.data_hex : candidate.data_text)));

  const viewButton = el("button", "small", showingHex ? T("web_view_text") : T("web_view_hex"));
  viewButton.addEventListener("click", () => {
    showingHex = !showingHex;
    viewButton.textContent = showingHex ? T("web_view_text") : T("web_view_hex");
    drawOutput();
  });
  actions.append(viewButton);

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
  }

  const nextButton = el("button", "small", T("web_next_input"));
  nextButton.addEventListener("click", () => useAsInput(candidate, readable));
  actions.append(nextButton);
  return card;
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

// ---------------------------------------------------------------- file input
function loadFile(file) {
  const reader = new FileReader();
  reader.onload = () => {
    const bytes = new Uint8Array(reader.result);
    state.file = { name: file.name, b64: bytesToBase64(bytes), size: bytes.length };
    $("file-name").textContent = file.name + " (" + bytes.length + " " + T("web_bytes") + ")";
    $("file-info").classList.remove("hidden");
    $("input-text").disabled = true;
    schedulePreview();
  };
  reader.readAsArrayBuffer(file);
}

function clearFile() {
  state.file = null;
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
  setStatus("");
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

  fetch("/api/health").then((r) => r.json()).then((health) => {
    $("version").textContent = "v" + health.version;
    $("offline-badge").classList.toggle("hidden", !health.offline);
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
    if (event.target.files[0]) loadFile(event.target.files[0]);
  });
  zone.addEventListener("dragover", (event) => {
    event.preventDefault();
    zone.classList.add("over");
  });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (event) => {
    event.preventDefault();
    zone.classList.remove("over");
    if (event.dataTransfer.files[0]) loadFile(event.dataTransfer.files[0]);
  });
  $("file-clear").addEventListener("click", () => {
    clearFile();
    schedulePreview();
  });
}

init();
