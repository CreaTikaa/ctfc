// Drive the real web UI in headless Chromium (dev tool, not shipped in the package).
//
// Why: the Flask test client checks the JSON; only a real browser runs app.js.
// Several bugs were only ever seen this way (HANDOFF section 5undecies).
//
// Usage (Node 22+ has WebSocket built in, nothing to install):
//   ctfc serve --port 8139 &
//   chromium --headless=new --remote-debugging-port=9333 --no-sandbox about:blank &
//   node scripts/browser_check.mjs <tab> <file> [url] [button label]
//
// It opens the page, "drops" <file> (sets state.file like a drop would), clicks
// the <tab> tab, presses Run, waits for the answer and prints the text of the
// results panel. Exit code 1 when the page shows an error status.

import { readFileSync } from "node:fs";
import { basename } from "node:path";

const [tab, file, url = "http://127.0.0.1:8139/", button = ""] = process.argv.slice(2);
if (!tab || !file) {
  console.error("usage: node scripts/browser_check.mjs <tab> <file> [url]");
  process.exit(2);
}

const targets = await (await fetch("http://127.0.0.1:9333/json/list")).json();
const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((resolve) => ws.addEventListener("open", resolve, { once: true }));

let nextId = 0;
const pending = new Map();
ws.addEventListener("message", (event) => {
  const message = JSON.parse(event.data);
  if (pending.has(message.id)) {
    pending.get(message.id)(message);
    pending.delete(message.id);
  }
});
function send(method, params = {}) {
  const id = ++nextId;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve) => pending.set(id, resolve));
}
async function evaluate(expression) {
  const answer = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (answer.result.exceptionDetails) throw new Error(JSON.stringify(answer.result.exceptionDetails));
  return answer.result.result.value;
}
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Chromium caches app.js between runs: always fetch the current one.
await send("Network.enable");
await send("Network.setCacheDisabled", { cacheDisabled: true });
await send("Page.navigate", { url });
await pause(1500);

const b64 = readFileSync(file).toString("base64");
const name = basename(file);
await evaluate(`
  state.file = { name: ${JSON.stringify(name)}, b64: ${JSON.stringify(b64)}, size: ${b64.length} };
  state.files = [state.file];
  document.querySelector('[data-tab="${tab}"]').click();
  document.getElementById("run").click();
  true;
`);
for (let i = 0; i < 240; i++) {
  await pause(500);
  const busy = await evaluate(`document.getElementById("run").disabled`);
  if (!busy) break;
}
const status = await evaluate(`document.getElementById("status").textContent`);
const text = await evaluate(`document.getElementById("results").innerText`);
console.log(text);
console.log("--- status: " + status);
if (button) {
  // Then click the first button with that label (e.g. "Open as input") and say
  // what the input box holds afterwards.
  await pause(1500); // the pieces list is fetched after the main result
  const clicked = await evaluate(`(() => {
    const target = [...document.querySelectorAll("button")].find((b) => b.textContent === ${JSON.stringify(button)});
    if (!target) return false;
    target.click();
    return true;
  })()`);
  await pause(4000);
  console.log("--- clicked " + JSON.stringify(button) + ": " + clicked);
  console.log("--- input now: " + (await evaluate(`document.getElementById("file-name").textContent`)));
  console.log("--- status: " + (await evaluate(`document.getElementById("status").textContent`)));
}
ws.close();
process.exit(/error/i.test(status) ? 1 : 0);
