// Remote MCP (authless, single-file) with cloud TS execution
// - Transports: HTTP streamable (/mcp) + SSE (/sse)
// - No external storage or auth. Purely utility-focused.
// - Tools for LLMs: run_ts_cloud (cloud code exec for TS/JS-like snippets),
//   summarize/chunk, crawl & scrape, http.fetch, url.parse, json.pick,
//   markdown.table, csv.parse, base64, crypto, zip, calc, time.now, uuid.v4

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { McpAgent } from "agents/mcp";

// ---------- Types ----------
type Env = { MCP_OBJECT: DurableObjectNamespace<MyMCP> };

// ---------- Small Utils ----------
const STOPWORDS = new Set(
  [
    "the","a","an","and","or","of","to","in","on","for","at","by","with","as","is","are","was","were",
    "be","been","being","that","this","it","from","but","if","then","than","so","not","no","will","would",
    "can","could","should","do","does","did","have","has","had","about","into","over","under","between",
    "we","you","they","he","she","i","me","my","our","your","their","them","his","her","its"
  ]
);

function htmlToText(html: string, maxChars = 50_000): string {
  try {
    html = html.replace(/<script[\s\S]*?<\/script>/gi, "");
    html = html.replace(/<style[\s\S]*?<\/style>/gi, "");
    html = html.replace(/<\/?(noscript|svg|canvas|iframe|picture|source|video|audio)\b[^>]*>/gi, " ");
    html = html.replace(/<\/?[^>]+(>|$)/g, " ");
    html = html.replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<")
               .replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
    html = html.replace(/\s+/g, " ").trim();
    return html.slice(0, maxChars);
  } catch {
    return html.slice(0, maxChars);
  }
}

function sentenceSplit(text: string): string[] {
  return text
    .replace(/\s+/g, " ")
    .split(/(?<=[.!?])\s+(?=[A-Z0-9가-힣])/u)
    .map((s) => s.trim())
    .filter(Boolean);
}

function wordTokens(s: string): string[] {
  return (s.toLowerCase().match(/[a-z0-9가-힣]+/gu) ?? []).filter((w) => !STOPWORDS.has(w));
}

function summarizeExtractive(text: string, opt: { maxSentences: number; minSentenceLen: number; }) {
  const sents = sentenceSplit(text).filter((s) => s.length >= opt.minSentenceLen);
  if (sents.length <= opt.maxSentences) return sents;
  const freq = new Map<string, number>();
  for (const s of sents) for (const t of wordTokens(s)) freq.set(t, (freq.get(t) ?? 0) + 1);
  const score = (s: string) => wordTokens(s).reduce((a, t) => a + (freq.get(t) ?? 0), 0);
  const scored = sents.map((s, i) => ({ i, s, score: score(s) })).sort((a, b) => b.score - a.score || a.i - b.i);
  return scored.slice(0, opt.maxSentences).sort((a, b) => a.i - b.i).map((x) => x.s);
}

async function sha(alg: "SHA-256" | "SHA-512", data: string) {
  const buf = await crypto.subtle.digest(alg, new TextEncoder().encode(data));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function okText(text: string) {
  return { content: [{ type: "text", text }] };
}
function okJSON(obj: unknown) {
  return { content: [{ type: "text", text: JSON.stringify(obj, null, 2) }] };
}
function b64encode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  // @ts-ignore
  return btoa(bin);
}
function b64decodeToBytes(b64: string): Uint8Array {
  // @ts-ignore
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function compress(kind: "gzip" | "deflate", input: Uint8Array): Promise<Uint8Array> {
  // @ts-ignore
  const cs = new CompressionStream(kind);
  const stream = new Blob([input]).stream().pipeThrough(cs);
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}
async function decompress(kind: "gzip" | "deflate", input: Uint8Array): Promise<Uint8Array> {
  // @ts-ignore
  const ds = new DecompressionStream(kind);
  const stream = new Blob([input]).stream().pipeThrough(ds);
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}
function parseJSONObject(text: string): any {
  try { return JSON.parse(text); } catch { throw new Error("Invalid JSON text"); }
}
function pickPath(obj: any, path: string): any {
  const segs = path.match(/[^.[\]]+|\[\d+\]/g) ?? [];
  let cur = obj;
  for (const seg of segs) {
    const key = seg.startsWith("[") ? Number(seg.slice(1, -1)) : seg;
    if (cur == null || !(key in cur)) return undefined;
    cur = (cur as any)[key as any];
  }
  return cur;
}
function csvParseSimple(text: string): string[][] {
  const rows: string[][] = [];
  let i = 0, field = "", row: string[] = [], inQuotes = false;
  const pushField = () => { row.push(field); field = ""; };
  const pushRow = () => { rows.push(row); row = []; };
  while (i < text.length) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i += 2; continue; } inQuotes = false; i++; continue; }
      field += c; i++; continue;
    }
    if (c === '"') { inQuotes = true; i++; continue; }
    if (c === ",") { pushField(); i++; continue; }
    if (c === "\n") { pushField(); pushRow(); i++; continue; }
    if (c === "\r") { i++; continue; }
    field += c; i++;
  }
  pushField(); pushRow();
  return rows;
}
function arrayOfObjectsToMarkdownTable(arr: Record<string, any>[]) {
  if (!arr.length) return "| (empty) |\n|---|\n| |\n";
  const cols = Array.from(arr.reduce((s, o) => { Object.keys(o).forEach(k => s.add(k)); return s; }, new Set<string>()));
  const head = `| ${cols.join(" | ")} |`;
  const sep  = `| ${cols.map(() => "---").join(" | ")} |`;
  const body = arr.map(o => `| ${cols.map(c => String(o[c] ?? "")).join(" | ")} |`).join("\n");
  return [head, sep, body].join("\n");
}
function urlInfo(u: string) {
  const url = new URL(u);
  const params: Record<string, string> = {};
  url.searchParams.forEach((v, k) => (params[k] = v));
  return {
    href: url.href, protocol: url.protocol, host: url.host, hostname: url.hostname,
    port: url.port, pathname: url.pathname, search: url.search, hash: url.hash, params,
  };
}
function safeEvalMath(expr: string): number {
  if (!/^[0-9+\-*/%().\s^]*$/.test(expr)) throw new Error("Invalid characters in expression.");
  // eslint-disable-next-line no-new-func
  const out = new Function(`return (${expr.replace(/\^/g, "**")});`)();
  if (typeof out !== "number" || !Number.isFinite(out)) throw new Error("Non-finite result.");
  return out;
}
function extractEmails(text: string): string[] {
  const re = /[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
  return Array.from(new Set(text.match(re) ?? []));
}
function extractUrls(text: string): string[] {
  const re = /\bhttps?:\/\/[^\s)]+/g;
  return Array.from(new Set(text.match(re) ?? []));
}

// ---------- Naive TS → JS (fallback) ----------
function transpileTSNaive(ts: string): string {
  let s = ts;

  // remove import/export lines
  s = s.replace(/^\s*export\s+(default\s+)?/gm, "");
  s = s.replace(/^\s*import\s+[^;]+;?\s*$/gm, "");

  // remove interface blocks
  s = s.replace(/interface\s+\w+\s*{[\s\S]*?}/g, "");

  // remove type aliases
  s = s.replace(/type\s+\w+\s*=\s*[^;]+;/g, "");

  // remove implements in class
  s = s.replace(/implements\s+[^{]+/g, "");

  // remove :type annotations (naive)
  s = s.replace(/:\s*[\w\[\]{}<>,|&?:\s]+(?=[)=;,\n])/g, "");

  // strip generics after function/class name or const f = ( ... )<T>
  s = s.replace(/(\bfunction\s+\w+|\bclass\s+\w+|\bconst\s+\w+\s*=\s*\()\<[^>]*\>/g, "$1");

  // strip `as Type` / `satisfies Type`
  s = s.replace(/\s+as\s+[\w\[\]{}<>,|&?:\s]+/g, "");
  s = s.replace(/\s+satisfies\s+[\w\[\]{}<>,|&?:\s]+/g, "");

  return s;
}

// ---------- JS executor used by TS cloud runner ----------
async function runUserCodeJS(code: string, args?: any, timeoutMs = 10_000, allowFetch = true) {
  const logs: Array<{ level: string; msg: any[] }> = [];
  const fakeConsole = {
    log: (...a: any[]) => logs.push({ level: "log", msg: a }),
    info: (...a: any[]) => logs.push({ level: "info", msg: a }),
    warn: (...a: any[]) => logs.push({ level: "warn", msg: a }),
    error: (...a: any[]) => logs.push({ level: "error", msg: a }),
  };
  const safeFetch = allowFetch ? fetch : undefined;

  const wrapped = `"use strict"; return (async (ctx, {fetch, URL, crypto, console}) => { ${code}\n })`;
  // eslint-disable-next-line no-new-func
  const fn = new Function(wrapped)();
  const exec = fn(Object(args ?? {}), { fetch: safeFetch, URL, crypto, console: fakeConsole });

  const timed = Promise.race([
    exec,
    new Promise((_, rej) => setTimeout(() => rej(new Error("Execution timed out")), timeoutMs)),
  ]);

  let result: any;
  try { result = await timed; }
  catch (e: any) { return { error: String(e?.message || e), logs }; }

  let printable: any;
  try { printable = typeof result === "string" ? result : JSON.parse(JSON.stringify(result)); }
  catch { printable = String(result); }

  return { result: printable, logs };
}

// ---------- TS Cloud runner (native-try → transpile-fallback) ----------
async function runTSCloud(code: string, args: any, timeoutMs: number, allowFetch: boolean, returnTranspiled: boolean) {
  // 1) try "native" (i.e., if code is already JS-compatible TS, it will run)
  let first = await runUserCodeJS(code, args, timeoutMs, allowFetch);
  if (!first.error) {
    return { mode: "native", ...first };
  }

  // Heuristic: if syntax-ish error, try transpile fallback
  const err = String(first.error || "").toLowerCase();
  const maybeSyntax = /unexpected|identifier|token|missing|cannot use import statement|':/.test(err);

  if (!maybeSyntax) {
    return { mode: "native", ...first };
  }

  // 2) naive transpile → run again
  const js = transpileTSNaive(code);
  const second = await runUserCodeJS(js, args, timeoutMs, allowFetch);
  return returnTranspiled ? { mode: "transpiled", transpiled: js, ...second } : { mode: "transpiled", ...second };
}

// ---------- MCP Durable Object (no persistence) ----------
export class MyMCP extends McpAgent<Env, { noop: true }, {}> {
  server = new McpServer({ name: "Authless Utility Kit", version: "4.1.0" });

  async init() {
    // ---- Health / Time / Random / Math ----
    this.server.tool("ping", "Health-check with timestamp.", z.object({}), async () =>
      okJSON({ pong: true, ts: new Date().toISOString() })
    );

    this.server.tool(
      "time.now",
      "Get current time. Optional IANA timezone, e.g. Asia/Seoul",
      z.object({ timeZone: z.string().optional() }),
      async ({ timeZone }) => {
        const now = new Date();
        const formatted = new Intl.DateTimeFormat("en", { dateStyle: "full", timeStyle: "long", timeZone: timeZone || undefined }).format(now);
        return okJSON({ iso: now.toISOString(), formatted, timeZone: timeZone || "system/default" });
      }
    );

    this.server.tool("uuid.v4", "Create a random UUID v4.", z.object({}), async () =>
      okJSON({ uuid: crypto.randomUUID() })
    );

    this.server.tool("calc", "Evaluate (+ - * / % ^ and parentheses).", z.object({ expr: z.string() }), async ({ expr }) =>
      okJSON({ expr, result: safeEvalMath(expr) })
    );

    // ---- Encoding / Crypto / Zip ----
    this.server.tool(
      "crypto.hash",
      "Hash string with SHA-256 or SHA-512.",
      z.object({ algorithm: z.enum(["SHA-256", "SHA-512"]), text: z.string() }),
      async ({ algorithm, text }) => okJSON({ algorithm, hex: await sha(algorithm, text) })
    );

    this.server.tool("base64.encode", "Base64-encode UTF-8 text.", z.object({ text: z.string() }), async ({ text }) =>
      okJSON({ base64: btoa(unescape(encodeURIComponent(text))) })
    );

    this.server.tool("base64.decode", "Base64-decode to UTF-8 text.", z.object({ base64: z.string() }), async ({ base64 }) =>
      okJSON({ text: decodeURIComponent(escape(atob(base64))) })
    );

    this.server.tool(
      "zip.compress",
      "Compress input (base64 bytes) with gzip/deflate → base64.",
      z.object({ algorithm: z.enum(["gzip", "deflate"]), base64: z.string() }),
      async ({ algorithm, base64 }) => {
        const bytes = b64decodeToBytes(base64);
        const out = await compress(algorithm, bytes);
        return okJSON({ algorithm, base64: b64encode(out) });
      }
    );

    this.server.tool(
      "zip.decompress",
      "Decompress (gzip/deflate) base64 → base64 raw + UTF-8 preview (if decodable).",
      z.object({ algorithm: z.enum(["gzip", "deflate"]), base64: z.string() }),
      async ({ algorithm, base64 }) => {
        const bytes = b64decodeToBytes(base64);
        const out = await decompress(algorithm, bytes);
        let text: string | null = null;
        try { text = new TextDecoder().decode(out); } catch { text = null; }
        return okJSON({ algorithm, base64: b64encode(out), text });
      }
    );

    // ---- Web / HTTP / Crawl ----
    this.server.tool(
      "http.fetch",
      "HTTP request. Returns status, headers, text body (truncated).",
      z.object({
        url: z.string().url(),
        method: z.enum(["GET","POST","PUT","PATCH","DELETE","HEAD"]).default("GET"),
        headers: z.record(z.string()).optional(),
        body: z.string().optional(),
        maxBodyChars: z.number().int().positive().default(200_000),
        followRedirects: z.boolean().default(true),
      }),
      async ({ url, method, headers, body, maxBodyChars, followRedirects }) => {
        const res = await fetch(url, { method, headers, body, redirect: followRedirects ? "follow" : "manual" });
        const text = await res.text();
        const hdrs: Record<string, string> = {};
        res.headers.forEach((v, k) => (hdrs[k] = v));
        return okJSON({
          url: res.url, ok: res.ok, status: res.status, statusText: res.statusText,
          headers: hdrs, body: text.slice(0, maxBodyChars), truncated: text.length > maxBodyChars
        });
      }
    );

    this.server.tool(
      "web.scrape",
      "Fetch a page and extract readable text (quick HTML→text).",
      z.object({ url: z.string().url(), maxChars: z.number().int().positive().default(30_000) }),
      async ({ url, maxChars }) => {
        const res = await fetch(url);
        const html = await res.text();
        const text = htmlToText(html, maxChars);
        return okJSON({ url: res.url, ok: res.ok, status: res.status, excerpt: text, length: text.length });
      }
    );

    this.server.tool("url.parse", "Parse URL into parts/query.", z.object({ url: z.string().url() }), async ({ url }) =>
      okJSON(urlInfo(url))
    );

    this.server.tool(
      "crawl.fetch_many",
      "Fetch multiple URLs → short text excerpts (perExcerpt chars).",
      z.object({ urls: z.array(z.string().url()).min(1).max(10), perExcerpt: z.number().int().positive().default(2000) }),
      async ({ urls, perExcerpt }) => {
        const results: any[] = [];
        for (const u of urls) {
          try {
            const res = await fetch(u);
            const html = await res.text();
            results.push({ url: res.url, ok: res.ok, status: res.status, excerpt: htmlToText(html, perExcerpt) });
          } catch (e: any) {
            results.push({ url: u, ok: false, error: String(e?.message || e) });
          }
        }
        return okJSON({ count: results.length, results });
      }
    );

    this.server.tool(
      "crawl.summarize_many",
      "Fetch URLs and produce extractive summaries.",
      z.object({
        urls: z.array(z.string().url()).min(1).max(8),
        maxSentences: z.number().int().positive().max(8).default(5),
        minSentenceLen: z.number().int().positive().default(50),
        maxCharsPerPage: z.number().int().positive().default(20_000),
      }),
      async ({ urls, maxSentences, minSentenceLen, maxCharsPerPage }) => {
        const results: any[] = [];
        for (const u of urls) {
          try {
            const res = await fetch(u);
            const html = await res.text();
            const text = htmlToText(html, maxCharsPerPage);
            const summary = summarizeExtractive(text, { maxSentences, minSentenceLen });
            results.push({ url: res.url, ok: res.ok, status: res.status, summary });
          } catch (e: any) {
            results.push({ url: u, ok: false, error: String(e?.message || e) });
          }
        }
        return okJSON({ count: results.length, results });
      }
    );

    // ---- Text ops ----
    this.server.tool(
      "text.summarize",
      "Extractive summary into N sentences (simple frequency scoring).",
      z.object({ text: z.string(), maxSentences: z.number().int().positive().max(12).default(5), minSentenceLen: z.number().int().positive().default(40) }),
      async ({ text, maxSentences, minSentenceLen }) => okJSON({ sentences: summarizeExtractive(text, { maxSentences, minSentenceLen }) })
    );

    this.server.tool(
      "text.extract",
      "Extract emails and URLs.",
      z.object({ text: z.string() }),
      async ({ text }) => okJSON({ emails: extractEmails(text), urls: extractUrls(text) })
    );

    this.server.tool(
      "text.chunk",
      "Chunk large text into ~chunkSize chars with sentence boundary preference.",
      z.object({ text: z.string(), chunkSize: z.number().int().positive().default(4000), overlap: z.number().int().min(0).default(200) }),
      async ({ text, chunkSize, overlap }) => {
        const sents = sentenceSplit(text);
        const chunks: string[] = [];
        let cur = "";
        for (const s of sents) {
          if ((cur + " " + s).length > chunkSize && cur) {
            chunks.push(cur.trim());
            cur = cur.slice(Math.max(0, cur.length - overlap));
          }
          cur += (cur ? " " : "") + s;
        }
        if (cur.trim()) chunks.push(cur.trim());
        return okJSON({ count: chunks.length, chunks });
      }
    );

    // ---- JSON/CSV/MD utils ----
    this.server.tool("json.pick", "Pick value by path from JSON text.", z.object({ json: z.string(), path: z.string() }), async ({ json, path }) =>
      okJSON({ path, value: pickPath(parseJSONObject(json), path) })
    );

    this.server.tool("markdown.table", "Markdown table from JSON array of objects.", z.object({ json: z.string() }), async ({ json }) => {
      const arr = parseJSONObject(json);
      if (!Array.isArray(arr)) throw new Error("Input JSON must be an array of objects.");
      return okText(arrayOfObjectsToMarkdownTable(arr as any[]));
    });

    this.server.tool("csv.parse", "Naive CSV parser → rows.", z.object({ csv: z.string() }), async ({ csv }) =>
      okJSON({ rows: csvParseSimple(csv) })
    );

    // ---- CLOUD TS EXECUTION ----
    this.server.tool(
      "run_ts_cloud",
      "Execute TypeScript/JS-like code in the cloud. Tries native first, falls back to naive transpile. Returns {mode, result?, logs?, error?}. Code runs inside an async function with args accessible via 'ctx'.",
      z.object({
        code: z.string().describe("TS snippet. Example: 'type P={x:number}; const f=(p:P)=>p.x*2; return f({x:3});'"),
        args: z.record(z.any()).optional().describe("Variables accessible as 'ctx' inside your code."),
        timeoutMs: z.number().int().positive().max(60000).default(10000),
        allowFetch: z.boolean().default(true),
        returnTranspiled: z.boolean().default(false),
      }),
      async ({ code, args, timeoutMs, allowFetch, returnTranspiled }) => {
        const out = await runTSCloud(code, args, timeoutMs, allowFetch, returnTranspiled);
        return okJSON(out);
      }
    );
  }

  onStateUpdate(_: { noop: true }) { /* no-op */ }

  static infoResponse(): Response {
    const body =
`Authless Utility MCP
Endpoints:
  /mcp  - HTTP streamable MCP
  /sse  - SSE (legacy)

Tools:
  run_ts_cloud (cloud TS exec: native try → transpile fallback)
  ping, time.now, uuid.v4, calc,
  crypto.hash, base64.encode/decode, zip.compress/decompress,
  http.fetch, web.scrape, url.parse,
  crawl.fetch_many, crawl.summarize_many,
  text.summarize, text.extract, text.chunk,
  json.pick, markdown.table, csv.parse
No memory/notes/KV. Single-file deployment.`;
    return new Response(body, { status: 200, headers: { "content-type": "text/plain; charset=utf-8" } });
  }

  static serveFetch = MyMCP.serve("/mcp", { binding: "MCP_OBJECT" });
  static serveSseFetch = MyMCP.serveSSE("/sse", { binding: "MCP_OBJECT" });
}

// Cloudflare Worker entry
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET,POST,OPTIONS",
          "access-control-allow-headers": "content-type,authorization",
          "access-control-max-age": "86400",
        },
      });
    }

    if (url.pathname === "/mcp") return MyMCP.serveFetch.fetch(request, env, ctx);
    if (url.pathname === "/sse" || url.pathname === "/sse/message") return MyMCP.serveSseFetch.fetch(request, env, ctx);
    if (url.pathname === "/") return MyMCP.infoResponse();
    return new Response("Not Found", { status: 404 });
  },
};