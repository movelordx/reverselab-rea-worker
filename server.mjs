import http from "node:http";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, extname, join } from "node:path";
import { pipeline } from "node:stream/promises";
import { spawn } from "node:child_process";

const PORT = Number(process.env.PORT || 10000);
const SECRET = process.env.WORKER_SHARED_SECRET || "";
const CALLBACK_HOST_SUFFIX = process.env.CALLBACK_HOST_SUFFIX || ".floot.app";
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_BYTES || 100 * 1024 * 1024);
const MAX_JOB_MS = Number(process.env.MAX_JOB_MS || 12 * 60 * 1000);
const CONCURRENCY = Math.max(1, Number(process.env.WORKER_CONCURRENCY || 1));

if (SECRET && SECRET.length < 24) {
  console.error("When set, WORKER_SHARED_SECRET must have at least 24 characters.");
  process.exit(1);
}

const queue = [];
let active = 0;

function json(res, status, body) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify(body));
}

function authorized(req) {
  if (!SECRET) return true;
  const given = req.headers.authorization?.replace(/^Bearer\s+/i, "") || "";
  const a = Buffer.from(SECRET);
  const b = Buffer.from(given);
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 128 * 1024) throw new Error("request body too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function validateJob(input) {
  if (!input || typeof input !== "object") throw new Error("invalid job");
  for (const key of ["jobId", "downloadUrl", "originalName", "targetKind", "question", "callbackUrl", "callbackToken"]) {
    if (typeof input[key] !== "string" || !input[key]) throw new Error(`missing ${key}`);
  }
  const dl = new URL(input.downloadUrl);
  const cb = new URL(input.callbackUrl);
  if (dl.protocol !== "https:" || cb.protocol !== "https:") throw new Error("https URLs required");
  if (!dl.hostname.endsWith("amazonaws.com")) throw new Error("download host not allowed");
  if (!cb.hostname.endsWith(CALLBACK_HOST_SUFFIX)) throw new Error("callback host not allowed");
  if (!Number.isFinite(input.sizeBytes) || input.sizeBytes <= 0 || input.sizeBytes > MAX_FILE_BYTES) throw new Error("invalid file size");
  if (!new Set(["auto", "javascript", "dotnet", "wasm", "binary"]).has(input.targetKind)) throw new Error("invalid targetKind");
  if (input.question.length > 2000) throw new Error("question too long");
  return input;
}

async function callback(job, payload) {
  const response = await fetch(job.callbackUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ json: { jobId: job.jobId, callbackToken: job.callbackToken, workerJobId: job.workerJobId, ...payload } }),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`callback HTTP ${response.status}`);
}

function enqueue(job) {
  queue.push(job);
  drain();
}

function drain() {
  while (active < CONCURRENCY && queue.length) {
    const job = queue.shift();
    active++;
    processJob(job).catch((error) => console.error("job failed", job.jobId, error)).finally(() => {
      active--;
      drain();
    });
  }
}

async function downloadTo(url, output, expectedSize) {
  const response = await fetch(url, { signal: AbortSignal.timeout(90_000), redirect: "error" });
  if (!response.ok || !response.body) throw new Error(`download HTTP ${response.status}`);
  const contentLength = Number(response.headers.get("content-length") || 0);
  if (contentLength && contentLength > MAX_FILE_BYTES) throw new Error("remote file exceeds limit");
  await pipeline(response.body, createWriteStream(output, { flags: "wx" }));
  const actual = (await stat(output)).size;
  if (actual > MAX_FILE_BYTES) throw new Error("downloaded file exceeds limit");
  if (expectedSize && actual !== expectedSize) throw new Error(`size mismatch: expected ${expectedSize}, received ${actual}`);
  return actual;
}

async function runCommand(args, outputPath, cwd) {
  return await new Promise((resolve, reject) => {
    const child = spawn("rea", args, { cwd, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, REA_ANALYSIS_PROVIDER: "ghidra" } });
    const out = createWriteStream(outputPath, { flags: "wx" });
    let stderr = "";
    let processDone = false;
    let streamDone = false;
    let exitCode = null;
    let exitSignal = null;
    let settled = false;
    const timer = setTimeout(() => child.kill("SIGKILL"), MAX_JOB_MS);
    const maybeFinish = () => {
      if (settled || !processDone || !streamDone) return;
      settled = true;
      clearTimeout(timer);
      if (exitCode === 0) resolve({ code: exitCode, stderr });
      else reject(new Error(`rea ${args[0]} failed (${exitCode ?? exitSignal}): ${stderr.slice(-2000)}`));
    };
    child.stdout.pipe(out);
    child.stderr.on("data", (chunk) => { if (stderr.length < 64_000) stderr += chunk.toString(); });
    child.on("error", (error) => { if (!settled) { settled = true; clearTimeout(timer); reject(error); } });
    child.on("close", (code, signal) => { processDone = true; exitCode = code; exitSignal = signal; maybeFinish(); });
    out.on("finish", () => { streamDone = true; maybeFinish(); });
    out.on("error", (error) => { if (!settled) { settled = true; clearTimeout(timer); reject(error); } });
  });
}

function pickSeeds(question) {
  const stop = new Set(["quero","entender","como","funciona","funcionar","sistema","qual","quais","onde","para","uma","uns","das","dos","com","sem","que","isso","essa","esse","esta","está","the","how","what","with","from","this","that","and"]);
  return [...new Set(question.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").match(/[a-z0-9_.-]{4,}/g) || [])]
    .filter((word) => !stop.has(word))
    .sort((a, b) => b.length - a.length)
    .slice(0, 2);
}

async function sha256File(path) {
  const data = await readFile(path);
  return createHash("sha256").update(data).digest("hex");
}

async function detectFormat(path, name) {
  const data = await readFile(path);
  const lower = name.toLowerCase();
  if (data.length >= 4 && data[0] === 0x00 && data[1] === 0x61 && data[2] === 0x73 && data[3] === 0x6d) return "WebAssembly (WASM)";
  if (data.length >= 4 && data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46) return "ELF";
  if (data.length >= 2 && data[0] === 0x4d && data[1] === 0x5a) return lower.endsWith(".dll") ? "PE / DLL" : "PE / Windows executable";
  if (lower.endsWith(".asar")) return "Electron ASAR";
  return extname(lower).replace(".", "").toUpperCase() || "artefato genérico";
}

function collectInteresting(value, limit = 30) {
  const out = [];
  const seen = new Set();
  const visit = (node, path = "") => {
    if (out.length >= limit || node == null) return;
    if (typeof node === "string") {
      const clean = node.replace(/\s+/g, " ").trim();
      if (clean.length >= 6 && clean.length <= 260 && !seen.has(clean)) {
        seen.add(clean);
        out.push(path ? `${path}: ${clean}` : clean);
      }
      return;
    }
    if (typeof node === "number" || typeof node === "boolean") return;
    if (Array.isArray(node)) {
      for (let i = 0; i < Math.min(node.length, 30); i++) visit(node[i], `${path}[${i}]`);
      return;
    }
    if (typeof node === "object") {
      const preferred = ["summary","name","path","kind","type","status","authority","limitation","limitations","function","symbol","route","api","module","framework","message","coverage"];
      const entries = Object.entries(node).sort(([a],[b]) => Number(preferred.includes(b)) - Number(preferred.includes(a)));
      for (const [key, child] of entries.slice(0, 80)) visit(child, path ? `${path}.${key}` : key);
    }
  };
  visit(value);
  return out;
}

async function parseJson(path) {
  const info = await stat(path);
  if (info.size > 32 * 1024 * 1024) return { oversized: true, size: info.size };
  return JSON.parse(await readFile(path, "utf8"));
}

async function analyzeWithRea(job, targetPath, workdir) {
  const outputs = [];
  const lower = job.originalName.toLowerCase();

  if (job.targetKind === "javascript" && lower.endsWith(".asar")) {
    const evidence = join(workdir, "javascript-evidence.json");
    await runCommand(["analyze-javascript-application", targetPath, "--json"], evidence, workdir);
    const viewInput = join(workdir, "javascript-view-input.json");
    const summary = join(workdir, "javascript-summary.json");
    await new Promise((resolve, reject) => {
      const child = spawn("jq", ["-c", "{source:{kind:\"inline\",evidence:.},view:{kind:\"summary\"}}", evidence], { stdio: ["ignore", "pipe", "pipe"] });
      const out = createWriteStream(viewInput, { flags: "wx" });
      child.stdout.pipe(out);
      let err = "";
      child.stderr.on("data", c => err += c.toString());
      child.on("close", code => code === 0 ? resolve() : reject(new Error(`jq failed: ${err}`)));
    });
    await runCommand(["inspect-analysis-view", viewInput, "--json"], summary, workdir);
    outputs.push({ command: "analyze-javascript-application + summary view", data: await parseJson(summary) });
    return outputs;
  }

  if (job.targetKind === "dotnet" || lower.endsWith(".dll")) {
    for (const [label, args] of [
      ["inspect-managed-artifact", ["inspect-managed-artifact", targetPath, "--json"]],
      ["inspect-managed-members", ["inspect-managed-members", targetPath, "--json"]],
    ]) {
      const out = join(workdir, `${label}.json`);
      await runCommand(args, out, workdir);
      outputs.push({ command: label, data: await parseJson(out) });
    }
    return outputs;
  }

  const overview = join(workdir, "native-overview.json");
  const providerArgs = job.targetKind === "wasm" ? ["analyze", targetPath, "--json"] : ["analyze", targetPath, "--provider", "ghidra", "--json"];
  await runCommand(providerArgs, overview, workdir);
  outputs.push({ command: providerArgs.join(" "), data: await parseJson(overview) });

  if (job.targetKind !== "wasm") {
    for (const seed of pickSeeds(job.question)) {
      const tracePath = join(workdir, `trace-${seed.replace(/[^a-z0-9_-]/g, "_")}.json`);
      try {
        await runCommand(["trace", targetPath, seed, "--provider", "ghidra", "--json"], tracePath, workdir);
        outputs.push({ command: `trace ${seed}`, data: await parseJson(tracePath) });
      } catch (error) {
        outputs.push({ command: `trace ${seed}`, error: error.message });
      }
    }
  }
  return outputs;
}

function buildReport(job, format, sha256, outputs) {
  const evidence = [];
  const extracted = [];
  const limitations = [];
  for (const item of outputs) {
    if (item.error) {
      limitations.push(`${item.command}: ${item.error.slice(0, 500)}`);
      continue;
    }
    evidence.push(`REA concluiu: ${item.command}`);
    if (item.data?.oversized) {
      evidence.push(`${item.command}: Evidence completo gerado (${(item.data.size / 1024 / 1024).toFixed(1)} MB); relatório usa somente a projeção disponível.`);
      continue;
    }
    extracted.push(...collectInteresting(item.data, 12));
  }
  const unique = [...new Set(extracted)].slice(0, 24);
  evidence.push(...unique.slice(0, 14));
  return {
    summary: `O worker isolado executou REA CLI${job.targetKind === "binary" || job.targetKind === "auto" ? " com Ghidra" : ""} sobre ${job.originalName}. A análise foi estática e orientada pelo objetivo informado, sem Codex, Claude, Gemini ou API paga de IA.`,
    architecture: [
      `Formato identificado pelo worker: ${format}`,
      `Objetivo solicitado: ${job.question}`,
      `Rotas de análise executadas: ${outputs.map(o => o.command).join("; ")}`,
      `Seeds determinísticos derivados da pergunta: ${pickSeeds(job.question).join(", ") || "nenhum"}`,
    ],
    evidence: [`SHA-256: ${sha256}`, ...evidence],
    limitations: [
      "O relatório é uma síntese determinística das evidências do REA; esta versão não usa um LLM para interpretar ambiguidades.",
      "Ausência de uma evidência no relatório não prova ausência no artefato; o Evidence completo pode ser maior que a projeção exibida.",
      ...limitations.slice(0, 5),
      "O serviço não tenta quebrar DRM, autenticação, anti-cheat ou licenciamento.",
    ],
    suggestedImplementation: [
      "Use as funções, módulos, rotas e relações evidenciadas como especificação comportamental, não como código a copiar.",
      "Implemente uma versão própria e teste o comportamento contra casos observáveis do produto original.",
      unique.length ? `Primeiros pontos para revisão manual: ${unique.slice(0, 4).join(" | ")}` : "Revise o Evidence do REA para selecionar funções ou módulos específicos para uma segunda análise.",
    ],
    technical: {
      sha256,
      detectedFormat: format,
      extractedStrings: unique.slice(0, 20),
      engine: "REA 4.1.0 + Ghidra 12.1.4",
    },
  };
}

async function processJob(job) {
  const workdir = await mkdtemp(join(tmpdir(), "reverselab-"));
  try {
    await callback(job, { status: "running" });
    const safeName = basename(job.originalName).replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 120) || "artifact.bin";
    const target = join(workdir, safeName);
    await downloadTo(job.downloadUrl, target, job.sizeBytes);
    const [sha256, format] = await Promise.all([sha256File(target), detectFormat(target, job.originalName)]);
    const outputs = await analyzeWithRea(job, target, workdir);
    const report = buildReport(job, format, sha256, outputs);
    await callback(job, { status: "completed", result: report });
  } catch (error) {
    console.error("analysis error", job.jobId, error);
    try { await callback(job, { status: "failed", errorMessage: error instanceof Error ? error.message.slice(0, 3900) : "worker failure" }); } catch (callbackError) { console.error("failure callback error", callbackError); }
  } finally {
    await rm(workdir, { recursive: true, force: true });
  }
}

async function health() {
  const output = join(tmpdir(), `rea-health-${randomUUID()}.json`);
  try {
    await runCommand(["providers", "--json"], output, tmpdir());
    const providers = await parseJson(output);
    return { ok: true, engine: "REA 4.1.0 + Ghidra 12.1.4", providers };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : "health failure" };
  } finally {
    await rm(output, { force: true });
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    if (req.method === "GET" && url.pathname === "/health") {
      const result = await health();
      return json(res, result.ok ? 200 : 503, result);
    }
    if (req.method === "POST" && url.pathname === "/jobs") {
      if (!authorized(req)) return json(res, 401, { error: "unauthorized" });
      const input = validateJob(await readJson(req));
      const workerJobId = randomUUID();
      const job = { ...input, workerJobId };
      try {
        await callback(job, { status: "running" });
      } catch {
        return json(res, 403, { error: "job callback validation failed" });
      }
      if (queue.length >= 20) return json(res, 429, { error: "worker queue full" });
      enqueue(job);
      return json(res, 202, { accepted: true, workerJobId, queueDepth: queue.length, active });
    }
    return json(res, 404, { error: "not found" });
  } catch (error) {
    return json(res, 400, { error: error instanceof Error ? error.message : "bad request" });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`ReverseLab worker listening on :${PORT}, concurrency=${CONCURRENCY}`);
});
