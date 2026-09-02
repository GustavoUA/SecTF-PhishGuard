import { analyzeMessage } from "./analysis-engine.js";
import { senderDomain, verifyDomain } from "./domain-verifier.js";

const $ = (id) => document.getElementById(id);
const sections = ["idle", "loading", "error", "result"];
let lastExtracted = null;
let lastBaseAnalysis = null;
const show = (name) => sections.forEach((id) => $(id).classList.toggle("hidden", id !== name));
const text = (id, value, fallback = "No disponible") => {
  const missing = value === undefined || value === null || value === "";
  $(id).textContent = missing ? fallback : String(value);
};

function render(extracted, analysis) {
  lastExtracted = extracted;
  $("score-card").className = `score-card ${analysis.level}`;
  const labels = { low: "RIESGO BAJO", medium: "RIESGO MEDIO", high: "RIESGO ALTO" };
  text("level-label", labels[analysis.level]); text("score", analysis.score); text("recommendation", analysis.recommendation);
  text("provider", extracted.provider); text("sender", extracted.sender); text("subject", extracted.subject); text("links-count", analysis.summary.linksAnalyzed, "0");
  const container = $("reasons"); container.replaceChildren();
  if (!analysis.reasons.length) {
    const empty = document.createElement("div"); empty.className = "no-reasons"; empty.textContent = "No se detectaron señales locales destacables."; container.append(empty);
  } else {
    analysis.reasons.forEach((reason) => {
      const card = document.createElement("article"); card.className = "reason";
      const title = document.createElement("h3"); title.textContent = `${reason.title} (+${reason.points})`;
      const detail = document.createElement("p"); detail.textContent = reason.detail; card.append(title, detail);
      if (reason.evidence) { const evidence = document.createElement("code"); evidence.textContent = reason.evidence; card.append(evidence); }
      container.append(card);
    });
  }
  show("result");
}

function addDomainRow(list, label, value) {
  const term = document.createElement("dt"); term.textContent = label;
  const detail = document.createElement("dd"); detail.textContent = value;
  list.append(term, detail);
}

function renderDomainReport(report) {
  const target = $("domain-status"); target.replaceChildren(); target.className = "domain-report";
  const title = document.createElement("h3"); title.textContent = `Dominio: ${report.registered}`;
  const list = document.createElement("dl"); list.className = "domain-grid";
  addDomainRow(list, "DNS", !report.dnsChecked ? "No disponible" : report.exists ? "Encontrado" : "No encontrado");
  addDomainRow(list, "Correo MX", !report.mxChecked ? "No disponible" : report.mx ? "Sí" : "No");
  addDomainRow(list, "SPF", report.spf ? "Publicado" : "No encontrado");
  addDomainRow(list, "DMARC", !report.dmarcChecked ? "No disponible" : report.dmarc ? "Publicado" : "No encontrado");
  addDomainRow(list, "DNSSEC", report.dnssec ? "Validado" : "No confirmado");
  addDomainRow(list, "Antigüedad", report.ageDays === null ? "No disponible" : `${report.ageDays} días`);
  addDomainRow(list, "Impacto", report.riskPoints ? `+${report.riskPoints} puntos` : "Sin aumento");
  target.append(title, list);
  if (report.warnings.length) {
    const warnings = document.createElement("ul"); warnings.className = "domain-warnings";
    report.warnings.forEach((warning) => { const item = document.createElement("li"); item.textContent = warning; warnings.append(item); });
    target.append(warnings);
  }
  const note = document.createElement("p"); note.className = "domain-note";
  note.textContent = report.partial ? "Comprobación parcial: algún servicio no respondió. Estos datos no certifican que el remitente sea legítimo." : "La existencia y antigüedad de un dominio no certifican que el remitente sea legítimo.";
  target.append(note);
}

function analysisWithDomainVerification(baseAnalysis, report) {
  if (!report || report.riskPoints <= 0) return baseAnalysis;
  const reasons = baseAnalysis.reasons.filter((reason) => reason.id !== "domain-verification");
  reasons.push({
    id: "domain-verification", points: report.riskPoints, title: "Verificación pública del dominio",
    detail: report.warnings.length ? report.warnings.join(" ") : "La comprobación pública encontró señales que requieren cautela.", evidence: report.registered
  });
  const score = Math.min(100, baseAnalysis.score + report.riskPoints);
  const level = score >= 65 ? "high" : score >= 35 ? "medium" : "low";
  const recommendation = level === "high"
    ? "No pulses enlaces ni respondas. Verifica la solicitud por un canal oficial independiente y notifícala al equipo de seguridad."
    : level === "medium"
      ? "Comprueba remitente y destino real de los enlaces. Confirma la solicitud por otro canal antes de actuar."
      : baseAnalysis.recommendation;
  return { ...baseAnalysis, score, level, recommendation, reasons: reasons.sort((a, b) => b.points - a.points) };
}

async function checkSenderDomain() {
  const button = $("verify-domain"); const domain = senderDomain(lastExtracted?.sender);
  if (!domain) { const target = $("domain-status"); target.className = "domain-report"; target.textContent = "No se pudo extraer el dominio del remitente."; return; }
  button.disabled = true; button.textContent = "Verificando dominio…";
  try {
    const report = await verifyDomain(domain);
    if (lastBaseAnalysis) render(lastExtracted, analysisWithDomainVerification(lastBaseAnalysis, report));
    renderDomainReport(report);
  }
  catch (error) { const target = $("domain-status"); target.className = "domain-report"; target.textContent = `No se pudo verificar: ${error.message}`; }
  finally { button.disabled = false; button.textContent = "Repetir verificación del dominio"; }
}

async function analyze() {
  show("loading");
  text("loading-message", "Analizando señales locales…");
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error("No hay una pestaña activa disponible.");
    const execution = await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content-extractor.js"] });
    const extracted = execution?.[0]?.result;
    if (!extracted?.ok) throw new Error(extracted?.error || "No se pudo leer el correo abierto.");
    lastBaseAnalysis = analyzeMessage(extracted);
    const domain = senderDomain(extracted.sender);
    let domainReport = null;
    if (domain) {
      text("loading-message", "Verificando el dominio del remitente…");
      domainReport = await verifyDomain(domain);
    }
    render(extracted, analysisWithDomainVerification(lastBaseAnalysis, domainReport));
    if (domainReport) renderDomainReport(domainReport);
  } catch (error) {
    const blocked = /Cannot access|chrome:\/\/|edge:\/\/|extensions gallery/i.test(error.message);
    text("error-message", blocked ? "Chrome/Edge no permite analizar esta página. Abre un correo en Gmail u Outlook Web." : error.message);
    show("error");
  }
}

$("analyze").addEventListener("click", analyze); $("retry").addEventListener("click", analyze); $("again").addEventListener("click", analyze);
$("verify-domain").addEventListener("click", checkSenderDomain);
