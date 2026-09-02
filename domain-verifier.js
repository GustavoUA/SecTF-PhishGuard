const COMPOUND_SUFFIXES = new Set(["co.uk", "com.au", "com.br", "com.mx", "co.jp", "com.es", "org.es", "gob.es", "my.id"]);

export function normalizeDomain(value) {
  return String(value || "").trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

export function registrableDomain(hostname) {
  const parts = normalizeDomain(hostname).split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const lastTwo = parts.slice(-2).join(".");
  return COMPOUND_SUFFIXES.has(lastTwo) ? parts.slice(-3).join(".") : lastTwo;
}

export function senderDomain(sender) {
  const match = String(sender || "").match(/@([^<>\s,;]+)/);
  return match ? normalizeDomain(match[1]) : "";
}

async function dnsQuery(name, type) {
  const url = new URL("https://dns.google/resolve");
  url.searchParams.set("name", name);
  url.searchParams.set("type", type);
  url.searchParams.set("do", "1");
  const response = await fetch(url, { headers: { accept: "application/dns-json" }, cache: "no-store" });
  if (!response.ok) throw new Error(`DNS respondió ${response.status}`);
  return response.json();
}

function answers(result, type) {
  const typeCodes = { A: 1, MX: 15, TXT: 16, AAAA: 28 };
  return (result?.Answer || []).filter((answer) => answer.type === typeCodes[type]).map((answer) => String(answer.data || ""));
}

function registrationDate(rdap) {
  const event = (rdap?.events || []).find((item) => ["registration", "registered"].includes(item.eventAction));
  const date = event?.eventDate ? new Date(event.eventDate) : null;
  return date && !Number.isNaN(date.getTime()) ? date : null;
}

export function ageInDays(date, now = new Date()) {
  return date ? Math.max(0, Math.floor((now.getTime() - date.getTime()) / 86400000)) : null;
}

export function verificationRiskPoints(report) {
  let points = 0;
  if (report.dnsChecked !== false && !report.exists) points += 18;
  if (report.ageDays !== null && report.ageDays < 30) points += 20;
  else if (report.ageDays !== null && report.ageDays < 180) points += 12;
  if (report.mxChecked !== false && !report.mx) points += 6;
  if (report.dmarcChecked !== false && !report.dmarc) points += 4;
  return Math.min(40, points);
}

async function rdapQuery(domain) {
  const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    headers: { accept: "application/rdap+json, application/json" }, cache: "no-store", redirect: "follow"
  });
  if (!response.ok) throw new Error(`RDAP respondió ${response.status}`);
  return response.json();
}

export async function verifyDomain(rawDomain) {
  const host = normalizeDomain(rawDomain);
  const registered = registrableDomain(host);
  if (!host || !host.includes(".")) throw new Error("El dominio no es válido.");

  const [aResult, aaaaResult, mxResult, spfResult, dmarcResult, rdapResult] = await Promise.allSettled([
    dnsQuery(host, "A"), dnsQuery(host, "AAAA"), dnsQuery(registered, "MX"), dnsQuery(registered, "TXT"),
    dnsQuery(`_dmarc.${registered}`, "TXT"), rdapQuery(registered)
  ]);
  const fulfilled = (result) => result.status === "fulfilled" ? result.value : null;
  const a = answers(fulfilled(aResult), "A");
  const aaaa = answers(fulfilled(aaaaResult), "AAAA");
  const mx = answers(fulfilled(mxResult), "MX");
  const txt = answers(fulfilled(spfResult), "TXT");
  const dmarcTxt = answers(fulfilled(dmarcResult), "TXT");
  const rdap = fulfilled(rdapResult);
  const created = registrationDate(rdap);
  const ageDays = ageInDays(created);
  const exists = a.length > 0 || aaaa.length > 0 || mx.length > 0;
  const spf = txt.some((record) => /v=spf1/i.test(record));
  const dmarc = dmarcTxt.some((record) => /v=dmarc1/i.test(record));
  const dnssec = [aResult, aaaaResult, mxResult].some((result) => result.status === "fulfilled" && result.value?.AD === true);
  const dnsChecked = [aResult, aaaaResult, mxResult].some((result) => result.status === "fulfilled");
  const mxChecked = mxResult.status === "fulfilled";
  const dmarcChecked = dmarcResult.status === "fulfilled";
  const warnings = [];
  if (dnsChecked && !exists) warnings.push("No se encontraron registros DNS habituales.");
  if (ageDays !== null && ageDays < 30) warnings.push("Dominio registrado hace menos de 30 días.");
  else if (ageDays !== null && ageDays < 180) warnings.push("Dominio registrado hace menos de 6 meses.");
  if (mxChecked && !mx.length) warnings.push("No se encontraron servidores de correo MX.");
  if (dmarcChecked && !dmarc) warnings.push("No se encontró una política DMARC publicada.");

  const report = {
    host, registered, exists, mx: mx.length > 0, spf, dmarc, dnssec, dnsChecked, mxChecked, dmarcChecked,
    created: created ? created.toISOString() : null, ageDays, warnings,
    partial: [aResult, aaaaResult, mxResult, spfResult, dmarcResult, rdapResult].some((result) => result.status === "rejected")
  };
  report.riskPoints = verificationRiskPoints(report);
  return report;
}
