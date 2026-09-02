/**
 * SecTF PhishGuard local analysis engine.
 * Browser-independent and reusable from an extension, website, PWA or Node tests.
 */

const BRAND_DOMAINS = Object.freeze({
  microsoft: ["microsoft.com", "live.com", "office.com", "outlook.com"],
  google: ["google.com", "gmail.com", "googleapis.com", "googleusercontent.com", "gstatic.com"],
  apple: ["apple.com", "icloud.com"],
  amazon: ["amazon.com", "amazon.es"],
  paypal: ["paypal.com"],
  netflix: ["netflix.com"],
  facebook: ["facebook.com", "meta.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com"],
  dropbox: ["dropbox.com"],
  docusign: ["docusign.com"],
  santander: ["santander.com", "bancosantander.es"],
  bbva: ["bbva.com", "bbva.es"],
  caixa: ["caixabank.es"],
  correos: ["correos.es"]
});

const RULES = {
  urgency: /\b(urgente|inmediatamente|(?:últim[oa] |aviso )final|ahora mismo|expira(?:rá)?|caduca(?:rá)?|suspendid[oa]|bloquead[oa]|acción requerida|plazo|24 horas|urgent|immediately|final notice|expires?|suspended|locked|action required)\b/i,
  credentials: /\b(contraseña|clave|credenciales|iniciar sesión|inicio de sesión|verifica(?:r|ción)? (?:tu |su )?(?:cuenta|identidad)|password|credentials?|sign[ -]?in|log[ -]?in|verify (?:your )?(?:account|identity))\b/i,
  payment: /\b(pago|factura|transferencia|bizum|tarjeta|cuenta bancaria|reembolso|premio|multa|payment|invoice|wire transfer|bank account|refund|prize|gift card)\b/i,
  mfa: /\b(código (?:de )?(?:verificación|seguridad|acceso)|doble factor|2fa|mfa|one[ -]?time (?:code|password)|otp|verification code|security code)\b/i,
  threat: /\b(eliminaremos|cerraremos|perderás|penalización|acceso no autorizado|actividad sospechosa|(?:datos|fotos|vídeos|videos|cuenta|archivos) (?:serán|seran|van a ser) (?:borrad[oa]s?|eliminad[oa]s?)|hemos bloqueado tu cuenta|cuenta (?:ha sido |está |esta )?(?:bloqueada|suspendida)|we will (?:close|delete)|(?:data|photos?|videos?|account|files?) (?:will be |will )?(?:deleted|removed|gone|lost)(?: by end of day)?|account (?:has been )?(?:blocked|locked|suspended)|unauthorized access|suspicious activity)\b/i,
  subscriptionLure: /\b(renueva(?:r)? (?:tu |su )?suscripci[oó]n|suscripci[oó]n gratis|reactiva(?:r)? (?:tu |su )?cuenta|renovaci[oó]n fallida|almacenamiento (?:lleno|agotado)|renew (?:your )?subscription|renewal failed|free (?:subscription|renewal)|reactivate (?:your )?account|storage (?:is )?(?:full|expired)|last chance|immediate action required)\b/i
  ,promotionLure: /\b(descuento (?:ha sido |acaba de )?(?:activado|activarse)|oferta exclusiva|reclama (?:tu |su )?(?:descuento|premio)|discount (?:has been |just )?(?:activated|unlocked)|exclusive (?:deal|offer)|claim (?:your )?(?:discount|reward)|limited[ -]time offer)\b/i
};

function normalizeText(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function addReason(reasons, id, points, title, detail, evidence) {
  if (reasons.some((reason) => reason.id === id)) return;
  reasons.push({ id, points, title, detail, evidence: evidence || "" });
}

function safeUrl(raw) {
  try {
    const value = String(raw || "").trim();
    const candidate = /^[a-z][a-z\d+.-]*:/i.test(value) ? value : `https://${value}`;
    const parsed = new URL(candidate);
    return ["http:", "https:"].includes(parsed.protocol) ? parsed : null;
  } catch {
    return null;
  }
}

function looksLikeVisibleUrl(raw) {
  const value = normalizeText(raw).replace(/[),.;]+$/, "");
  return /^(?:https?:\/\/|www\.)[^\s]+$/i.test(value) || /^[a-z\d](?:[a-z\d-]*[a-z\d])?(?:\.[a-z\d](?:[a-z\d-]*[a-z\d])?)+(?:[\/?#][^\s]*)?$/i.test(value);
}

function registrableApprox(hostname) {
  const parts = hostname.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const compound = new Set(["co.uk", "com.au", "com.br", "com.mx", "co.jp"]);
  const lastTwo = parts.slice(-2).join(".");
  return compound.has(lastTwo) ? parts.slice(-3).join(".") : lastTwo;
}

function levenshtein(a, b) {
  const left = String(a); const right = String(b);
  const row = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let i = 1; i <= left.length; i += 1) {
    let previous = row[0]; row[0] = i;
    for (let j = 1; j <= right.length; j += 1) {
      const saved = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (left[i - 1] === right[j - 1] ? 0 : 1));
      previous = saved;
    }
  }
  return row[right.length];
}

function isIp(hostname) {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return hostname.split(".").every((part) => Number(part) <= 255);
  return hostname.includes(":") && /^[\da-f:]+$/i.test(hostname);
}

function suspiciousSender(sender) {
  const match = String(sender || "").match(/<?([^<>\s@]+)@([^<>\s]+)>?/);
  if (!match) return null;
  const local = match[1].toLowerCase();
  const domain = match[2].toLowerCase().replace(/[>,;]$/, "");
  const looksGenerated = (label, minimum = 8) => {
    const compact = label.replace(/[^a-z]/g, "");
    if (compact.length < minimum) return false;
    const vowels = (compact.match(/[aeiou]/g) || []).length;
    return vowels / compact.length < 0.25 || /[bcdfghjklmnpqrstvwxyz]{5,}/.test(compact);
  };
  const labels = domain.split(".").slice(0, -1);
  const randomLabel = labels.find((label) => looksGenerated(label));
  const randomLocal = looksGenerated(local, 10);
  const numericLocal = /\d{5,}/.test(local) && local.length >= 12;
  return randomLabel || randomLocal || numericLocal ? { domain, evidence: `${local}@${domain}` } : null;
}

function claimedIdentityMismatch(sender, fullText) {
  const match = String(sender || "").match(/^\s*([^<]+?)\s*<[^<>\s@]+@([^<>\s]+)>/);
  if (!match) return null;
  const display = match[1].replace(/[^\p{L}\p{N} ._-]/gu, " ").trim();
  const domain = match[2].toLowerCase().replace(/[>,;]$/, "");
  const ignored = new Set(["account", "security", "cloud", "support", "team", "service", "notification", "noreply", "no-reply"]);
  const candidate = display.toLowerCase().split(/[\s._-]+/).find((word) => word.length >= 5 && !ignored.has(word));
  if (!candidate || !new RegExp(`\\b${candidate.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i").test(fullText)) return null;
  const compactDomain = domain.replace(/[^a-z\d]/g, "");
  return compactDomain.includes(candidate.replace(/[^a-z\d]/g, "")) ? null : { identity: candidate, domain };
}

function brandLookalike(hostname) {
  const registered = registrableApprox(hostname);
  const label = registered.split(".")[0].replace(/[-_]/g, "");
  const labels = hostname.split(".").slice(0, -1).flatMap((part) => [part, ...part.split(/[-_]/)]).filter(Boolean);
  for (const [brand, officialDomains] of Object.entries(BRAND_DOMAINS)) {
    if (officialDomains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))) continue;
    const distance = levenshtein(label, brand);
    const closeLabel = labels.some((part) => brand.length >= 5 && levenshtein(part, brand) <= 1);
    const containsBrand = labels.some((part) => part.includes(brand)) || label.includes(brand);
    if ((brand.length >= 5 && distance <= 1) || closeLabel || containsBrand) return { brand, registered };
  }
  return null;
}

function inspectLink(link, reasons) {
  const parsed = safeUrl(link.href || link.url);
  if (!parsed) {
    addReason(reasons, `invalid-url-${link.href}`, 8, "Enlace no válido", "El enlace no se pudo interpretar de forma segura.", link.href);
    return;
  }
  const host = parsed.hostname.toLowerCase();
  if (isIp(host)) addReason(reasons, `ip-${host}`, 22, "URL con dirección IP", "Los servicios legítimos rara vez piden iniciar sesión mediante una IP.", host);
  if (host.includes("xn--")) addReason(reasons, `punycode-${host}`, 24, "Dominio Punycode", "Puede representar caracteres visualmente parecidos a los de una marca.", host);
  if (parsed.protocol === "http:") addReason(reasons, `http-${host}`, 8, "Conexión sin HTTPS", "El enlace usa HTTP sin cifrado.", parsed.href);
  if (host.split(".").length >= 5) addReason(reasons, `subdomains-${host}`, 10, "Demasiados subdominios", "Una cadena larga puede ocultar cuál es el dominio real.", host);
  const suspiciousTld = /\.(?:zip|mov|top|xyz|click|work|support|live|cam|rest|gq|tk)$/i.test(host);
  if (suspiciousTld) addReason(reasons, `tld-${host}`, 10, "Extensión de dominio de riesgo", "Este tipo de dominio aparece con frecuencia en campañas temporales; no prueba fraude por sí solo.", host);
  const lookalike = brandLookalike(host);
  if (lookalike) addReason(reasons, `brand-${lookalike.brand}-${host}`, 28, "Posible suplantación de marca", `El dominio no es oficial, pero se parece a ${lookalike.brand}.`, host);

  const visible = looksLikeVisibleUrl(link.text) ? safeUrl(link.text) : null;
  if (visible && visible.hostname.toLowerCase() !== host) {
    addReason(reasons, `mismatch-${host}`, 25, "El destino no coincide con el enlace mostrado", `El texto apunta a ${visible.hostname}, pero el destino real es ${host}.`, `${link.text} → ${parsed.href}`);
  }
}

export function analyzeMessage(input = {}) {
  const sender = normalizeText(input.sender);
  const subject = normalizeText(input.subject);
  const body = normalizeText(input.body || input.text);
  const links = Array.isArray(input.links) ? input.links : [];
  const fullText = `${subject} ${body}`;
  const reasons = [];

  if (RULES.urgency.test(fullText)) addReason(reasons, "urgency", 12, "Lenguaje de urgencia", "El mensaje intenta acelerar una decisión y reducir la comprobación.");
  if (RULES.credentials.test(fullText)) addReason(reasons, "credentials", 22, "Solicitud relacionada con credenciales", "Pide iniciar sesión, verificar la cuenta o facilitar claves.");
  if (RULES.payment.test(fullText)) addReason(reasons, "payment", 18, "Petición o incentivo económico", "Menciona pagos, transferencias, facturas, premios o datos financieros.");
  if (RULES.mfa.test(fullText)) addReason(reasons, "mfa", 24, "Solicitud de código MFA", "Un código de acceso o verificación no debe compartirse con terceros.");
  if (RULES.threat.test(fullText)) addReason(reasons, "threat", 24, "Amenaza de bloqueo o pérdida de datos", "Presiona afirmando que la cuenta, los datos o los archivos serán bloqueados o eliminados.");
  if (RULES.subscriptionLure.test(fullText)) addReason(reasons, "subscription-lure", 16, "Cebo de suscripción o reactivación", "Promete una renovación gratuita o exige reactivar una cuenta, un patrón habitual de captación de clics.");
  if (RULES.promotionLure.test(fullText)) addReason(reasons, "promotion-lure", 12, "Cebo promocional", "Anuncia un descuento, recompensa u oferta activada para provocar una acción rápida. Puede ser spam legítimo o una campaña fraudulenta.");

  for (const link of links.slice(0, 100)) inspectLink(link, reasons);

  const senderDomain = (sender.match(/@([^>\s]+)/) || [])[1]?.toLowerCase().replace(/[>,;]$/, "");
  const oddSender = suspiciousSender(sender);
  if (oddSender) addReason(reasons, "suspicious-sender-shape", 16, "Remitente de aspecto generado", "El dominio o identificador contiene una secuencia inusual, frecuente en infraestructura desechable. No es una prueba por sí sola.", oddSender.evidence);
  const claimedIdentity = claimedIdentityMismatch(sender, fullText);
  if (claimedIdentity) addReason(reasons, "claimed-identity-mismatch", 18, "Identidad mostrada ajena al dominio", `El mensaje se presenta como ${claimedIdentity.identity}, pero el dominio del remitente es ${claimedIdentity.domain}. Puede tratarse de un proveedor externo o de suplantación.`, sender);
  if (senderDomain) {
    const mentionedBrand = Object.keys(BRAND_DOMAINS).find((brand) => new RegExp(`\\b${brand}\\b`, "i").test(`${sender} ${fullText}`));
    if (mentionedBrand && !BRAND_DOMAINS[mentionedBrand].some((domain) => senderDomain === domain || senderDomain.endsWith(`.${domain}`))) {
      addReason(reasons, `sender-brand-${mentionedBrand}`, 18, "Remitente ajeno a la marca mencionada", `El mensaje menciona ${mentionedBrand}, pero el remitente usa ${senderDomain}.`, sender);
    }
  }

  const strongIds = new Set(reasons.map((reason) => reason.id));
  const hasPressure = strongIds.has("urgency") || strongIds.has("threat");
  const hasAction = strongIds.has("credentials") || strongIds.has("payment") || strongIds.has("subscription-lure") || strongIds.has("mfa");
  const hasUntrustedOrigin = strongIds.has("suspicious-sender-shape") || reasons.some((reason) => reason.id.startsWith("sender-brand-") || reason.id.startsWith("brand-"));
  if (hasPressure && hasAction && hasUntrustedOrigin) {
    addReason(reasons, "compound-campaign", 18, "Combinación típica de campaña de phishing", "Coinciden presión, una llamada a actuar y un origen no confiable; juntas son mucho más significativas que por separado.");
  }

  const score = Math.min(100, reasons.reduce((sum, reason) => sum + reason.points, 0));
  const level = score >= 65 ? "high" : score >= 35 ? "medium" : "low";
  const recommendations = {
    high: "No pulses enlaces ni respondas. Verifica la solicitud por un canal oficial independiente y notifícala al equipo de seguridad.",
    medium: "Comprueba remitente y destino real de los enlaces. Confirma la solicitud por otro canal antes de actuar.",
    low: "No se detectaron señales fuertes, pero el análisis automático no garantiza que el mensaje sea seguro. Mantén la cautela."
  };
  return {
    score, level, reasons: reasons.sort((a, b) => b.points - a.points), recommendation: recommendations[level],
    summary: { sender, subject, bodyLength: body.length, linksAnalyzed: Math.min(links.length, 100) }
  };
}

export const internals = { levenshtein, registrableApprox, brandLookalike, safeUrl, looksLikeVisibleUrl, suspiciousSender, claimedIdentityMismatch };
