import test from "node:test";
import assert from "node:assert/strict";
import { analyzeMessage } from "../analysis-engine.js";

test("detecta una campaña con urgencia, credenciales y dominio parecido", () => {
  const result = analyzeMessage({ sender: "Soporte Microsoft <alertas@micros0ft-login.xyz>", subject: "Acción requerida: cuenta suspendida", body: "Inicia sesión inmediatamente para verificar tu cuenta.", links: [{ text: "https://login.microsoft.com", href: "http://micros0ft-login.xyz/access" }] });
  assert.equal(result.level, "high"); assert.equal(result.score, 100);
  assert.ok(result.reasons.some((reason) => reason.id.startsWith("brand-")));
  assert.ok(result.reasons.some((reason) => reason.id.startsWith("mismatch-")));
});

test("mantiene riesgo bajo para un mensaje neutro sin enlaces", () => {
  const result = analyzeMessage({ sender: "ana@example.org", subject: "Reunión semanal", body: "Adjunto el orden del día de mañana.", links: [] });
  assert.equal(result.level, "low"); assert.equal(result.score, 0); assert.equal(result.reasons.length, 0);
});

test("detecta IP, punycode y MFA", () => {
  const result = analyzeMessage({ body: "Comparte tu código de verificación", links: [{ text: "Abrir", href: "https://192.168.1.8/login" }, { text: "Abrir", href: "https://xn--pple-43d.com" }] });
  assert.equal(result.level, "high");
  assert.ok(result.reasons.some((reason) => reason.title === "URL con dirección IP"));
  assert.ok(result.reasons.some((reason) => reason.title === "Dominio Punycode"));
});

test("no confunde el texto descriptivo de un enlace con una URL visible", () => {
  const result = analyzeMessage({
    sender: "noresponder@idealista.com",
    subject: "Resumen diario de nuevos anuncios",
    body: "Hola, te enviamos recomendaciones personalizadas.",
    links: [
      { text: "Piso en Cuesta de la Villa, Santa Úrsula", href: "https://www.idealista.com/inmueble/108673126/" },
      { text: "Descargar app", href: "https://idealista.onelink.me/3139118072/i38rtpc3" }
    ]
  });
  assert.equal(result.score, 0);
  assert.ok(!result.reasons.some((reason) => reason.id.startsWith("mismatch-")));
});

test("sí detecta cuando el texto visible es otro dominio", () => {
  const result = analyzeMessage({ links: [{ text: "login.microsoft.com", href: "https://evil.example/login" }] });
  assert.ok(result.reasons.some((reason) => reason.id.startsWith("mismatch-")));
});

test("clasifica como alto el aviso falso de borrado y pago", () => {
  const result = analyzeMessage({
    sender: "gustavoucar1984 <hetgiltuahh@pckdripvq.horizon-fauna.arrebennin.biz>",
    subject: "Aviso final. Todos los datos serán borrados",
    body: "Tu método de pago ha caducado. Actualiza tus datos de Apple.",
    links: [{ text: "Continuar", href: "https://storage.googleapis.com/example/index.html" }]
  });
  assert.equal(result.level, "high");
  assert.ok(result.score >= 80);
  assert.ok(result.reasons.some((reason) => reason.id === "compound-campaign"));
  assert.ok(!result.reasons.some((reason) => reason.id.startsWith("brand-google-")));
});

test("clasifica como alto el falso bloqueo con renovación gratis", () => {
  const result = analyzeMessage({
    sender: "<lsoyebm.65.4922436@vkg.adzbyqotsrrje.us>",
    subject: "¡Hemos bloqueado tu cuenta! Tus fotos y videos serán eliminados. ¡Renueva tu suscripción gratis!",
    body: "Reactiva tu cuenta ahora.",
    links: [{ text: "Renovar", href: "https://storage.googleapis.com/example/renew.html" }]
  });
  assert.equal(result.level, "high");
  assert.ok(result.score >= 80);
  assert.ok(result.reasons.some((reason) => reason.id === "threat"));
  assert.ok(result.reasons.some((reason) => reason.id === "suspicious-sender-shape"));
});

test("no marca googleapis como typosquatting de Google", () => {
  const result = analyzeMessage({ links: [{ text: "Abrir documento", href: "https://storage.googleapis.com/bucket/file" }] });
  assert.ok(!result.reasons.some((reason) => reason.id.startsWith("brand-google-")));
});

test("clasifica como alto la falsa pérdida de fotos de Cloud Storage", () => {
  const result = analyzeMessage({
    sender: "AccountSecurity—Cloud <kfmuutlwbhh@oleqhfkap.port.55td.snourtenal.me>",
    subject: "Your photos and videos will be gone by end of day",
    body: "URGENT ACCOUNT NOTICE — IMMEDIATE ACTION REQUIRED. Cloud Storage. Renewal Failed. Renew your subscription.",
    links: [{ text: "Renew now", href: "https://storage.googleapis.com/example/renew" }]
  });
  assert.equal(result.level, "high");
  assert.ok(result.score >= 80);
  assert.ok(result.reasons.some((reason) => reason.id === "suspicious-sender-shape"));
  assert.ok(result.reasons.some((reason) => reason.id === "subscription-lure"));
  assert.ok(result.reasons.some((reason) => reason.id === "compound-campaign"));
});

test("eleva a medio una promoción con identidad y dominio incongruentes", () => {
  const result = analyzeMessage({
    sender: "Starscope <haacapvigjt@tnssvbcyu.eco-friendly.eachalingi.my.id>",
    subject: "El Descuento de Starscope Acaba de Activarse",
    body: "Starscope Monocular Telescope. Discount just activated.",
    links: [{ text: "Ver descuento", href: "https://example.invalid/offer" }]
  });
  assert.equal(result.level, "medium");
  assert.ok(result.score >= 35);
  assert.ok(result.reasons.some((reason) => reason.id === "claimed-identity-mismatch"));
  assert.ok(result.reasons.some((reason) => reason.id === "promotion-lure"));
});
