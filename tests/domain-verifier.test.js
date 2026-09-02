import test from "node:test";
import assert from "node:assert/strict";
import { ageInDays, registrableDomain, senderDomain, verificationRiskPoints } from "../domain-verifier.js";

test("extrae el dominio del remitente con nombre visible", () => {
  assert.equal(senderDomain("Starscope <offer@mailer.example.com>"), "mailer.example.com");
});

test("calcula dominios registrables con sufijos compuestos", () => {
  assert.equal(registrableDomain("promo.eachalingi.my.id"), "eachalingi.my.id");
  assert.equal(registrableDomain("login.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("www.example.com"), "example.com");
});

test("calcula antigüedad en días", () => {
  assert.equal(ageInDays(new Date("2026-01-01T00:00:00Z"), new Date("2026-01-31T12:00:00Z")), 30);
});

test("limita a 40 puntos el impacto de un dominio joven sin correo", () => {
  assert.equal(verificationRiskPoints({ exists: false, ageDays: 10, mx: false, dmarc: false }), 40);
  assert.equal(verificationRiskPoints({ exists: true, ageDays: 2000, mx: true, dmarc: true }), 0);
});

test("no penaliza comprobaciones que no respondieron", () => {
  assert.equal(verificationRiskPoints({ exists: false, ageDays: null, mx: false, dmarc: false, dnsChecked: false, mxChecked: false, dmarcChecked: false }), 0);
});
