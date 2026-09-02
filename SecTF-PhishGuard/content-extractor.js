(() => {
  const clean = (value) => String(value || "").replace(/\s+/g, " ").trim();
  const absoluteHref = (anchor) => anchor.href || anchor.getAttribute("href") || "";
  const uniqueLinks = (root) => {
    const seen = new Set();
    return [...root.querySelectorAll("a[href]")].map((anchor) => ({
      text: clean(anchor.innerText || anchor.textContent),
      href: absoluteHref(anchor)
    })).filter((link) => {
      if (!/^https?:/i.test(link.href) || seen.has(link.href)) return false;
      seen.add(link.href); return true;
    }).slice(0, 100);
  };

  const host = location.hostname;
  let messageRoot = null; let sender = ""; let subject = ""; let provider = "";

  if (host === "mail.google.com") {
    provider = "Gmail";
    messageRoot = document.querySelector(".adn.ads:not([style*='display: none'])") || document.querySelector(".ii.gt")?.closest(".adn") || document.querySelector(".ii.gt");
    subject = clean(document.querySelector("h2.hP")?.textContent || document.querySelector("[data-thread-perm-id] h2")?.textContent);
    const senderEl = messageRoot?.querySelector(".gD[email], [email].g2, [data-hovercard-id]");
    const senderEmail = clean(senderEl?.getAttribute("email") || senderEl?.getAttribute("data-hovercard-id"));
    const senderName = clean(senderEl?.getAttribute("name") || messageRoot?.querySelector(".gD")?.getAttribute("name") || messageRoot?.querySelector(".gD")?.textContent || senderEl?.textContent);
    sender = senderEmail && senderName && senderName.toLowerCase() !== senderEmail.toLowerCase() ? `${senderName} <${senderEmail}>` : (senderEmail || senderName);
  } else if (/outlook\.(?:live|office)\.com$/.test(host) || host === "outlook.office365.com") {
    provider = "Outlook Web";
    messageRoot = document.querySelector("[role='main'] [aria-label*='Message body'], [role='main'] [aria-label*='Cuerpo del mensaje'], [role='main'] .allowTextSelection")?.closest("[role='document'], [role='main'], div") || document.querySelector("[role='main']");
    subject = clean(document.querySelector("[role='main'] h1, [role='main'] h2, [data-testid='message-subject']")?.textContent);
    const senderEl = document.querySelector("[role='main'] [data-testid='message-sender'], [role='main'] [title*='@'], [role='main'] [aria-label*='From:'], [role='main'] [aria-label*='De:']");
    sender = clean(senderEl?.getAttribute("title") || senderEl?.getAttribute("aria-label") || senderEl?.textContent);
  } else {
    return { ok: false, error: "Abre un correo en Gmail o Outlook Web antes de analizarlo." };
  }

  if (!messageRoot) return { ok: false, error: `No se encontró un correo abierto en ${provider}. Abre el mensaje completo y vuelve a intentarlo.` };
  const body = clean(messageRoot.innerText || messageRoot.textContent);
  if (!body) return { ok: false, error: "El correo está abierto, pero no se pudo leer su contenido visible." };
  return { ok: true, provider, sender, subject, body: body.slice(0, 100000), links: uniqueLinks(messageRoot) };
})();
