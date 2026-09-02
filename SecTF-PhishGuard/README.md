# SecTF PhishGuard

MVP gratuito y local-first para Chromium (Manifest V3). Analiza manualmente el correo abierto en Gmail y Outlook Web, calcula un **Risk Score 0–100** y explica las señales encontradas. No usa backend, telemetría, servicios de IA ni APIs externas.

## Instalación manual

### Chrome

1. Descomprime la carpeta si la recibiste como ZIP.
2. Abre `chrome://extensions`.
3. Activa **Modo de desarrollador**.
4. Pulsa **Cargar descomprimida**.
5. Selecciona la carpeta `SecTF-PhishGuard` (la que contiene `manifest.json`).
6. Opcional: fija la extensión desde el menú de extensiones.

### Microsoft Edge

1. Descomprime la carpeta si la recibiste como ZIP.
2. Abre `edge://extensions`.
3. Activa **Modo de desarrollador**.
4. Pulsa **Cargar desempaquetada** y selecciona `SecTF-PhishGuard`.

## Uso

1. Abre Gmail u Outlook Web y entra en un mensaje concreto.
2. Pulsa el icono de SecTF PhishGuard.
3. Pulsa **Analizar correo abierto**.
4. Revisa la puntuación, las razones y la recomendación.

El análisis se ejecuta al pulsar el botón. El contenido visible del mensaje permanece en el navegador y no se almacena.

Al analizar un mensaje, PhishGuard verifica automáticamente el dominio del remitente mediante Google Public DNS y RDAP antes de mostrar la puntuación final. Envía únicamente el nombre del dominio y no abre los enlaces del mensaje. Comprueba DNS, MX, SPF, DMARC, DNSSEC y antigüedad cuando los datos están disponibles. Las señales negativas pueden añadir hasta 40 puntos explicables al Risk Score; una consulta sin respuesta no penaliza, y los datos positivos nunca reducen el riesgo ni certifican que el correo sea legítimo. El botón permite repetir la verificación.

## Qué analiza

- Lenguaje de urgencia, amenazas y consecuencias negativas.
- Solicitudes de credenciales, inicio de sesión o verificación de cuenta.
- Pagos, transferencias, facturas, premios y datos financieros.
- Solicitudes de códigos MFA/2FA/OTP.
- URLs con IP, HTTP sin cifrar, Punycode y exceso de subdominios.
- Algunas extensiones de dominio usadas a menudo en campañas temporales.
- Enlaces cuyo texto visible parece una URL distinta al destino real.
- Typosquatting básico y uso engañoso de una lista local de marcas.
- Diferencia entre la marca mencionada y el dominio del remitente cuando puede extraerse.

## Privacidad y permisos mínimos

- `activeTab`: concede acceso temporal únicamente a la pestaña activa después de una acción del usuario.
- `scripting`: permite ejecutar el extractor local en esa pestaña al pulsar analizar.
- Acceso a `dns.google` y `rdap.org`: se utiliza exclusivamente cuando el usuario solicita verificar un dominio.

No hay `host_permissions`, acceso al historial, almacenamiento, cookies, identidad ni red. El código no realiza peticiones externas.

## Arquitectura

- `analysis-engine.js`: motor puro y desacoplado; recibe `{ sender, subject, body, links }` y devuelve score, nivel, razones y recomendación.
- `content-extractor.js`: extracción best-effort del correo visible en Gmail/Outlook.
- `popup.html`, `popup.css`, `popup.js`: interfaz y coordinación.
- `tests/`: pruebas unitarias del motor con Node.js, sin dependencias.

Para ejecutar las pruebas (opcional): `npm test`.

## Limitaciones conocidas

- Gmail y Outlook cambian su HTML con frecuencia; los selectores podrían necesitar mantenimiento.
- Solo analiza el mensaje visible y los enlaces presentes en el DOM. No inspecciona adjuntos, imágenes, QR, cabeceras completas, redirecciones ni el destino final tras navegar.
- La dirección completa del remitente o el asunto pueden no estar expuestos por la interfaz en todos los idiomas o diseños.
- El modelo de dominio registrable es aproximado y no incluye una Public Suffix List completa.
- Las reglas producen falsos positivos y falsos negativos. Una puntuación baja no certifica seguridad.
- No valida SPF, DKIM o DMARC, porque normalmente esas cabeceras no están disponibles desde la vista del mensaje.
- La lista local de marcas es deliberadamente pequeña en este MVP.

## Roadmap

1. Robustecer selectores con pruebas sobre distintas vistas e idiomas.
2. Añadir una Public Suffix List compacta y ampliar marcas mediante archivos de datos versionados.
3. Analizar cabeceras cuando el usuario las pegue o importe de forma explícita.
4. Detectar QR y texto en imágenes localmente con WebAssembly, de forma opcional.
5. Añadir tests de integración y accesibilidad.
6. Adaptar el motor a una PWA offline y Firefox.
7. Ofrecer políticas empresariales y listas locales personalizadas sin telemetría.

## Licencia

MIT. El archivo `LICENSE` permite usar, modificar y distribuir el proyecto gratuitamente. Ajusta el titular si lo vas a publicar bajo tu nombre u organización.
