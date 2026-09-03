# Manual de instalación móvil - SecTF PhishGuard

## Antes de empezar

SecTF PhishGuard Mobile es una aplicación web instalable (PWA). No abre los enlaces sospechosos, no almacena los mensajes y reutiliza el mismo motor local de la extensión de escritorio.

> La dirección móvil funcionará cuando GitHub Pages esté activado: **https://gustavoua.github.io/SecTF-PhishGuard/mobile/**

## Instalar en Android con Chrome

1. Abre Chrome en el teléfono.
2. Visita la dirección de PhishGuard Mobile.
3. Si aparece el aviso **Instala PhishGuard**, pulsa **Instalar**.
4. Si no aparece, abre el menú de Chrome (tres puntos) y selecciona **Instalar aplicación** o **Añadir a pantalla de inicio**.
5. Confirma la instalación.
6. Busca el icono de PhishGuard en la pantalla de inicio o en el cajón de aplicaciones.

## Instalar en iPhone o iPad con Safari

1. Abre Safari. No uses el navegador interno de Gmail, Outlook o una red social.
2. Visita la dirección de PhishGuard Mobile.
3. Pulsa el botón **Compartir** de Safari.
4. Desplázate y selecciona **Añadir a pantalla de inicio**.
5. Comprueba el nombre y pulsa **Añadir**.
6. Abre PhishGuard desde el nuevo icono de la pantalla de inicio.

## Analizar un correo, SMS o enlace

### Método compatible con todos los móviles

1. En la aplicación de origen, selecciona y copia el texto del mensaje. Incluye el remitente, el asunto y cualquier enlace visible cuando sea posible.
2. Abre PhishGuard.
3. Pulsa **Pegar desde el portapapeles**. Si el navegador no concede acceso, mantén pulsado el cuadro y elige **Pegar**.
4. Pulsa **Analizar ahora**.
5. Espera a que termine la comprobación del dominio.
6. Revisa la puntuación, las señales detectadas y la recomendación.

### Desde el menú Compartir

En Android y navegadores compatibles:

1. Selecciona el texto o enlace sospechoso.
2. Pulsa **Compartir**.
3. Elige **PhishGuard**.
4. La aplicación recibirá el contenido e iniciará el análisis.

La disponibilidad de esta función depende del sistema, navegador y aplicación de origen. Si PhishGuard no aparece, utiliza el método de copiar y pegar.

## Cómo funciona

1. **Entrada:** el usuario pega un correo, SMS o enlace, o lo envía desde el menú Compartir.
2. **Extracción:** la aplicación identifica remitente, asunto, texto y direcciones web visibles.
3. **Análisis local:** el motor busca urgencia, amenazas, solicitudes de credenciales, pagos, códigos MFA, suplantación de marcas y enlaces engañosos.
4. **Dominio real:** utiliza el dominio del remitente; si no existe, analiza el primer enlace detectado.
5. **Comprobación pública:** consulta DNS, MX, SPF, DMARC, DNSSEC y antigüedad mediante DNS/RDAP sin abrir la web sospechosa.
6. **Puntuación:** suma las señales y limita el resultado a 100 puntos. Cada señal explica cuántos puntos aporta.
7. **Resultado:** presenta riesgo bajo, medio o alto y una recomendación concreta.

El motor local funciona después de la primera carga incluso sin conexión. La comprobación pública del dominio necesita Internet; si falla, PhishGuard conserva el resultado local y no penaliza por datos que no pudo obtener.

## Interpretar el resultado

- **Riesgo bajo (0-34):** no se encontraron señales fuertes. No significa que el mensaje sea seguro.
- **Riesgo medio (35-64):** existen señales que requieren comprobar remitente, contexto y destino real.
- **Riesgo alto (65-100):** no pulses enlaces ni respondas. Verifica la solicitud usando una dirección o teléfono oficial independiente.

La puntuación puede incluir hasta 40 puntos por información pública del dominio, como falta de DNS, MX o DMARC y una antigüedad muy baja.

## Privacidad

- El texto se analiza localmente en el dispositivo.
- PhishGuard no guarda el mensaje ni utiliza cuentas de usuario.
- La aplicación no visita los enlaces recibidos.
- Para verificar el dominio, solo envía su nombre a Google Public DNS y RDAP.
- El análisis por reglas puede funcionar sin conexión después de la primera carga. La verificación del dominio requiere Internet.

## Qué hacer ante riesgo alto

1. No pulses enlaces, no descargues archivos y no respondas.
2. No introduzcas contraseñas, códigos MFA ni datos bancarios.
3. Contacta con la empresa mediante su web oficial escrita manualmente, su aplicación oficial o un teléfono conocido.
4. En una organización, informa al equipo de seguridad y conserva el mensaje para su investigación.
5. Marca el correo como phishing o spam en la aplicación de correo.

## Solución de problemas

### No aparece la opción Instalar

- Comprueba que la página se abrió con HTTPS.
- En iPhone, utiliza Safari y **Añadir a pantalla de inicio**.
- En Android, abre el menú de Chrome y busca **Instalar aplicación**.

### No aparece PhishGuard en Compartir

- Abre primero la PWA instalada una vez.
- Reinicia la aplicación de origen.
- Si continúa sin aparecer, copia y pega el contenido.

### No se verifica el dominio

- Comprueba la conexión a Internet.
- El análisis local seguirá mostrándose aunque DNS o RDAP no respondan.
- Una comprobación incompleta no reduce la puntuación ni certifica que el remitente sea legítimo.

## Limitaciones

PhishGuard ofrece una evaluación orientativa y puede producir falsos positivos o falsos negativos. No sustituye a una pasarela de seguridad empresarial, al análisis de cabeceras completas ni a la revisión de un especialista.
