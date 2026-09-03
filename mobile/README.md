# SecTF PhishGuard Mobile

PWA instalable que reutiliza el motor local de SecTF PhishGuard.

## Funciones

- Analiza correos, SMS y enlaces pegados.
- Recibe texto y URL desde el menú **Compartir** en sistemas compatibles.
- Verifica automáticamente DNS, MX, SPF, DMARC y antigüedad del dominio.
- No abre enlaces sospechosos ni almacena el mensaje.
- Mantiene disponible el análisis por reglas después de la primera carga.

## Publicación

La PWA necesita HTTPS. En GitHub Pages, configura la rama **main** y la carpeta raíz como origen. Después estará disponible en:

https://gustavoua.github.io/SecTF-PhishGuard/mobile/

## Instalación

### Android

1. Abre la dirección anterior con Chrome.
2. Pulsa **Instalar** o usa **Añadir a pantalla de inicio**.
3. Para analizar contenido desde otra aplicación, abre **Compartir** y selecciona PhishGuard cuando aparezca disponible.

### iPhone o iPad

1. Abre la dirección con Safari.
2. Pulsa **Compartir** y después **Añadir a pantalla de inicio**.
3. Si la aplicación de origen no ofrece PhishGuard como destino, copia el mensaje o enlace y pégalo en la aplicación.

La compatibilidad del destino Compartir depende del navegador y del sistema operativo.
