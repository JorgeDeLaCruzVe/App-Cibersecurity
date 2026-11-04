# Security AI — Online

Plataforma híbrida de ciberseguridad en desarrollo, con tres módulos independientes.

## Estado real (noviembre 2026)

| Módulo | Estado |
| --- | --- |
| **Web Security** | Activo: comprobaciones HTTPS/HTTP, fecha de certificado TLS, cabeceras y DNS del dominio autorizado `nexdcglobal.pages.dev` |
| **Endpoint Security** | Sin equipos vinculados; requiere gateway privado, autenticar agentes y control de acceso |
| **Server Security** | Sin servidores vinculados; requiere gateway privado, autenticar agentes y control de acceso |
| **Respuesta automática e IA** | No habilitadas; requieren políticas y evaluación de seguridad |

## URL y endpoints

- [Panel online](https://security-ai-demo-online.onrender.com/)
- `GET /api/health`: estado de servicio
- `GET /api/web/sites`: único sitio real monitorizado y hallazgos
- `GET /api/web/nexdc/status`: comprobación técnica NEXDC
- `GET /api/assets`: inventario real (actualmente vacío)

El backend únicamente consulta un dominio autorizado y fijo. No acepta URLs arbitrarias, no realiza pruebas invasivas, no admite altas de agentes y no ejecuta acciones sobre sistemas del cliente. El resultado se almacena en caché durante 5 minutos y el navegador actualiza los resultados mientras la pestaña esté visible. **GitHub Actions realiza una comprobación programada cada hora (best-effort), con avisos y un resumen diario por Telegram cuando están configurados los secretos. No hay aún historial persistente ni supervisión continua garantizada.**

No presentar la ausencia de cabeceras HTTP como hallazgo explotable confirmado. La resolución DNS puede mostrar direcciones de una CDN, no los servidores de origen.

## Ejecución local

```bash
docker build -t security-ai-demo .
docker run --rm -p 10000:10000 security-ai-demo
```

## Próximas fases

1. Autenticación, MFA, permisos y almacenamiento persistente.
2. Agente Wazuh en laboratorio y gateway con certificados por empresa.
3. Telemetría normalizada y alertas sin datos ficticios.
4. Trabajos programados, notificaciones e historial.
5. Respuestas de bajo riesgo preaprobadas con auditoría y reversión.

## Telegram y monitorización automática

Se añadió un bot privado con comandos:

- `/id`: devuelve el ID del chat para configurarlo.
- `/estado`: consulta en tiempo real NEXDC, muestra también 0 PC y 0 servidores conectados.
- `/web`: HTTPS, HTTP y caducidad del certificado de NEXDC.
- `/servicios`: resumen de servicios; no inventa equipos conectados.
- `/ayuda`: comandos.

Para activarlo:

1. En Telegram, abre **@BotFather**, ejecuta `/newbot` y crea un bot. **Nunca pongas el token en el código ni lo envíes por chat.**
2. Abre [Render → Security AI → Environment](https://dashboard.render.com/web/srv-dblpr3gm7kps73bupm20/env). Añade `TELEGRAM_BOT_TOKEN` con el token, y `TELEGRAM_WEBHOOK_SECRET` con una clave aleatoria de al menos 32 caracteres alfanuméricos o guiones bajos. Render vuelve a desplegar el servidor y registra el webhook HTTPS.
3. Abre el bot en Telegram y envía `/id`. Copia el número que devuelve y configúralo como `TELEGRAM_CHAT_ID` en Render. Ahora `/estado`, `/web`, `/servicios` y `/ayuda` estarán disponibles únicamente para ese chat.
4. Para **alertas automáticas independientes de Render**, abre [GitHub → Actions secrets](https://github.com/JorgeDeLaCruzVe/App-Cibersecurity/settings/secrets/actions) y crea dos secretos del repositorio: `TELEGRAM_BOT_TOKEN` y `TELEGRAM_CHAT_ID`. No introduzcas sus valores en ningún fichero versionado.
5. En [GitHub Actions](https://github.com/JorgeDeLaCruzVe/App-Cibersecurity/actions) habilita workflows si lo pide GitHub. En **Security AI — monitoreo automático NEXDC**, elige **Run workflow** para ejecutar una comprobación manual. El cron revisa NEXDC cada hora; avisa cuando una comprobación indica un problema y envía un resumen a las 09:00 UTC (cuando GitHub ejecuta la tarea a tiempo).

**Limitaciones:** GitHub Actions puede retrasar o no ejecutar algún cron. Las alertas por anomalías pueden repetirse cada hora hasta que se recupere el sitio, porque aún no existe un almacenamiento duradero para deduplicarlas. La monitorización únicamente comprueba NEXDC por HTTPS/TLS, no realiza análisis intrusivos. Los mensajes directos necesitan que el servicio gratuito de Render esté despierto; podría tardar tras la inactividad. Este bot no modifica sistemas ni ejecuta comandos remotos.

**Seguridad:** webhook protegido mediante `X-Telegram-Bot-Api-Secret-Token`, comprobación constante de `TELEGRAM_CHAT_ID`, y ausencia de comandos shell. La acción `/id` devuelve únicamente el identificador numérico del chat solicitado.
