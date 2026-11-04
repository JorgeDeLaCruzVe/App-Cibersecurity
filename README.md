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

El backend únicamente consulta un dominio autorizado y fijo. No acepta URLs arbitrarias, no realiza pruebas invasivas, no admite altas de agentes y no ejecuta acciones sobre sistemas del cliente. El resultado se almacena en caché durante 5 minutos y el navegador actualiza los resultados mientras la pestaña esté visible. **No existe todavía un monitor persistente 24/7 ni almacenamiento histórico.**

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
