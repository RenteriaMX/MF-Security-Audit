# MF-Security-Audit

Script de auditoría de cadena de suministro (supply chain) para proyectos
**Plone 6 / Volto**. Auto-contenido, sin dependencias externas más allá de
`pnpm` (y opcionalmente `jq` para reportes detallados).

## Uso rápido

```bash
curl -fsSL https://raw.githubusercontent.com/RenteriaMX/MF-Security-Audit/main/audit-plone.sh | bash
```

### Detección del proyecto

El script detecta el directorio frontend en este orden:

1. Argumento de línea de comandos: `./audit-plone.sh /ruta/a/frontend`
2. Variable de entorno `PLONE_BASE` (busca `$PLONE_BASE/frontend`, si no existe usa `$PLONE_BASE`)
3. Default: `/opt/plone/web-plone`

```bash
PLONE_BASE=/srv/mi-proyecto-plone ./audit-plone.sh
```

## Qué audita

| # | Check | Herramienta |
|---|-------|-------------|
| 1 | Integridad del lockfile — detecta hashes modificados en `pnpm-lock.yaml` | `pnpm install --frozen-lockfile --dry-run` |
| 2 | Vulnerabilidades conocidas HIGH / CRITICAL | `pnpm audit --audit-level=high` |
| 3 | Scripts `postinstall` sospechosos en `node_modules` (filtrados contra whitelist de paquetes nativos conocidos: esbuild, sharp, canvas, node-gyp, etc.) | búsqueda en `package.json` |
| 4 | Typosquatting básico de paquetes Volto/Plone (`@plone/`, `@plonegovbr/`, `volto-`) — detecta sustituciones de caracteres tipo `v0lto`, `@pl0ne/`, prefijos sin scope, etc. | comparación de nombres en `package.json` |

## Salida

Al final se muestra un resumen y el script retorna un código de salida apto
para pipelines CI/CD:

| Resultado | Código de salida |
|-----------|------------------|
| ✓ Sin problemas | `0` |
| ⚠ Advertencias | `1` |
| ✗ Críticos encontrados | `2` |

## Requisitos

- `pnpm` instalado (`npm install -g pnpm`)
- `jq` (opcional, recomendado para detalle de vulnerabilidades y typosquatting más preciso)

## Licencia

MIT
