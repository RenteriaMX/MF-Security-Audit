# MF-Security-Audit

Script de auditoría de cadena de suministro (supply chain) para proyectos
**Plone 6 / Volto**. Auto-contenido, sin dependencias externas más allá de
`pnpm` (y opcionalmente `jq` para reportes detallados).

## Uso rápido

```bash
curl -fsSL https://raw.githubusercontent.com/RenteriaMX/MF-Security-Audit/main/audit-plone.sh | bash -s /opt/plone/mi-proyecto
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
| 1 | Integridad del lockfile — detecta hashes modificados en `pnpm-lock.yaml` | `pnpm install --frozen-lockfile --lockfile-only` |
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

## Cómo interpretar los hallazgos del check 2 (vulnerabilidades)

No todas las HIGH/CRITICAL que reporta `pnpm audit` son responsabilidad del
proyecto. Antes de alarmarte, revisa la **cadena de dependencias** con:

```bash
pnpm why <paquete> --recursive
```

Es común que vulnerabilidades en paquetes como `undici`, `uuid` o similares
lleguen como **deuda técnica del propio Volto**, no de algo que el equipo del
proyecto haya agregado. Ejemplo real encontrado en una auditoría:

```
@plone/volto devDependencies:
  vitest      → jsdom → undici   (CVEs HIGH en undici)
  release-it  → undici           (CVEs HIGH en undici)
```

`vitest` y `release-it` están **declarados directamente en `package.json` de
`@plone/volto`** (fijados vía `catalog:` en `pnpm-workspace.yaml`) — son parte
del toolchain oficial de testing/release de Volto. La corrección real depende
de que el proyecto Volto upstream actualice esas versiones; mientras tanto se
puede mitigar con `pnpm.overrides` para forzar versiones parchadas de la
dependencia transitiva (`undici`, `jsdom`, etc.) sin esperar al upstream.

Esto **no aplica** a hallazgos en dependencias de producción declaradas
directamente por el proyecto (esas sí son responsabilidad inmediata del
equipo).

## Herramientas complementarias para auditorías más exhaustivas

Este script cubre lo esencial de supply chain para Plone/Volto, pero para un
análisis más profundo conviene combinar con:

| Herramienta | Qué aporta |
|---|---|
| [**Socket.dev / `socket-cli`**](https://socket.dev) | Analiza comportamiento de paquetes (acceso a red, filesystem, `eval`, scripts de instalación) y detecta typosquatting con mucha más precisión que una comparación de nombres |
| [**OSV-Scanner**](https://github.com/google/osv-scanner) (Google) | Escanea lockfiles contra la base de datos OSV — más amplia que las advisories de npm |
| [**Snyk CLI**](https://snyk.io) | Base de datos de vulnerabilidades propia, sugiere parches/upgrades automáticos (`snyk fix`) |
| [**Trivy**](https://github.com/aquasecurity/trivy) (Aqua) | Escanea filesystem, lockfiles e imágenes de contenedor — útil si el proyecto se despliega en Docker |
| [**lockfile-lint**](https://github.com/lirantal/lockfile-lint) | Valida que el lockfile apunte a registries/hosts confiables (detecta lockfiles envenenados con URLs maliciosas) |
| [**OpenSSF Scorecard**](https://github.com/ossf/scorecard) | Evalúa la "salud" de seguridad de cada dependencia upstream (mantenimiento, CI, firmas, etc.) |

Para CI/CD, lo más práctico es correr este script junto con `osv-scanner` o
`socket-cli` — cubren huecos distintos (CVEs vs. comportamiento malicioso de
paquetes) sin solaparse demasiado.

## Requisitos

- `pnpm` instalado (`npm install -g pnpm`)
- `jq` (opcional, recomendado para detalle de vulnerabilidades y typosquatting más preciso)

## Licencia

MIT
