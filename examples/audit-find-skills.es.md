# Auditoría: find-skills (vercel-labs/skills)

Origen: github.com/vercel-labs/skills, ruta `skills/find-skills/SKILL.md` · commit `699d35b21bd3c97dbc0edeae062b2698898bb2e5` · 2026-10-28
Licencia MIT, ~37.000 estrellas, última actividad del repo 2026-10-28. Un solo archivo (5.472 bytes), sin scripts.
Veredicto: **INSTALAR CON CAMBIOS (no instalada)**, confianza media.

| Eje | Nota | Por qué |
|---|---|---|
| Seguridad | 3 | El archivo está limpio (escáner: 0 CRITICAL/HIGH; 5 MEDIUM por `npx`, ninguno oculto). El riesgo es de comportamiento: manda ejecutar `npx skills add <x> -g -y`, que instala sin confirmar y sin auditar, y su "verificación de calidad" se basa en instalaciones y estrellas, que no prueban seguridad. |
| Beneficio | 3 | Aporta un flujo de búsqueda (leaderboard de skills.sh, filtros por popularidad). Claude ya puede buscar con WebSearch/`gh`; el valor extra es conocer skills.sh y la CLI. |
| Coste | 3 | Fijo ~98 tokens (bien). Al activarse ~1.460. La descripción dispara con cualquier "how do I do X" / "can you do X", así que se carga con frecuencia en preguntas que no necesitan una skill. |
| Funciona | 2 | Solo leída. No se ejecutó `npx skills`: en esta máquina no hay Node (`node/npm/npx` ausentes), así que su mecanismo central no funcionaría tal cual. |

## Hallazgos que importan
1. `SKILL.md:103` "`-g` instala globalmente y `-y` omite las confirmaciones" y Paso 6 "puedes instalarla por el usuario": invita a saltarse la decisión del usuario. Es el hueco que `skill-auditor` cierra.
2. `SKILL.md:23-29` y ejemplos: todo pasa por `npx skills ...`, que descarga y ejecuta la última versión del paquete npm en cada llamada, sin fijar versión. Consulté el registro: `skills@1.7.4`, MIT, repo vercel-labs, sin scripts install/postinstall, dependencias `tar` y `yaml`. Fijar esa versión reduce el riesgo.
3. `SKILL.md:1-3` descripción amplia: "how do I do X", "can you do X", "expresa interés en ampliar capacidades". Riesgo de sobreactivación.
4. Paso 4 usa instalaciones/estrellas como filtro. Es una pista de popularidad, no una auditoría.

## Cambios necesarios
- No instalar la versión original tal cual. Mejor: usar solo la idea de búsqueda (ya integrada en `skill-auditor/references/discovery.md`: skills.sh por WebFetch, `gh search`, y `npx --yes skills@1.7.4 find` solo si hay Node y lo apruebas).
- Si aun así la quieres instalada: quitar `-g -y` y el Paso 6, reducir la descripción a "busca una skill para...", y que todo candidato pase por `skill-auditor` antes de cualquier `add`.

## Qué no pude comprobar
Comportamiento real de la CLI (no ejecutada, sin Node), contenido de skills.sh, y si el paquete npm publicado coincide con el repo.
