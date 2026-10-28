# Auditoría: skill-auditor (auditoría propia)

Origen: creada en esta sesión, `~/.claude/skills/skill-auditor/` · Fecha: 2026-10-28
Veredicto: **INSTALAR (ya instalada)**, confianza media. Se auditó solo con el escáner y lectura; el test A/B de la sección "Funciona" no se ha hecho.

| Eje | Nota | Por qué |
|---|---|---|
| Seguridad | 4 | Escáner de solo lectura: no ejecuta, importa ni sigue enlaces de lo que analiza. Sin red, sin escritura salvo `--md/--json` que pides tú. Los CRITICAL/HIGH son autohits explicados abajo. |
| Beneficio | 3 | Aporta consistencia (formato fijo, reglas con ID, cifras de tokens del escáner, triaje por escrito). En el A/B un modelo sin la skill detectó lo mismo en los 3 casos, así que la ventaja de detección no está demostrada. |
| Coste | 4 | Fijo ~200 tokens (nombre+descripción), al activarse ~1.760 (creció con el paso de instalar), bajo demanda ~5.700 (referencias, incluida la guía de hallazgos, que se cargan solo cuando hacen falta). Descripción acotada a frases de auditoría de skills. |
| Funciona | 3 | 18 tests automáticos; A/B de 3 casos sin ventaja de detección medible frente a un modelo sin la skill (ver `evals/ab-test-iteration-1.md`). |

## Autohits esperados (76 hallazgos: 3 CRITICAL, 29 HIGH, 32 MEDIUM, 11 LOW, 1 INFO)

_Actualizado tras añadir `install_skill.py` y la guía de hallazgos: más archivos, más citas de patrones._

El escáner contiene los patrones que busca y la documentación los cita, así que se marca a sí mismo. No hay directiva para ignorarlos (sería también una puerta para un atacante).

- **EX-PIPE (CRITICAL)** en `references/rubric.md:13`: la rúbrica cita `curl | sh` como ejemplo de qué penalizar. Texto, no orden.
- **CB-EXFIL y CB-DECODEEXEC (CRITICAL)** en `scripts/scan_skill.py`: combinaciones por coincidencia de patrones. El archivo menciona `.ssh`, `.env`, `webhook.site`, `base64` y `exec(` dentro de sus tablas de regex. Ninguna es una llamada real: no hay `import` de red ni de `base64`, ni `exec`.
- **HIGH/MEDIUM en `scan_skill.py`** (EX-IEX, EX-LOLBIN, PE-*, SE-*, NE-EXFIL, OB-*): líneas de la propia tabla de reglas.
- **HIGH/MEDIUM en `SKILL.md` y `references/`**: PI-HIDE, PI-AUTHORITY, PI-NOCONFIRM, PE-CLAUDE, SC-RUNREMOTE, SC-INSTALL, CO-FANOUT. Son citas de lo que hay que buscar o de lo que NO hay que hacer (`npx skills add`).
- Verificado: el fichero fuente ya no contiene caracteres invisibles (UN-ZW y UN-BIDI desaparecieron tras escribirlos como secuencias de escape).

## Validación realizada

1. **Fixture maliciosa** (`curl | bash`, base64+exec, lectura de `~/.ssh`, `webhook.site`, IP cruda, carácter de ancho cero, frase de inyección, `allowed-tools: Bash(*)`, `hooks.json` con comando): BLOCK, exit 3. Detectó todo salvo `Bash(*)` en la primera pasada (bug corregido: la regex exigía un carácter tras `)`).
2. **11 skills `replica-*`**: 0 CRITICAL; 2 con HIGH.
   - `replica-deploy`: PE-CLAUDE, una ruta `~/.claude/skills/` citada en prosa. Benigno.
   - `replica-launch`: UN-ZW, un carácter de ancho cero literal en `listing.py:50` (el código que detecta caracteres invisibles lo lleva escrito sin escapar). No es malicioso, pero conviene reescribirlo como `‍`. Detección correcta.
   - Falsos positivos corregidos tras la primera pasada: `re.compile(` marcado como `compile()`, y `.env.example` marcado como `.env`.
   - MEDIUM restantes: `npx` en bloques de código de documentación (real, avisa de código remoto) y `zlib.decompress` en `imgdiff.py` para leer PNG (benigno).
3. **Consola Windows**: el informe pasa por un saneador que convierte invisibles y escapes ANSI en `\uXXXX`; probado imprimiendo la fixture sin error de codificación.

## Límites

- Tokens estimados con 3,5 caracteres/token, ±25 %.
- Puede dar falsos positivos en documentación que cita patrones y falsos negativos en prosa que manipule al modelo sin usar frases conocidas.
- Para skills de terceros ejecuta además los pasos 3-6 del flujo (lectura completa, escalado a `thinker-opus`, coste/beneficio, prueba opt-in).
