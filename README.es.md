# skill-auditor

Una skill de Claude que audita otras skills y plugins **antes de instalarlos**: si es segura, si merece la pena, cuántos tokens cuesta y si de verdad funciona. También busca skills candidatas y las audita primero.

Una skill es texto e instrucciones que se ejecutan con tus permisos y ocupan contexto. Instalarla es una decisión de confianza. Muchos instaladores (`npx skills add ...`) ejecutan código remoto antes de que hayas mirado nada; esta skill pone la auditoría primero.

English: [README.md](README.md).

## Qué hace

- **Seguridad:** `scan_skill.py` revisa toda la carpeta (código oculto o codificado, ejecución remota, secretos más red, frases de inyección, Unicode invisible, hooks, servidores MCP, cambios en la configuración de Claude). Después el modelo lee la skill entera.
- **Beneficio:** rúbrica 0-5 frente a lo que Claude ya hace y a tus skills instaladas.
- **Coste:** tres estimaciones de tokens (fijo, al activarse, bajo demanda) y aviso de descripciones demasiado amplias.
- **¿Funciona?:** prueba opcional con y sin la skill; avisa del coste antes y pide permiso.
- **Búsqueda:** `references/discovery.md`. Solo busca; no instala.

Entrega una tarjeta (Seguridad / Beneficio / Coste / Funciona) con veredicto *instalar / instalar con cambios / no instalar*.

### Instalar, tal cual o limpia

Si quieres una skill con hallazgos CRITICAL/HIGH, `scripts/install_skill.py` instala una **copia limpiada**: `prepare` quita lo marcado (hooks, configuración MCP, scripts, binarios), borra caracteres invisibles o claves del frontmatter, y puedes editar el resto a mano; `plan` enseña las diferencias exactas, el destino y los HIGH, y se niega mientras quede un CRITICAL; `apply` instala solo con el token de ese plan, verifica hashes, reescanea y deja registro. Eliges global (todos los proyectos) o un proyecto, y se te pregunta cada vez. No existe un "sí a todo": un sí antiguo no vale para una instalación nueva. `--replace` mueve la copia anterior a `.removed/`, no la borra.

## ¿Cómo distingue un hallazgo benigno de uno malicioso?

No lo decide el escáner: un hallazgo es una pista. El informe explica, para cada regla que saltó, qué significa y cuándo suele ser benigno o sospechoso, y plantea seis preguntas: ¿código o texto?, ¿lee o escribe?, ¿se combina con algo más?, ¿encaja con el propósito declarado?, ¿el destino es fijo y documentado?, ¿se avisa al usuario? Lo que no puedas responder con los archivos se queda como hallazgo. Tabla completa: [findings-guide.md](skills/skill-auditor/references/findings-guide.md).

## Alcance

- Entrada: carpeta con skills (`SKILL.md`) o un plugin. Lee texto; binarios, comprimidos, PDF y `.git` solo se señalan.
- Nunca ejecuta, importa ni instala lo que analiza.
- No demuestra que algo sea seguro: "sin hallazgos" significa "no coincidió ningún patrón conocido". No ve contenido descargado en ejecución ni juzga intenciones.
- Python 3.8+ (probado en 3.14, Windows 11), sin dependencias. Tokens estimados, ±25 %.
- Medido: una prueba pequeña con/sin skill ([evals/ab-test-iteration-1.md](evals/ab-test-iteration-1.md)) **no mostró ventaja de detección** frente a un modelo fuerte sin ayuda en tres casos fáciles, con ~16 % más de tokens; lo que aporta ahí es consistencia y trazabilidad. Pendiente: prueba de activación, varianza entre ejecuciones, paquetes grandes y ofuscados.

## Instalación

```bash
git clone https://github.com/Quiet115/skill-auditor
cp -r skill-auditor/skills/skill-auditor ~/.claude/skills/
```

Léela antes, que es el sentido del proyecto. Luego pídele a Claude: *"audita esta skill: <ruta o URL>"*. En PowerShell usa `$HOME`, no `~`.

## Pruebas y licencia

`python -I -m unittest discover -s tests` · Licencia MIT, sin garantía.
