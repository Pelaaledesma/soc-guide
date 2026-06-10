<p align="center">
  <img src="https://img.shields.io/badge/SOC%20Guide-v1.0-00c8ff?style=flat-square" alt="version"/>
  <img src="https://img.shields.io/badge/estado-en%20desarrollo-yellow?style=flat-square" alt="estado"/>
  <img src="https://img.shields.io/badge/licencia-MIT-blue?style=flat-square" alt="license"/>
</p>

<h1 align="center">⎔ SOC Guide</h1>
<p align="center">Guía de consulta rápida para SOC Analytics — basada en React, data-driven, pensada para estudiar.</p>
<p align="center">
  <a href="#-secciones">Secciones</a> •
  <a href="#-stack">Stack</a> •
  <a href="#-cómo-usarla">Cómo usarla</a> •
  <a href="#-cómo-contribuir">Contribuir</a>
</p>

---

### ¿Por qué?

Arrancando el path de SOC Analytics me di cuenta de que cada tema implicaba buscar en mil lugares distintos. Un EventID acá, un comando de Volatility allá, una query de Sentinel en un video, un playbook en un PDF. Terminaba con más pestañas abiertas que estudio hecho.

En lugar de seguir perdiendo tiempo, armé esto: una guía con React y datos en JSON, pensada para tener la información justa y necesaria en un solo lugar.

### 📋 Secciones

La guía cubre 17 secciones con contenido ordenado para consulta rápida:

| # | Sección | Qué incluye |
|---|---------|-------------|
| 🔍 | **Triage de Alertas** | Proceso de 5 pasos, árbol de decisión, preguntas guía por tipo de alerta |
| 🏷️ | **Matriz de Severidad** | Clasificación CRITICAL / HIGH / MEDIUM / LOW con ejemplos y acciones |
| 📋 | **Windows EventLogs Clave** | EventIDs 4624, 4688, 4104, 7045 y más con riesgo asociado |
| 📡 | **Sysmon Events** | EventIDs 1, 3, 8, 10, 22 y más para monitoreo avanzado |
| 💻 | **Comandos Forense Windows** | PowerShell, netstat, Get-WinEvent, Scheduled Tasks, Run keys |
| ⚡ | **LOLBins** | 12 binarios legítimos con uso malicioso y cómo detectarlos |
| 🐧 | **Comandos Forense Linux** | ps, ss, find, journalctl, auditd, SUID/SGID |
| 📝 | **Logs Críticos en Linux** | auth.log, syslog, audit.log, apache, mail |
| 🌐 | **Análisis de Red** | Beaconing, DGA, Data Exfil, DNS Tunneling con tcpdump/tshark |
| ⚡ | **Queries Útiles** | KQL (Sentinel), SPL (Splunk), ESQL (Elastic) |
| ⛔ | **Contención Rápida** | Acciones por escenario: ransomware, C2, cuenta comprometida, phishing |
| 📋 | **Playbooks** | Procedimientos paso a paso para phishing y ransomware |
| 🎯 | **MITRE ATT&CK** | 858 técnicas con descripciones, enlaces y detección rápida |
| 🔬 | **Forensia de Memoria RAM** | Comandos de Volatility 3 (psscan, netscan, malfind, filescan) |
| 🦠 | **Análisis de Malware** | Triage rápido, hashes, entropía, sandboxes, packers |
| 🛠️ | **Toolbox** | Herramientas organizadas por función: SIEM, EDR, CTI, OSINT, Forensia |
| 📄 | **Cheat Sheet** | Conversiones rápidas: bytes, hashes, epoch, hex, base64, URLs |

### 🧱 Stack

| Capa | Tecnología |
|------|-----------|
| UI | React 18 (vanilla, sin bundler — CDN) |
| Datos | JSON estructurado (`data/sections.json`) |
| Estilo | CSS custom properties, grid, sin frameworks |
| Deploy | Render (static site) |
| Fuente | Inter + JetBrains Mono |

### 🚀 Cómo usarla

Es un sitio estático. No requiere build ni dependencias.

**Opción 1 — Abrir directo**

```
git clone https://github.com/Pelaaledesma/soc-guide.git
cd soc-guide
# Abrir index.html en el navegador
```

**Opción 2 — Servir localmente (opcional)**

```bash
python3 -m http.server 8080
# Ir a http://localhost:8080
```

**Opción 3 — Deploy propio en Render**

Forkeá el repo, conectalo a Render como static site con `publishPath: .` y listo.

### 📁 Estructura

```
soc-guide/
├── index.html              # App React (todo en un archivo)
├── data/
│   └── sections.json       # Contenido de todas las secciones
├── scripts/
│   ├── auto-commit.sh      # Auto-commit con timestamp
│   ├── sync-mitre.js       # Sincronización MITRE ATT&CK
│   └── update-all.sh       # Actualización completa
├── render.yaml             # Config de Render
└── README.md
```

### 🤝 Cómo contribuir

Si estás en la misma y querés aportar, bienvenido:

- **Agregar contenido**: editá `data/sections.json` y mandá PR
- **Corregir errores**: si algún EventID, comando o query está mal, abrí un issue
- **Sugerir secciones**: lo que te haya hecho falta y no está, proponelo

Cualquier crítica constructiva suma. Recién estoy arrancando y esto es parte del aprendizaje.

### 📄 Licencia

MIT — podés usarlo, modificarlo y compartirlo libremente.

---

<p align="center">
  <sub>Hecho con ⎔ mientras estudiaba SOC Analytics.</sub>
</p>
