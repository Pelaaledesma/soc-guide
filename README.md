<p align="center">
  <img src="https://img.shields.io/badge/SOC%20Guide-v2.2-26c6da?style=flat-square" alt="version"/>
  <img src="https://img.shields.io/badge/estado-en%20desarrollo-yellow?style=flat-square" alt="estado"/>
  <img src="https://img.shields.io/badge/licencia-MIT-blue?style=flat-square" alt="license"/>
  <img src="https://img.shields.io/badge/dise%C3%B1o-terminal-0a0e14?style=flat-square" alt="terminal"/>
  <img src="https://img.shields.io/badge/buscar-s%C3%AD-66bb6a?style=flat-square" alt="search"/>
  <img src="https://img.shields.io/badge/stack-React%2018-42a5f5?style=flat-square" alt="react"/>
  <img src="https://img.shields.io/badge/herramientas-2-ffa726?style=flat-square" alt="tools"/>
  <img src="https://img.shields.io/badge/secciones-24-66bb6a?style=flat-square" alt="sections"/>
  <img src="https://img.shields.io/badge/mindmaps-4-ab47bc?style=flat-square" alt="mindmaps"/>
</p>

<br>

<h1 align="center"><code>⎔ SOC Guide</code></h1>
<p align="center"><b>Guía de referencia para SOC Analytics</b> — estilo terminal oscuro, filtrable, con búsqueda en tiempo real.</p>
<p align="center"><a href="https://soc-guide.onrender.com" target="_blank"><code>🔗 soc-guide.onrender.com</code></a></p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-secciones">Secciones</a> •
  <a href="#-stack">Stack</a> •
  <a href="#-cómo-usarla">Cómo usarla</a> •
  <a href="#-capturas">Capturas</a>
</p>

<br>

---

<br>

## ⚡ Features

|  |  |
|---|---|
| 🧮 **Calculadora CVSS v3.1** | Seleccioná métricas, pegá un vector o buscá un CVE-ID real (NVD API). Score + barra de severidad en vivo |
| 🔐 **Verificador de Hashes** | Calculá MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512 de texto o archivos. Compará contra un hash conocido |
| 🗺️ **Mapas mentales de Threat Hunting** | 4 mapas visuales de SBousseaden: procesos Windows, servicios, telemetría Sysmon kernel-mode, hunting en Security Log |
| 🏛️ **Active Directory Security** | Kerberoasting, DCSync, AS-REP Roast, ACL abuse con EventIDs y detección |
| ☁️ **Cloud & Entra ID Monitoring** | MFA bombing, consent grants, device code phishing con queries KQL |
| 📧 **Email Forensics** | Análisis de cabeceras, SPF/DKIM/DMARC, detección de phishing paso a paso |
| 📝 **Sigma Rules** | Escribí detecciones portables y traducilas a KQL / SPL / ESQL |
| 🎨 **Diseño terminal oscuro mejorado** | Paleta #0a0e14, acentos cyan/orange, glassmorphism, tipografía ampliada |
| 🔍 **Búsqueda en tiempo real** | Filtra secciones por contenido (títulos, tablas, comandos, todo) |
| 🏷️ **Filtros por categoría** | ALL · TRIAGE · WINDOWS · LINUX · NETWORK · PLAYBOOKS · MITRE · TOOLS · CLOUD · EMAIL |
| 🖼️ **Hero con imagen de fondo** | Foto SOC con overlay oscuro + escudo SVG animado |
| 📎 **Referencias externas** | Links directos a documentación oficial (Microsoft, MITRE, CISA, Volatility, SigmaHQ, etc.) al buscar |
| 🌐 **Google Search integrado** | Botón "G" en el buscador para ampliar la consulta en Google |
| 📋 **Copy con un clic** | Botón ⎘ copiar en todos los bloques de código |
| 📊 **Matriz MITRE ATT&CK** | Técnicas navegables + tabla de tácticas rápidas con EventIDs |
| 🔲 **Toolbox expandible** | Tarjetas de herramientas clickeables con expand/contraer para ver info completa |
| ⚡ **Sin build ni dependencias** | React 18 vía CDN, todo en un HTML |
| 📱 **Responsive** | Diseño adaptado a desktop y mobile |

<br>

## 📋 Secciones

Las **24 secciones** cubren el espectro completo de SOC Analytics:

|  | Sección | Contenido |
|---|---|---|
| 🔍 | **Triage de Alertas** | Proceso 5 pasos, árbol decisión, preguntas guía |
| 🏷️ | **Matriz de Severidad** | CRITICAL / HIGH / MEDIUM / LOW con ejemplos |
| 📋 | **Windows EventLogs** | EventIDs 4624, 4688, 4104, 7045 y más |
| 📡 | **Sysmon Events** | EventIDs 1, 3, 8, 10, 22 |
| 💻 | **Forense Windows** | PowerShell, netstat, Get-WinEvent, Run keys |
| ⚡ | **LOLBins** | 12 binarios legítimos con uso malicioso |
| 🐧 | **Forense Linux** | ps, ss, find, journalctl, auditd |
| 📝 | **Logs Linux** | auth.log, syslog, audit.log |
| 🌐 | **Análisis de Red** | Beaconing, DGA, Data Exfil, DNS Tunneling |
| ⚡ | **Queries SIEM** | KQL (Sentinel), SPL (Splunk), ESQL (Elastic) |
| ⛔ | **Contención Rápida** | Ransomware, C2, cuenta comprometida, phishing |
| 📋 | **Playbooks** | Phishing y ransomware paso a paso |
| 🎯 | **MITRE ATT&CK** | Tácticas rápidas, top 10 técnicas + matriz navegable |
| 🔬 | **Forensia RAM** | Volatility 3: 10 plugins, detección de rootkits |
| 🦠 | **Malware** | Triage, hashes, entropía, sandboxes, packers |
| 🛠️ | **Toolbox** | SIEM, EDR, CTI, OSINT, Forensia |
| 🧮 | **Calculadora CVSS** | Métricas CVSS v3.1, búsqueda por CVE-ID en NVD |
| 🔐 | **Verificador de Hashes** | MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512 |
| 📄 | **Cheat Sheet** | Bytes, hashes, epoch, hex, base64, URLs |
| ⚙️ | **Windows Processes** | Mapa mental de SBousseaden + tabla de 13 procesos críticos |
| 🏛️ | **Active Directory** | Kerberoasting, DCSync, AS-REP, Golden Ticket, ACL abuse |
| ☁️ | **Cloud & Entra ID** | MFA bombing, device code phishing, consent grants |
| 📧 | **Email Security** | Headers, SPF/DKIM/DMARC, análisis de phishing |
| 📝 | **Sigma Rules** | Estructura de reglas, traducción a KQL/SPL/ESQL |

<br>

## 🧱 Stack

```
┌───────────────────────────────────────┐
│  UI    │  React 18 (sin bundler)      │
│  Datos │  JSON → data/sections.json   │
│  Busc. │  Tiempo real (JS puro)       │
│  Calc. │  CVSS v3.1 + NVD API (REST)  │
│  Hash  │  Web Crypto API (SHA) + MD5  │
│  Ext.  │  Links curados + Google       │
│  Deploy│  Render (auto-deploy)         │
│  Fonts │  Inter + JetBrains Mono       │
└───────────────────────────────────────┘
```

**Sin framework CSS, sin build step, sin backend.**

<br>

## 🚀 Cómo usarla

Ya está online en **Render**, deploy automático con cada push:

```
🔗 https://soc-guide.onrender.com
```

Si querés correrla local o forkearla:

```bash
git clone https://github.com/Pelaaledesma/soc-guide.git
cd soc-guide
python3 -m http.server 8080
# Ir a http://localhost:8080
```

El `render.yaml` ya está configurado — fork, conectás a Render como static site con `publishPath: .` y deploy automático listo.

<br>

## 📁 Estructura

```
soc-guide/
├── index.html              # App React 18 completa (sin bundler + herramientas interactivas)
├── assets/                 # Mapas mentales de threat hunting (SBousseaden)
├── data/
│   └── sections.json       # Contenido estructurado de 24 secciones
├── scripts/
│   ├── auto-commit.sh      # Auto-commit con timestamp
│   ├── sync-mitre.js       # Sincronización MITRE ATT&CK
│   └── update-all.sh       # Actualización completa
├── render.yaml             # Config Render static site
└── README.md
```

<br>

## 🧮 Herramientas interactivas

Dos herramientas integradas como secciones dinámicas con React:

| Herramienta | Cómo funciona |
|---|---|
| **Calculadora CVSS v3.1** | Seleccioná métricas (AV, AC, PR, UI, S, C, I, A) con pills interactivos, o pegá un vector string completo. También podés **buscar un CVE-ID real** (ej: `CVE-2024-21626`) que consulta la API pública de NVD y auto-completa las métricas. Score, severidad, vector, impacto y explotabilidad se actualizan en vivo con barra visual. |
| **Verificador de Hashes** | Calculá el hash de un texto o archivo usando MD5 (nativo, sin librerías) o SHA-1 / SHA-256 / SHA-384 / SHA-512 (Web Crypto API). Seleccioná múltiples algoritmos a la vez. Podés pegar un hash conocido y ver si coincide. |

## 🗺️ Mapas mentales visuales

Cuatro mapas de **Samir Bousseaden (@SBousseaden)** incluidos como referencia visual directa:

| Mapa | Sección | Para qué sirve |
|---|---|---|
| **Windows Core Processes** | Windows Processes | Identificar procesos legítimos vs anómalos |
| **Sysmon Kernel-Mode Telemetry** | Sysmon Events | Telemetría del kernel: eventos 7, 10, 12-14 |
| **Windows Services** | Windows Processes | Servicios críticos y sus señales de alerta |
| **Hunting Security Log** | Windows EventLogs | Rutas de hunting en el Security Log |

<br>

## 🔎 Búsqueda y referencias

El buscador en tiempo real indexa **todo el contenido** localmente (títulos, tablas, comandos, descripciones) y se combina con los filtros por categoría.

Cuando encontrás un tema, el panel **📎 Referencias externas** te da acceso directo a la documentación oficial:

| Término | Referencia |
|---------|-----------|
| `4624`, `4688`, `4104` | Microsoft Docs |
| `T1059`, `T1566`, `T1047` | MITRE ATT&CK |
| `volatility`, `malfind` | Volatility Foundation |
| `kql`, `splunk`, `esql` | Microsoft / Splunk / Elastic |
| `ransomware`, `phishing` | CISA |
| `sysmon`, `autoruns` | Sysinternals |
| `lolbas` | LOLBAS Project |
| `yara`, `sigma` | YARA / Sigma |
| `kerberoasting`, `dcsync`, `as-rep` | Microsoft / MITRE ATT&CK |
| `entra id`, `mfa`, `conditional access` | Microsoft Entra ID |
| `spf`, `dkim`, `dmarc` | RFC / M3AAWG |

Además, el botón **G** al lado del buscador abre una consulta en Google con `SOC + {término}`.

<br>

## 📄 Licencia

MIT — podés usarlo, modificarlo y compartirlo libremente.

---

<p align="center">
  <sub>Hecho con ⎔ mientras estudiaba SOC Analytics.</sub>
</p>
