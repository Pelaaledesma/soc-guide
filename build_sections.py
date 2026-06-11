#!/usr/bin/env python3
"""Add new sections to SOC Guide sections.json"""

import json, sys

with open('/home/n3k0p/soc-guide/data/sections.json', 'r') as f:
    data = json.load(f)

existing_ids = {s['id'] for s in data['sections']}

new_sections = []

# ── 1. Windows Processes + Mindmap ──────────────────────────────────
if 'win-procs' not in existing_ids:
    new_sections.append({
        "id": "win-procs",
        "icon": "\u2699\ufe0f",
        "title": "Windows Processes — Guía Visual",
        "badge": "Mindmap + Referencia",
        "desc": "Mapa mental de SBousseaden para identificar procesos core de Windows y detectar anomalías. Cada proceso legítimo puede ser secuestrado o suplantado.",
        "content": [
            {"type": "callout", "s": "i", "title": "\ud83e\udde0 Procesos: la línea entre lo normal y lo malicioso", "body": "Los atacantes usan procesos legítimos de Windows para evadir detección. Conocer qué es normal en cada proceso es la base del threat hunting en endpoints."},
            {"type": "sub", "title": "Mapa Mental: Windows Core Processes (SBousseaden)"},
            {"type": "image", "src": "assets/windows-processes-th-mindmap.png", "alt": "Windows Processes Threat Hunting Mindmap by SBousseaden", "caption": "Fuente: @SBousseaden — Threat Hunting Mindmap"},
            {"type": "callout", "s": "g", "title": "\ud83d\udccd Cómo usar este mapa", "body": "Cada nodo representa un proceso core de Windows. Las ramas muestran: (1) qué hace el proceso normalmente, (2) qué anomalías buscar, (3) qué eventIDs monitorear, (4) técnicas MITRE asociadas."},
            {"type": "sub", "title": "Procesos Críticos y Señales de Alerta"},
            {"type": "table", "h": ["Proceso", "Función legítima", "Señal de alerta", "EventID clave"],
             "r": [
                 ["smss.exe", "Session Manager — arranca sesiones", "Ejecutándose fuera de %SystemRoot%\\System32", "4688 (created)"],
                 ["csrss.exe", "Client/Server Runtime — subsistema Win32", "Parent distinto de smss.exe", "4688"],
                 ["winlogon.exe", "Logon interactivo", "Carga de DLL no firmadas o sospechosas", "4624, 4648"],
                 ["lsass.exe", "Local Security Authority — auth", "Proceso hijo inesperado (cmd, powershell)", "4688, 4625"],
                 ["svchost.exe", "Service Host — servicios genéricos", "Fuera de C:\\Windows\\System32\\ o nombre de servicio anómalo", "4688, 4698"],
                 ["services.exe", "Service Control Manager", "Inicio de servicio con nombre aleatorio", "4698, 7045"],
                 ["wininit.exe", "Windows Initialization", "Carga de drivers sin firma", "4688"],
                 ["taskhost.exe", "Host para tareas en segundo plano", "Ejecución desde Temp o AppData", "4688"],
                 ["spoolsv.exe", "Print Spooler", "Carga de DLL con PrintNightmare o similar", "4688, 7045"],
                 ["wmiprvse.exe", "WMI Provider Host", "Ejecución remota inesperada (lateral movement)", "4688, 19/20 (Sysmon WMI)"],
                 ["explorer.exe", "Shell de Windows", "Parent distinto de userinit.exe o ejecución sospechosa", "4688"],
                 ["dllhost.exe", "COM+ surrogate host", "Habitual en ataques que usan COM para evasión", "4688"],
                 ["regsvr32.exe", "Registro de COM/DLL", "Conexiones salientes a internet", "4688, Sysmon 3"]
             ]},
            {"type": "sub", "title": "Patrones de Procesos Anómalos"},
            {"type": "grid", "items": [
                {"i": "\ud83d\udd04", "t": "Process Hollowing / Herited", "d": "Un proceso legítimo (ej: svchost.exe) se crea en estado suspendido, se le reemplaza el código en memoria y se reanuda. Detectar con Sysmon Event 8 (CreateRemoteThread).", "c": "r"},
                {"i": "\ud83c\udfaf", "t": "Parent-Child Mismatch", "d": "winword.exe lanzando powershell.exe? Eso es ejecución de macro maliciosa. El árbol de procesos es la forma más rápida de detectar ataques basados en phishing.", "c": "o"},
                {"i": "\ud83d\udd75\ufe0f", "t": "Proceso desde ubicación incorrecta", "d": "lsass.exe debe estar en System32. Si lo ves en Temp, Windows, o un path de usuario — es malware haciéndose pasar por él.", "c": "r"},
                {"i": "\u26a1", "t": "Conexiones de red inesperadas", "d": "regsvr32.exe, rundll32.exe, mshta.exe conectándose a internet no es normal. Tampoco lo es wmiprvse.exe haciendo peticiones HTTP.", "c": "p"}
            ]},
            {"type": "callout", "s": "d", "title": "\ud83d\udd0d Referencia Visual — Usá el mindmap como cheat sheet", "body": "Imprimilo o tenelo abierto durante el triage. Con el tiempo vas a reconocer estos patrones de forma automática."}
        ]
    })

# ── 2. Active Directory EventLogs & Attack Paths ────────────────────
if 'ad-attacks' not in existing_ids:
    new_sections.append({
        "id": "ad-attacks",
        "icon": "\ud83c\udfdb\ufe0f",
        "title": "Active Directory — EventLogs & Attack Paths",
        "badge": "AD Security",
        "desc": "Active Directory es el core de la identidad corporativa y el principal objetivo de atacantes. Eventos clave para detectar kerberoasting, DCSync, ACL abuse y más.",
        "content": [
            {"type": "callout", "s": "i", "title": "\ud83c\udfdb\ufe0f AD es el nuevo perímetro", "body": "El 80% de los ataques enterprise involucran AD. Cada EventID te cuenta una parte de la historia: autenticación, autorización, cambios en objetos y delegación."},
            {"type": "sub", "title": "EventIDs Críticos de AD"},
            {"type": "table", "h": ["EventID", "Nombre", "Qué detecta", "Ejemplo de ataque"],
             "r": [
                 ["4768", "Kerberos TGT solicitado", "Solicitud de ticket de usuario a DC", "Normal en auth — anómalo si es desde IP fuera de horario"],
                 ["4769", "Kerberos TGS solicitado", "Solicitud de ticket de servicio", "Múltiples solicitudes = Kerberoasting"],
                 ["4776", "Validación NTLM", "Autenticación NTLM contra DC", "Brute force NTLM, pass-the-hash"],
                 ["4624", "Logon exitoso", "Inicio de sesión", "Logon type 3 desde IP no corporativa"],
                 ["4625", "Logon fallido", "Fallo de autenticación", "Password spray (muchos usuarios, pocos intentos c/u)"],
                 ["4670", "ACL modificada", "Cambio en permisos de objeto", "Backdoor en ACL de AdminSDHolder"],
                 ["4738", "Usuario modificado", "Cambio en atributos de user", "Deshabilitar Kerberos pre-auth para AS-REP roast"],
                 ["4742", "Computer modificada", "Cambio en atributos de equipo", "Delegación no restringida agregada"],
                 ["5136", "Modificación LDAP", "Cambio en objeto LDAP del DC", "Modificar ACL de grupo privilegiado"],
                 ["4728", "Miembro agregado a grupo", "Usuario agregado a grupo de seguridad", "Agregar user a Domain Admins no autorizado"]
             ]},
            {"type": "sub", "title": "Ataques Comunes a AD"},
            {"type": "accordion", "items": [
                {"title": "\ud83e\udd2e Kerberoasting",
                 "lines": [
                     "QUÉ ES: Solicitar tickets TGS para cuentas de servicio y crackear offline su contraseña.",
                     "DETECCIÓN: Múltiples EventID 4769 con RC4 encriptación (0x17) desde misma IP en corto tiempo, hacia diferentes SPNs.",
                     "KQL: `SecurityEvent | where EventID==4769 and TicketEncryptionType==\"0x17\" | summarize count() by Account, IpAddress`",
                     "MITRE: T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting",
                     "PREVENCIÓN: Cuentas de servicio con contraseñas de >25 caracteres, Group Managed Service Accounts (gMSA), monitorear EventID 4769 anomalías."
                 ]},
                {"title": "\ud83d\udd11 AS-REP Roasting",
                 "lines": [
                     "QUÉ ES: Cuentas sin Kerberos pre-authentication habilitada exponen hashes crackeables.",
                     "DETECCIÓN: EventID 4768 sin pre-auth (atributo \"-Do not require Kerberos preauthentication\" habilitado). Monitorear cambios con EventID 4738.",
                     "KQL: `SecurityEvent | where EventID==4738 and TargetAccount contains \"$\" and AccountPropertyChanges contains \"Do not require\"`",
                     "MITRE: T1558.004 — AS-REP Roasting",
                     "PREVENCIÓN: Deshabilitar cuentas sin pre-auth, auditar con `Get-ADUser -ResultPageSize 2000 -Filter {DoesNotRequirePreAuth -eq $True}`"
                 ]},
                {"title": "\ud83d\udce1 DCSync",
                 "lines": [
                     "QUÉ ES: Usar DRSUAPI para replicar credenciales desde el DC — cualquier cuenta con DS-Replication-Get-Changes puede hacer esto.",
                     "DETECCIÓN: EventID 4662 (acceso a DS) con GUID de DS-Replication-Get-Changes. Buscar replicaciones desde cuentas no-DC.",
                     "KQL: `SecurityEvent | where EventID==4662 and ObjectName contains \"DS-Replication-Get-Changes\"`",
                     "MITRE: T1003.006 — DCSync",
                     "PREVENCIÓN: Monitorear el grupo \"Replicator\", limitar miembros con privilegios de replicación."
                 ]},
                {"title": "\ud83c\udff4 Golden / Silver Ticket",
                 "lines": [
                     "QUÉ ES: Un atacante con el hash KRBTGT forja tickets Kerberos que no expiran.",
                     "DETECCIÓN: EventID 4670 con SID 502 (KRBTGT) modificado. Tickets con lifetime mayor al máximo configurado. Logon con SID History anómalo.",
                     "MITRE: T1558.001 — Golden Ticket, T1558.002 — Silver Ticket",
                     "PREVENCIÓN: Rotar password de KRBTGT cada 6-12 meses, monitorear EventID 4670 en krbtgt."
                 ]},
                {"title": "\ud83d\udee1\ufe0f ACL Abuse / AdminSDHolder",
                 "lines": [
                     "QUÉ ES: Modificar ACLs en objetos AD para persistir incluso después de limpiar membresías de grupo.",
                     "DETECCIÓN: EventID 5136 + 4670 en AdminSDHolder o grupos protegidos (Domain Admins, Enterprise Admins).",
                     "KQL: `SecurityEvent | where EventID==4670 and ObjectName contains \"AdminSDHolder\"`",
                     "MITRE: T1098 — Account Manipulation (ACL abuse)"
                 ]}
            ]},
            {"type": "sub", "title": "Comandos de Auditoría Rápida"},
            {"type": "tabs", "tabs": [
                {"label": "PowerShell", "lang": "powershell", "lines": [
                    "# Cuentas sin Kerberos pre-auth",
                    "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True}",
                    "",
                    "# Cuentas de servicio con SPN (posible kerberoasting)",
                    "Get-ADUser -Filter {ServicePrincipalName -ne \"\"} -Properties ServicePrincipalName",
                    "",
                    "# Último cambio de KRBTGT",
                    "Get-ADUser krbtgt -Properties passwordLastSet, passwordNeverExpires",
                    "",
                    "# Miembros con privilegios de replicación",
                    "Get-ADObject -SearchBase \"CN=Configuration,...\" -LDAPFilter \"(objectClass=user)\""
                ]},
                {"label": "KQL", "lang": "kql", "lines": [
                    "// Kerberoasting: múltiples TGS con RC4 desde misma IP",
                    "SecurityEvent",
                    "| where EventID == 4769",
                    "| where TicketEncryptionType == \"0x17\"",
                    "| summarize TGS_count=count() by Account, IpAddress",
                    "| where TGS_count > 5",
                    "",
                    "// Logon anómalo desde IP externa",
                    "SecurityEvent",
                    "| where EventID == 4624 and LogonType == 3",
                    "| where not(IpAddress startswith \"10.\" or IpAddress startswith \"192.168.\")"
                ]}
            ]},
            {"type": "callout", "s": "d", "title": "\u26a0\ufe0f Regla de oro: monitoreá quién pide tickets, no solo quién se loguea", "body": "Muchos ataques a AD no generan un logon tradicional — ocurren a nivel de protocolo Kerberos (4768/4769). Si solo monitoreás 4624, te estás perdiendo el 70% de los ataques AD."}
        ]
    })

# ── 3. Cloud / Entra ID Security ────────────────────────────────────
if 'cloud' not in existing_ids:
    new_sections.append({
        "id": "cloud",
        "icon": "\u2601\ufe0f",
        "title": "Cloud & Entra ID — Security Monitoring",
        "badge": "Cloud",
        "desc": "El perímetro se mudó a la nube. Autenticación moderna, consent grants, MFA bombing, device code phishing y más vectores en Entra ID (Azure AD).",
        "content": [
            {"type": "callout", "s": "i", "title": "\u2601\ufe0f Cloud ≠ segura por defecto", "body": "Entra ID registra todo en los Audit Logs y Sign-In Logs. El problema no es falta de datos — es saber qué mirar."},
            {"type": "sub", "title": "Logs Críticos de Entra ID"},
            {"type": "table", "h": ["Log", "Qué registra", "Caso de uso"],
             "r": [
                 ["SignInLogs", "Cada inicio de sesión", "Detectar auth desde IP anómala, MFA failures, device code phishing"],
                 ["AuditLogs", "Cambios en configuración de tenant", "Detectar consent grants maliciosos, cambios en Conditional Access"],
                 ["ProvisioningLogs", "Sincronización de identidades", "Detectar modificación de cuentas en hybrid setup"],
                 ["AADServicePrincipalSignInLogs", "SPN / service principal auth", "Detectar abuso de service credentials o OAuth apps"]
             ]},
            {"type": "sub", "title": "Vectores de Ataque Cloud"},
            {"type": "grid", "items": [
                {"i": "\ud83d\udcf1", "t": "MFA Bombing / Fatigue", "d": "El atacante bombardea al usuario con push notifications MFA hasta que acepta por cansancio. Detectar con múltiples MFA denegadas en segundos antes de una aceptada.", "c": "r"},
                {"i": "\ud83c\udfaf", "t": "Device Code Phishing", "d": "Atacante convence al user de ingresar un código de device auth en una pantalla legítima. Detectar con múltiples device code auth de IP no corporativa.", "c": "o"},
                {"i": "\u2705", "t": "Consent Grant Malicioso", "d": "Una app OAuth pide permisos elevados (Mail.Read, Files.ReadWrite.All). El user acepta y el atacante accede sin re-autenticarse.", "c": "r"},
                {"i": "\ud83d\udd12", "t": "Token Theft / Replay", "d": "Token robado vía phishing o malware es reutilizado desde IP diferente. Detectar con sign-in correlation ID + location mismatch.", "c": "p"}
            ]},
            {"type": "sub", "title": "KQL Queries para Entra ID"},
            {"type": "code", "lang": "kql", "lines": [
                "// MFA bombing: m\u00faltiples denegadas + una aceptada en <2 min",
                "SigninLogs",
                "| where ResultType == \"500121\"  // MFA denied",
                "| summarize Denegadas = count(), UltimaDenegada = max(TimeGenerated) by UserPrincipalName, IPAddress",
                "| join kind=inner (",
                "    SigninLogs",
                "    | where ResultType == \"0\" and AuthenticationRequirement == \"multiFactorAuthentication\"",
                "    | project UserPrincipalName, IPAddress, TiempoAuth = TimeGenerated",
                "    ) on UserPrincipalName, IPAddress",
                "| where datetime_diff('second', TiempoAuth, UltimaDenegada) < 120",
                "| project UserPrincipalName, IPAddress, Denegadas, TiempoAuth",
                "",
                "// Device code auth desde IP an\u00f3mala",
                "SigninLogs",
                "| where ClientAppUsed == \"Device Code\"",
                "| where RiskLevelDuringSignIn in (\"medium\", \"high\")",
                "",
                "// Nuevo consent grant sospechoso",
                "AuditLogs",
                "| where OperationName == \"Consent to application\"",
                "| where TargetResources.0.modifiedProperties.0.newValue contains \".Read\""
            ]},
            {"type": "callout", "s": "d", "title": "\u26a0\ufe0f Conditional Access no es suficiente", "body": "CA reduce riesgo pero no lo elimina. MFA bombing y token theft evaden CA porque el token ya fue emitido. Necesitás monitorear los Sign-In Logs, no solo confiar en CA."},
            {"type": "sub", "title": "Referencias Rápidas"},
            {"type": "grid", "items": [
                {"i": "\ud83d\udcc4", "t": "Entra ID Audit Logs", "d": "Azure Portal > Entra ID > Monitoring > Audit Logs — retenci\u00f3n default 30 d\u00edas (requiere SIEM para m\u00e1s).", "c": "b"},
                {"i": "\ud83d\udd0c", "t": "Unified Audit Log (UAL)", "d": "M365 Security & Compliance center. Incluye Exchange, SharePoint, Teams. Retenci\u00f3n default 90-180 d\u00edas.", "c": "b"},
                {"i": "\u26a1", "t": "Azure Policy", "d": "Pol\u00edticas de detecci\u00f3n autom\u00e1tica: alertar sobre consent grants, apps sin publicar, y service principals con credenciales vencidas.", "c": "b"}
            ]}
        ]
    })

# ── 4. Email Security ──────────────────────────────────────────────
if 'email-sec' not in existing_ids:
    new_sections.append({
        "id": "email-sec",
        "icon": "\ud83d\udce7",
        "title": "Email Security — Headers & Autenticación",
        "badge": "Email Forensics",
        "desc": "El phishing empieza y termina en el email. Saber leer cabeceras, validar SPF/DKIM/DMARC y rastrear el origen real de un mensaje.",
        "content": [
            {"type": "callout", "s": "i", "title": "\ud83d\udce7 El email es el vector #1", "body": "El 91% de los ataques empiezan por email. Las cabeceras no mienten — el remitente visible sí."},
            {"type": "sub", "title": "Anatomy de una Cabecera de Email"},
            {"type": "table", "h": ["Campo", "Qu\u00e9 muestra", "Para qu\u00e9 sirve"],
             "r": [
                 ["Received", "Servidores por los que pas\u00f3", "Rastrear origen real (la \u00faltima entrada es la m\u00e1s cercana al origen)"],
                 ["Return-Path", "Direcci\u00f3n de rebote", "Qui\u00e9n realmente envi\u00f3 el mail (vs From visible)"],
                 ["Reply-To", "Respuesta configurada", "Si difiere de From, es phishing casi seguro"],
                 ["Authentication-Results", "Resultados SPF/DKIM/DMARC", "PASS = leg\u00edtimo, FAIL/softfail = spoofing"],
                 ["DKIM-Signature", "Firma DKIM", "El dominio firm\u00f3 criptogr\u00e1ficamente el mensaje"],
                 ["Message-ID", "ID \u00fanico del mensaje", "Para correlacionar con logs del servidor de correo"],
                 ["X-Originating-IP", "IP de origen (si se registra)", "Geolocalizaci\u00f3n del remitente real"]
             ]},
            {"type": "sub", "title": "SPF, DKIM y DMARC — La Trinidad"},
            {"type": "grid", "items": [
                {"i": "\ud83d\udee1\ufe0f", "t": "SPF (Sender Policy Framework)", "d": "El dominio publica qu\u00e9 IPs pueden enviar mail en su nombre. Si el mail llega de una IP no listada \u2192 SPF fail. Check: `nslookup -type=TXT dominio.com | findstr spf`", "c": "b"},
                {"i": "\ud83d\udd10", "t": "DKIM (DomainKeys Identified Mail)", "d": "Firma criptogr\u00e1fica del dominio. El servidor receptor valida la firma contra la clave p\u00fablica del DNS. Si no coincide \u2192 el mensaje fue alterado o falsificado.", "c": "b"},
                {"i": "\ud83d\udccb", "t": "DMARC (Domain-based Auth)", "d": "Pol\u00edtica que define qu\u00e9 hacer si SPF y/o DKIM fallan: none | quarantine | reject. Indica c\u00f3mo el dominio quiere que traten su correo.", "c": "b"}
            ]},
            {"type": "sub", "title": "An\u00e1lisis R\u00e1pido de Phishing"},
            {"type": "accordion", "items": [
                {"title": "\ud83d\udd0d Paso a paso: analizar email sospechoso",
                 "lines": [
                     "1. Descargar .EML/.MSG original (NO reenviar — pierde cabeceras).",
                     "2. Abrir con bloc de notas o visor de cabeceras.",
                     "3. Identificar el \u00faltimo (m\u00e1s antiguo) Received: esa es la IP de origen real.",
                     "4. Verificar Return-Path vs From — si difieren, probablemente spoofing.",
                     "5. Buscar Authentication-Results: SPF, DKIM, DMARC. Si alg\u00fan FAIL, el mail no es leg\u00edtimo.",
                     "6. Verificar enlaces sin hacer clic: copiar URL y analizar con VirusTotal o URLScan.io."
                 ]},
                {"title": "\ud83d\udea8 Indicadores de Phishing en Headers",
                 "lines": [
                     "- SPF fail + DKIM fail + DMARC fail = spoofing confirmado.",
                     "- Reply-To diferente de From = phishing casi siempre.",
                     "- Return-Path de dominio .ga, .ml, .cf, .tk = dominios gratuitos usados para spam.",
                     "- Received de IP en pa\u00eds no relacionado con la empresa.",
                     "- Enlaces con URL encoding excesivo o dominios que imitan marcas (rnicrosoft.com, paypa1.com)."
                 ]}
            ]},
            {"type": "sub", "title": "Comandos \u00fatiles"},
            {"type": "tabs", "tabs": [
                {"label": "PowerShell", "lang": "powershell", "lines": [
                    "# Analizar cabeceras de un .EML",
                    "$eml = [MimeKit.MimeMessage]::Load(\"phishing.eml\")",
                    "$eml.Headers",
                    "",
                    "# Validar SPF de un dominio",
                    "Resolve-DnsName -Type TXT dominio.com | Where-Object Strings -like '*spf*'"
                ]},
                {"label": "Linux", "lang": "bash", "lines": [
                    "# Ver cabeceras completas",
                    "cat email.eml | grep -E '^(Received|Return-Path|From|Reply-To|Authentication-Results):'",
                    "",
                    "# Validar SPF",
                    "dig txt dominio.com | grep -i spf",
                    "",
                    "# Extraer URL de un email",
                    "grep -oP 'https?://[^\\s<>\"\\']+' email.eml | sort -u"
                ]}
            ]},
            {"type": "callout", "s": "d", "title": "\u26a0\ufe0f IMPORTANTE: no reenvi\u00e9is el email", "body": "Reenviar destruye las cabeceras originales. Siempre ped\u00ed el .EML /.MSG adjunto original. En Outlook es \"Guardar como > Mensaje de correo (.eml)\"."}
        ]
    })

# ── 5. Sigma Rules ─────────────────────────────────────────────────
if 'sigma' not in existing_ids:
    new_sections.append({
        "id": "sigma",
        "icon": "\ud83d\udceb",
        "title": "Sigma Rules — Escribe Detecciones Portables",
        "badge": "Sigma",
        "desc": "Sigma es a los logs lo que YARA es a los archivos: un formato estandarizado para describir detecciones que se traduce a cualquier SIEM (KQL, SPL, ESQL, Lucene, etc.).",
        "content": [
            {"type": "callout", "s": "i", "title": "\ud83e\udde0 Sigma = detecciones que viajan", "body": "Escrib\u00eds una regla Sigma una vez y la convert\u00eds a Sentinel, Splunk, Elastic, QRadar, y m\u00e1s de 20 backends."},
            {"type": "sub", "title": "Estructura de una Regla Sigma"},
            {"type": "code", "lang": "yaml", "lines": [
                "title: PowerShell Execution from Office",
                "id: 7f7f8a0a-4c5e-4c1e-b7c8-8e0f2a5b3c9a",
                "status: experimental",
                "description: Detects Office products spawning PowerShell",
                "author: SOC Guide",
                "date: 2024/01/01",
                "tags:",
                "  - attack.execution",
                "  - attack.t1059.001",
                "logsource:",
                "  product: windows",
                "  category: process_creation",
                "detection:",
                "  selection_parent:",
                "    ParentImage|endswith:",
                "      - '\\\\WINWORD.EXE'",
                "      - '\\\\EXCEL.EXE'",
                "      - '\\\\POWERPNT.EXE'",
                "  selection_img:",
                "    Image|endswith: '\\\\powershell.exe'",
                "  condition: all of selection_*",
                "falsepositives:",
                "  - Administrative scripts",
                "level: high"
            ]},
            {"type": "sub", "title": "Traducción a SIEMs"},
            {"type": "tabs", "tabs": [
                {"label": "Sigma → KQL", "lang": "kql", "lines": [
                    "// Sigma rule: Office spawning PowerShell",
                    "DeviceProcessEvents",
                    "| where FolderPath endswith \"\\\\powershell.exe\"",
                    "| where InitiatingProcessFolderPath endswith @\"\\WINWORD.EXE\"",
                    "   or InitiatingProcessFolderPath endswith @\"\\EXCEL.EXE\"",
                    "   or InitiatingProcessFolderPath endswith @\"\\POWERPNT.EXE\""
                ]},
                {"label": "Sigma → SPL", "lang": "spl", "lines": [
                    "index=windows source=\"WinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1",
                    "| search Image=*\\\\powershell.exe",
                    "  AND (ParentImage=*\\\\WINWORD.EXE OR ParentImage=*\\\\EXCEL.EXE OR ParentImage=*\\\\POWERPNT.EXE)"
                ]},
                {"label": "Sigma → ESQL", "lang": "esql", "lines": [
                    "process where process.name == \"powershell.exe\"",
                    "and parent.name in (\"WINWORD.EXE\", \"EXCEL.EXE\", \"POWERPNT.EXE\")"
                ]}
            ]},
            {"type": "sub", "title": "LogSources más comunes"},
            {"type": "table", "h": ["Categoría", "Producto", "Descripción"],
             "r": [
                 ["process_creation", "windows", "Sysmon Event 1 / EID 4688 — creación de procesos"],
                 ["file_event", "windows", "Sysmon Event 11 — creación/escritura de archivos"],
                 ["network_connection", "windows", "Sysmon Event 3 — conexiones de red salientes"],
                 ["registry_event", "windows", "Sysmon Events 12-14 — modificación de registro"],
                 ["image_load", "windows", "Sysmon Event 7 — carga de DLL"],
                 ["dns_query", "windows", "Sysmon Event 22 — consultas DNS"],
                 ["security", "windows", "Windows Security Log (EventLog)"],
                 ["webserver", "linux", "Apache, Nginx, IIS access logs"],
                 ["firewall", "network", "Firewall traffic logs"]
             ]},
            {"type": "callout", "s": "g", "title": "\ud83d\udd17 Herramientas clave", "body": "Sigma CLI (pip install sigma-cli) para convertir reglas. sigconverter.io para probar online. El repositorio oficial: github.com/SigmaHQ/sigma"},
            {"type": "sub", "title": "Ejemplos Rápidos"},
            {"type": "accordion", "items": [
                {"title": "\ud83d\udd11 Detectar Pass-the-Hash",
                 "lines": [
                     "title: Suspicious NTLM Logon (Pass-the-Hash)",
                     "logsource: product: windows, service: security",
                     "detection:",
                     "  selection:",
                     "    EventID: 4624",
                     "    LogonType: 3",
                     "    LogonProcessName: 'NtLmSsp'",
                     "    WorkstationName: 'NULL'",
                     "  condition: selection",
                     "level: high"
                 ]},
                {"title": "\ud83d\udcbb Detectar WMI Lateral Movement",
                 "lines": [
                     "title: WMI Event Subscription Lateral Movement",
                     "logsource: product: windows, service: sysmon",
                     "detection:",
                     "  selection:",
                     "    EventID: 19",
                     "    EventType: 'WmiBindingEvent'",
                     "  condition: selection",
                     "level: high"
                 ]}
            ]}
        ]
    })

# ── 6. Actualizar MITRE ─────────────────────────────────────────────
# Add detailed detection content to the mitre section
mitre_section = next((s for s in data['sections'] if s['id'] == 'mitre'), None)
if mitre_section and len(mitre_section.get('content', [])) < 5:
    # Add detailed content before the existing mitre block
    new_mitre_content = [
        {"type": "callout", "s": "i", "title": "\ud83c\udfaf MITRE ATT&CK en SOC", "body": "La matriz no es solo una taxonomía — es un mapa de qué esperar en cada fase de un ataque. Usala para guiar el triage y las búsquedas."},
        {"type": "sub", "title": "Tácticas Rápidas para el Día a Día"},
        {"type": "table", "h": ["Táctica", "Qué busca el atacante", "EventIDs típicos", "Ejemplo concreto"],
         "r": [
             ["TA0001 — Initial Access", "Entrar al entorno", "4624, 4688 (Office)", "Phishing con macro, exploit en aplicación pública"],
             ["TA0002 — Execution", "Correr código malicioso", "4688, 4104, Sysmon 1", "PowerShell, WMI, scheduled task, mshta"],
             ["TA0003 — Persistence", "Mantenerse adentro", "4698, 7045, 4657", "Registry Run keys, servicios, scheduled tasks"],
             ["TA0004 — Privilege Escalation", "Obtener más permisos", "4670, 4688 (como SYSTEM)", "UAC bypass, token impersonation, exploits"],
             ["TA0005 — Defense Evasion", "No ser detectado", "1102 (log clear), Sysmon 12-14", "Apagar logging, firmar binarios, process hollowing"],
             ["TA0006 — Credential Access", "Robar credenciales", "4768, 4769, 4662", "Mimikatz, Kerberoasting, DCSync, keylogging"],
             ["TA0007 — Discovery", "Reconocer el entorno", "4798, 4799, 4688 (whoami)", "net user, net group, BloodHound, AD explorer"],
             ["TA0008 — Lateral Movement", "Moverse a otros hosts", "4624 (LogonType 3/9), 4688", "RDP, PsExec, WMI, SMB exec, WinRM"],
             ["TA0009 — Collection", "Recolectar datos", "4688 (rar/zip/7z)", "Comprimir archivos, clipboard, screenshots"],
             ["TA0010 — Exfiltration", "Sacar datos", "Sysmon 3 (DNS/HTTP), 22", "FTP, HTTP POST, DNS tunneling, cloud uploads"],
             ["TA0011 — Command & Control", "Comunicarse con C2", "Sysmon 3, 22, Windows-Firewall", "HTTP/S beacons, DNS TXT queries, DoH, WebSocket"]
         ]},
        {"type": "sub", "title": "Top 10 Técnicas más Detectadas en SOC"},
        {"type": "grid", "items": [
            {"i": "1", "t": "T1059 — Command & Scripting Interp.", "d": "PowerShell, cmd, script. La técnica #1. EventID 4104 (ScriptBlock Logging) es tu mejor aliado.", "c": "r"},
            {"i": "2", "t": "T1566 — Phishing", "d": "Spearphishing Attachment / Link. Sigue siendo el vector de entrada predominante.", "c": "r"},
            {"i": "3", "t": "T1055 — Process Injection", "d": "Inyectar código en proceso legítimo. Sysmon Event 8, 10 para detectar.", "c": "o"},
            {"i": "4", "t": "T1003 — OS Credential Dumping", "d": "Dump de LSASS. Monitorear EventID 4663 con acceso a lsass.exe.", "c": "r"},
            {"i": "5", "t": "T1047 — Windows Management Instrumentation", "d": "WMI para ejecución remota. Sysmon Events 19-21.", "c": "o"},
            {"i": "6", "t": "T1078 — Valid Accounts", "d": "Uso de cuentas legítimas robadas. Buscar logins desde ubicaciones anómalas.", "c": "p"},
            {"i": "7", "t": "T1053 — Scheduled Task / Job", "d": "Tareas programadas para persistencia o ejecución. EventID 4698.", "c": "o"},
            {"i": "8", "t": "T1547 — Boot or Logon Autostart", "d": "Registry Run keys, Startup folders. Sysmon Event 12-14.", "c": "o"},
            {"i": "9", "t": "T1021 — Remote Services", "d": "RDP, WinRM, PsExec para lateral movement. EventID 4624 LogonType 3/10.", "c": "r"},
            {"i": "10", "t": "T1562 — Impair Defenses", "d": "Deshabilitar AV, firewall, logging. EventID 1102 con log clear.", "c": "r"}
        ]}
    ]
    # Insert before the last mitre block content
    mitre_content = mitre_section.get('content', [])
    mitre_content[0:0] = new_mitre_content

# ── 7. Expandir Forensia RAM ────────────────────────────────────────
forensics_section = next((s for s in data['sections'] if s['id'] == 'forensics'), None)
if forensics_section:
    existing_content = forensics_section.get('content', [])
    new_forensic_content = [
        {"type": "callout", "s": "i", "title": "\ud83e\udde0 La memoria no miente — el disco puede ser manipulado", "body": "El malware en memoria no deja rastro en disco. Volatility es el est\u00e1ndar de facto para extraer procesos, conexiones, y artefactos de la RAM."},
        {"type": "sub", "title": "Volatility 3 — Plugins Esenciales"},
        {"type": "table", "h": ["Plugin", "Qu\u00e9 hace", "Cu\u00e1ndo usarlo"],
         "r": [
             ["windows.psscan", "Lista procesos (incluye ocultos)", "Siempre — empez\u00e1 ac\u00e1 para ver qu\u00e9 estaba corriendo"],
             ["windows.pstree", "\u00c1rbol de procesos con PPID", "Detectar parent-child mismatch (winword.exe \u2192 cmd.exe)"],
             ["windows.netscan", "Conexiones de red activas", "Detectar C2, beaconing, exfiltraci\u00f3n en curso"],
             ["windows.malfind", "Detecta memoria inyectada", "Encontrar process injection y shellcode oculto"],
             ["windows.filescan", "Archivos abiertos en el sistema", "Ver qu\u00e9 archivos estaban en uso al momento del volcado"],
             ["windows.dumpfiles", "Extrae archivos de memoria", "Recuperar binarios maliciosos para an\u00e1lisis offline"],
             ["windows.hashdump", "Extrae hashes NTLM de SAM + SYSTEM", "Detectar credential dumping y verificar cuentas comprometidas"],
             ["windows.cmdline", "L\u00ednea de comandos de cada proceso", "Saber exactamente c\u00f3mo se ejecut\u00f3 cada proceso"],
             ["windows.modscan", "Lista drivers y m\u00f3dulos del kernel", "Detectar rootkits a nivel kernel"],
             ["windows.registry.hivescan", "Ubica hives del registro en memoria", "Acceder a SAM, SYSTEM, SOFTWARE para volcado de credenciales"]
         ]},
        {"type": "sub", "title": "Flujo de An\u00e1lisis Forense"},
        {"type": "code", "lang": "shell", "lines": [
            "# 1. Identificar el perfil del volcado",
            "volatility -f memory.dmp windows.info",
            "",
            "# 2. Listar procesos (psscan > pslist para detectar ocultos)",
            "volatility -f memory.dmp windows.psscan",
            "volatility -f memory.dmp windows.pstree",
            "",
            "# 3. Examinar conexiones de red",
            "volatility -f memory.dmp windows.netscan",
            "",
            "# 4. Buscar inyecci\u00f3n de c\u00f3digo",
            "volatility -f memory.dmp windows.malfind",
            "",
            "# 5. Extraer hashes de credenciales",
            "volatility -f memory.dmp windows.hashdump",
            "",
            "# 6. Dump de proceso sospechoso por PID",
            "volatility -f memory.dmp windows.dumpfiles --pid 1234",
            "",
            "# 7. L\u00ednea de comandos de procesos",
            "volatility -f memory.dmp windows.cmdline"
        ]},
        {"type": "sub", "title": "Detectar un Rootkit de Kernel"},
        {"type": "callout", "s": "w", "title": "\ud83d\udd0d Compar\u00e1 pslist vs psscan", "body": "pslist enumera procesos usando la lista oficial de EPROCESS del kernel. psscan escanea toda la memoria buscando estructuras EPROCESS. Si un proceso aparece en psscan pero no en pslist, est\u00e1 oculto por un rootkit. Tambi\u00e9n verific\u00e1 con `modscan` si hay drivers sin firma o en paths no est\u00e1ndar."},
        {"type": "sub", "title": "Indicadores en Memoria"},
        {"type": "grid", "items": [
            {"i": "\ud83d\udd0d", "t": "Conexiones C2 activas", "d": "netscan muestra conexiones ESTABLISHED a IPs externas. Correlacionar con psscan para identificar qu\u00e9 proceso es el responsable.", "c": "r"},
            {"i": "\ud83d\udce1", "t": "Conexiones sin proceso asociado", "d": "Si netscan muestra conexiones pero no hay proceso asociado visible, es posible kernel-mode rootkit o conexi\u00f3n WMI.", "c": "o"},
            {"i": "\ud83e\udd16", "t": "Shellcode en memoria", "d": "malfind detecta regiones de memoria con permisos RWX (lectura-escritura-ejecuci\u00f3n). Normalmente la memoria es RX o RW, nunca RWX.", "c": "r"},
            {"i": "\ud83e\udd2e", "t": "Mimikatz en memoria", "d": "Si hay hashes NTLM en memoria sin un proceso legitimo de lsass accediendolos, es un dump de credenciales en curso.", "c": "r"}
        ]}
    ]
    # Insert at the beginning of existing content
    existing_content[0:0] = new_forensic_content

# ── Append new sections ──────────────────────────────────────────────
data['sections'].extend(new_sections)

# ── Write ────────────────────────────────────────────────────────────
with open('/home/n3k0p/soc-guide/data/sections.json', 'w') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print(f"✅ Done! Added {len(new_sections)} new sections.")
added_names = [s['id'] for s in new_sections]
if added_names:
    print(f"   New: {', '.join(added_names)}")
print(f"   Updated: mitre (expanded), forensics (expanded)")
print(f"   Total sections: {len(data['sections'])}")
