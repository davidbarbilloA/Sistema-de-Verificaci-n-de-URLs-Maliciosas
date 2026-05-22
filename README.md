#  Malicious URL Checker

> Herramienta de ciberseguridad defensiva para analizar URLs sospechosas, detectar phishing, malware y evaluar el nivel de riesgo mediante un score automatizado. Diseñada para equipos Blue Team y analistas SOC.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![Security](https://img.shields.io/badge/Security-Defensive-green)
![VirusTotal](https://img.shields.io/badge/API-VirusTotal-blueviolet)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Version](https://img.shields.io/badge/Version-2.0-orange)

---

##  Tabla de contenido

- [Versiones](#-versiones)
- [Arquitectura actual](#-arquitectura-actual)
- [Instalación](#-instalación)
- [Configuración](#-configuración)
- [Uso](#-uso)
- [Sistema de Score](#-sistema-de-score)
- [Ejemplos de salida](#-ejemplos-de-salida)
- [Roadmap — Versiones futuras](#-roadmap--versiones-futuras)

---

##  Versiones

###  v1.0 — MVP Básico *(Completado)*

Primera versión funcional con análisis estático de URLs.

| Módulo | Descripción |
|---|---|
| **Validación** | HTTPS, IP directa, longitud, caracteres raros, acortadores, subdominios |
| **Phishing** | Detección de palabras clave sospechosas en la URL |
| **VirusTotal** | Consulta a la API v3 con estadísticas reales de detección |
| **Score básico** | Sistema de puntuación 0–100 con 3 niveles de riesgo |
| **Consola** | Salida con colores: 🟢 Seguro / 🟡 Sospechoso / 🔴 Malicioso |
| **Logs CSV** | Historial con URL, fecha, score y clasificación |

---

###  v2.0 — Análisis Profundo *(Completado — versión actual)*

Expansión mayor con módulos de inteligencia avanzada, análisis dinámico y reporting profesional.

| Módulo | Descripción | Archivo |
|---|---|---|
| **WHOIS** | Antigüedad del dominio, fecha de creación y registrador | `src/services/whois_client.py` |
| **SSL/TLS** | Validez del certificado, emisor, fecha de expiración y días restantes | `src/services/ssl_client.py` |
| **Geolocalización IP** | IP del servidor, ciudad, país e ISP | `src/services/ip_client.py` |
| **Seguimiento de Redirecciones** | Cadena completa de saltos y URL final real | `src/services/browser_client.py` |
| **Análisis HTML** | Título de la página, conteo de scripts/iframes, formularios de login | `src/core/html_analyzer.py` |
| **Captura de pantalla** | Screenshot automático de la URL analizada (asyncio + Playwright) | `src/services/browser_client.py` |
| **Machine Learning** | Predicción heurística basada en características de la URL (simulación LR) | `src/core/ml_detector.py` |
| **Informe SOC** | Reporte ejecutivo/técnico profesional con IOCs, riesgo, amenaza y recomendaciones | `src/utils/report_generator.py` |
| **Score ampliado** | Penalizaciones adicionales por dominio nuevo, SSL inválido, HTML sospechoso y ML | `src/core/analyzer.py` |

---

##  Arquitectura actual

```
malicious-url-checker/
│
├── main.py                    # CLI interactiva y directa
│
├── src/
│   ├── core/
│   │   ├── analyzer.py        # Motor principal — orquesta todos los análisis
│   │   ├── html_analyzer.py   # Análisis del contenido HTML de la página
│   │   └── ml_detector.py     # Detector heurístico tipo ML
│   │
│   ├── services/
│   │   ├── virustotal.py      # Cliente VirusTotal API v3
│   │   ├── whois_client.py    # Edad y datos de registro del dominio
│   │   ├── ssl_client.py      # Verificación de certificado SSL/TLS
│   │   ├── ip_client.py       # Geolocalización de la IP del servidor
│   │   └── browser_client.py  # Redirecciones y captura de pantalla
│   │
│   └── utils/
│       ├── utils.py            # Constantes, helpers, banner
│       ├── logger.py           # Guardado de resultados en CSV
│       └── report_generator.py # Generador de informes SOC profesionales
│
├── logs/
│   ├── url_analysis.csv        # Historial de análisis
│   └── screenshot_*.png        # Capturas automáticas
│
├── requirements.txt
├── .env                        # Variables de entorno
├── .env.example
├── .gitignore
└── README.md
```

---

##  Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/malicious-url-checker.git
cd malicious-url-checker

# 2. Crear entorno virtual
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Instalar Playwright (para capturas de pantalla y redirecciones)
playwright install chromium
```

---

##  Configuración

### VirusTotal API Key (gratuita)

1. Regístrate en [https://www.virustotal.com](https://www.virustotal.com)
2. Ve a tu perfil → **API Key**
3. Copia tu clave

```bash
cp .env.example .env
# Edita .env y pega tu API Key
```

```env
VIRUSTOTAL_API_KEY=abc123...tu_clave_real
```

>  El análisis funciona **sin API Key**, pero VirusTotal quedará deshabilitado.

---

##  Uso

### Modo directo (una URL)

```bash
python main.py https://ejemplo-sospechoso.com/login
```

### Modo interactivo

```bash
python main.py
# El programa pedirá URLs en bucle hasta escribir 'salir'
```

---

##  Sistema de Score

### Penalizaciones (v2.0)

| Indicador | Penalización |
|---|---|
| Sin HTTPS | +20 |
| Usa dirección IP | +25 |
| URL demasiado larga | +10 |
| Caracteres sospechosos | +15 |
| Acortador de enlaces | +20 |
| Múltiples subdominios | +15 |
| Palabra de phishing | +10 (máx 30) |
| Malware en VirusTotal | +50 |
| Sospechoso en VirusTotal | +20 |
| Dominio nuevo (<1 año) | +25 |
| SSL inválido o ausente | +40 |
| HTML sospechoso / Login form | +30 |
| ML de alto riesgo (>60%) | +40 |

### Clasificación final

| Score | Nivel | Color |
|---|---|---|
| 0 – 30 | ✅ SEGURO | Verde |
| 31 – 60 | ⚠️ SOSPECHOSO | Amarillo |
| 61 – 100 | 🚨 MALICIOSO | Rojo |

---

## 🖥 Ejemplos de salida

```
─────────────────────────────────────────────────────────────────
  Iniciando análisis profundo para: http://192.168.1.1/login-paypal-verify
─────────────────────────────────────────────────────────────────

[ REDIRECCIONES ]
  Cadena:  http://192.168.1.1/login-paypal-verify -> http://phish.tk/steal
  Total:   1 saltos

[ IP INTELIGENTE ]
  IP:      192.168.1.1
  Ubic.:   Buenos Aires, Argentina
  ISP:     Telecom Argentina

[ ANALISIS HTML ]
  Título:  Ingresa tus datos de PayPal
  Scripts: 4
  Iframes: 1 (1 sospechosos)
  [!] Detectado formulario de ingreso de credenciales

[ MACHINE LEARNING ]
  Predicción:    MALICIOSO
  Prob. Riesgo:  87.4%

[!] VirusTotal detectó 5 motores maliciosos

[ CAPTURA DE PANTALLA ]
  [+] Captura guardada en: logs/screenshot_http_192.168.1.1_login-paypal-verify.png

═══════════════════════════════════════════════════════════════
  SCORE FINAL DE RIESGO: 100/100
  CLASIFICACIÓN:         [ MALICIOSO ]
═══════════════════════════════════════════════════════════════

¿Deseas generar un informe SOC profesional? (s/n): s
```

---

##  Roadmap — Versiones futuras

###  v3.0 — Interface y Distribución

- [ ] **Dashboard web** — Interfaz visual con Flask o FastAPI para analizar URLs desde el navegador
- [ ] **Análisis en batch** — Soporte para cargar un archivo `.txt` con múltiples URLs y procesarlas en cola
- [ ] **Exportación de reportes** — Generar informes en formato **JSON** y **HTML** además del `.txt` actual
- [ ] **Integración Google Safe Browsing API** — Segunda fuente de inteligencia de amenazas además de VirusTotal

###  v3.1 — Detección Avanzada

- [ ] **Detección de typosquatting** — Identificar dominios que imitan marcas conocidas (ej: `paypai.com`, `g00gle.com`)
- [ ] **Modelo ML real** — Reemplazar el detector heurístico actual por un modelo entrenado con datasets de phishing (sklearn / joblib)
- [ ] **Análisis de JavaScript** — Detectar ofuscación, scripts de minería o redirecciones ocultas en el JS de la página

###  v3.2 — Alertas y Automatización

- [ ] **Alertas por email o Telegram** — Notificaciones automáticas cuando una URL supera el umbral de riesgo
- [ ] **Integración SIEM** — Exportar IOCs en formato CEF o JSON estructurado para consumo por SIEMs (Splunk, ELK)
- [ ] **API REST propia** — Endpoint `/analyze` para integrar el checker en pipelines de seguridad externos

---

##  Licencia

MIT — Libre para uso personal y educativo.

---

> Desarrollado como proyecto de portafolio en Python y ciberseguridad defensiva.