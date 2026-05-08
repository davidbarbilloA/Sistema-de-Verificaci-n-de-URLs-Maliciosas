# 🔍 Malicious URL Checker

> Herramienta de ciberseguridad defensiva para analizar URLs sospechosas, detectar phishing, malware y evaluar el nivel de riesgo mediante un score automatizado.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![Security](https://img.shields.io/badge/Security-Defensive-green)
![VirusTotal](https://img.shields.io/badge/API-VirusTotal-blueviolet)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## 📋 Tabla de contenido

- [Características](#-características)
- [Arquitectura](#-arquitectura)
- [Instalación](#-instalación)
- [Configuración](#-configuración)
- [Uso](#-uso)
- [Sistema de Score](#-sistema-de-score)
- [Ejemplos de salida](#-ejemplos-de-salida)
- [Mejoras futuras](#-mejoras-futuras)

---

## ✨ Características

| Módulo | Descripción |
|---|---|
| **Validación** | HTTPS, IP directa, longitud, caracteres raros, acortadores, subdominios |
| **Phishing** | Detección de palabras clave sospechosas en la URL |
| **VirusTotal** | Consulta a la API v3 con estadísticas reales de detección |
| **Score** | Sistema de puntuación 0–100 con 3 niveles de riesgo |
| **Consola** | Salida con colores: 🟢 Seguro / 🟡 Sospechoso / 🔴 Malicioso |
| **Logs** | Historial CSV con URL, fecha, score y clasificación |

---

## 🏗 Arquitectura

```
malicious-url-checker/
│
├── main.py           # Punto de entrada — CLI interactiva y directa
├── analyzer.py       # Motor de análisis — orquesta todos los checks
├── virustotal.py     # Cliente VirusTotal API v3
├── utils.py          # Constantes, helpers, banner
├── logger.py         # Guardado de resultados en CSV
│
├── logs/
│   └── url_analysis.csv   # Generado automáticamente
│
├── requirements.txt
├── .env              # Variables de entorno (NO subir a Git)
├── .env.example      # Plantilla de configuración
├── .gitignore
└── README.md
```

---

## ⚙️ Instalación

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
```

---

## 🔑 Configuración

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

> ⚠️ El análisis funciona **sin API Key**, pero VirusTotal quedará deshabilitado.

---

## 🚀 Uso

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

## 📊 Sistema de Score

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

### Clasificación final

| Score | Nivel | Color |
|---|---|---|
| 0 – 30 | ✅ SEGURO | Verde |
| 31 – 60 | ⚠️ SOSPECHOSO | Amarillo |
| 61 – 100 | 🚨 MALICIOSO | Rojo |

---

## 🖥 Ejemplos de salida

```
───────────────────────────────────────────────────────
  Analizando: http://192.168.1.1/login-paypal-verify
───────────────────────────────────────────────────────

[ VALIDACIÓN DE URL ]
  ✘ Sin HTTPS (HTTP)
  ✘ Usa dirección IP
  ✔ Longitud normal
  ✔ Sin caracteres raros
  ✔ No es acortador
  ✔ Subdominios normales

[ DETECCIÓN DE PHISHING ]
  ✘ Palabras sospechosas encontradas: login, paypal, verify

[ VIRUSTOTAL ]
  Maliciosos:    5
  Sospechosos:   2
  Limpios:      60
  Sin detectar: 10

[ RESULTADO FINAL ]
  Score de riesgo: 100/100
  Clasificación:   [ MALICIOSO ]
```

---

## 🔮 Mejoras futuras

- [ ] Análisis de dominios con WHOIS (edad del dominio)
- [ ] Verificación de certificado SSL válido
- [ ] Soporte para análisis en batch desde archivo `.txt`
- [ ] Exportación de reportes en JSON/HTML
- [ ] Dashboard web con Flask o FastAPI
- [ ] Integración con Google Safe Browsing API
- [ ] Detección de typosquatting (ej: `paypai.com`)
- [ ] Envío de alertas por email o Telegram

---

## 📄 Licencia

MIT — Libre para uso personal y educativo.

---

> Desarrollado como proyecto de portafolio en Python y ciberseguridad defensiva.