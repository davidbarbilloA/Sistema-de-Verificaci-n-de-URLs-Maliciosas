# Malicious URL Checker – Verificación de URLs sospechosas

Herramienta de línea de comandos para ciberseguridad defensiva: analiza URLs sospechosas, detecta indicios de phishing y malware, y calcula un **score de riesgo de 0 a 100**. Pensada para equipos Blue Team y analistas SOC. Versión actual: **v2.0**.

## Tech stack

| Capa | Tecnologías |
|------|-------------|
| **Lenguaje** | Python 3.11+ |
| **Inteligencia de amenazas** | VirusTotal API v3, ip-api.com, WHOIS (`python-whois`) |
| **Análisis web** | Requests, BeautifulSoup, Playwright (Chromium) |
| **Parsing de URLs** | `validators`, `tldextract` |
| **Consola y configuración** | Colorama, python-dotenv |

## Estructura del proyecto

```text
Sistema-de-Verificaci-n-de-URLs-Maliciosas/
├── main.py                     # CLI: modo directo e interactivo
├── src/
│   ├── core/
│   │   ├── analyzer.py         # Motor principal: orquesta los análisis y calcula el score
│   │   ├── html_analyzer.py    # Análisis del contenido HTML de la página
│   │   └── ml_detector.py      # Detector heurístico (simula un modelo de ML)
│   ├── services/
│   │   ├── virustotal.py       # Cliente de VirusTotal API v3
│   │   ├── whois_client.py     # Antigüedad y registro del dominio
│   │   ├── ssl_client.py       # Verificación del certificado SSL/TLS
│   │   ├── ip_client.py        # Geolocalización de la IP del servidor
│   │   └── browser_client.py   # Redirecciones y capturas de pantalla
│   └── utils/
│       ├── utils.py            # Constantes, helpers y banner
│       ├── logger.py           # Historial de análisis en CSV
│       └── report_generator.py # Informes SOC
├── .env.example
├── requirements.txt
└── README.md
```

> La carpeta `logs/` se genera al ejecutar el programa y no se versiona.

## Funcionalidades

- **Validación estática**: HTTPS, uso de IP directa, longitud, caracteres sospechosos, acortadores y subdominios
- **Detección de phishing** por palabras clave en la URL
- **VirusTotal**: estadísticas de detección de los motores de análisis
- **WHOIS**: antigüedad del dominio, fecha de creación y registrador
- **SSL/TLS**: validez, emisor, expiración y días restantes del certificado
- **Geolocalización**: IP del servidor, ciudad, país e ISP
- **Redirecciones**: cadena completa de saltos y URL final
- **Análisis HTML**: título, scripts, iframes y formularios de login
- **Captura de pantalla** automática con Playwright
- **Detector heurístico**: estima el riesgo a partir de características de la URL con pesos simulados; no usa un modelo entrenado
- **Informe SOC** opcional con IOCs, riesgo, amenaza y recomendaciones
- **Historial en CSV** con URL, fecha, score y clasificación

## Sistema de score

### Penalizaciones

| Indicador | Puntos |
|-----------|--------|
| Sin HTTPS | +20 |
| Usa dirección IP | +25 |
| URL demasiado larga | +10 |
| Caracteres sospechosos | +15 |
| Acortador de enlaces | +20 |
| Múltiples subdominios | +15 |
| Palabra de phishing | +10 cada una (máx. 30) |
| Malicioso en VirusTotal | +50 |
| Sospechoso en VirusTotal | +20 |
| Dominio nuevo | +25 |
| SSL inválido (solo en URLs HTTPS) | +40 |
| Iframes sospechosos o formulario de login | +30 |
| Detector heurístico por encima de 60 % | +40 |

### Clasificación

| Score | Nivel | Color |
|-------|-------|-------|
| 0 – 30 | SEGURO | Verde |
| 31 – 60 | SOSPECHOSO | Amarillo |
| 61 – 100 | MALICIOSO | Rojo |

## Instalación y ejecución

### 1. Clonar el repositorio

```bash
git clone https://github.com/davidbarbilloA/Sistema-de-Verificaci-n-de-URLs-Maliciosas.git
cd Sistema-de-Verificaci-n-de-URLs-Maliciosas
```

### 2. Crear el entorno virtual e instalar dependencias

**Requisitos:** Python 3.11+

```bash
python -m venv venv
source venv/bin/activate
```

En Windows:

```bash
venv\Scripts\activate
```

Después, instala las dependencias y el navegador de Playwright:

```bash
pip install -r requirements.txt
playwright install chromium
```

### 3. Variables de entorno

Crea un archivo `.env` en la raíz con tu clave de [VirusTotal](https://www.virustotal.com) (gratuita):

```env
VIRUSTOTAL_API_KEY=tu_clave
```

| Variable | Descripción |
|----------|-------------|
| `VIRUSTOTAL_API_KEY` | Clave de la API de VirusTotal |

> El análisis funciona sin clave, pero con VirusTotal deshabilitado.

### 4. Ejecutar

Analizar una sola URL:

```bash
python main.py https://ejemplo-sospechoso.com/login
```

Modo interactivo (termina al escribir `salir`):

```bash
python main.py
```

## Flujo típico de uso

1. El analista ejecuta el programa con la URL sospechosa.
2. La consola muestra redirecciones, datos de la IP, análisis HTML, resultado heurístico y detecciones de VirusTotal.
3. El programa guarda la captura en `logs/` y registra el resultado en `logs/url_analysis.csv`.
4. Se muestra el score final con su clasificación.
5. Opcionalmente, genera un informe SOC y lo guarda en `logs/`.

## Roadmap

### v3.0 – Interfaz y distribución

- [ ] Dashboard web con Flask o FastAPI
- [ ] Análisis en lote desde un archivo `.txt`
- [ ] Exportación de informes en JSON y HTML
- [ ] Integración con Google Safe Browsing

### v3.1 – Detección avanzada

- [ ] Detección de typosquatting
- [ ] Modelo de ML entrenado con datasets de phishing
- [ ] Análisis de JavaScript (ofuscación, minería, redirecciones ocultas)

### v3.2 – Alertas y automatización

- [ ] Alertas por email o Telegram
- [ ] Exportación de IOCs para SIEM (Splunk, ELK)
- [ ] API REST propia con endpoint `/analyze`

## Licencia

MIT: libre para uso personal y educativo.

## Autor

- [@davidbarbilloA](https://github.com/davidbarbilloA)
