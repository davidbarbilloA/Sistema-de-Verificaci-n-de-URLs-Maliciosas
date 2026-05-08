"""
analyzer.py — Motor principal de análisis de URLs.
Orquesta validación, detección de phishing y consulta a VirusTotal.
"""

import re
from urllib.parse import urlparse

import tldextract
import validators

from virustotal import VirusTotalClient
from utils import PALABRAS_SOSPECHOSAS, ACORTADORES


class URLAnalyzer:
    """
    Clase principal que centraliza todos los análisis sobre una URL.
    Retorna un diccionario estructurado con checks, score y detalles.
    """

    # Penalizaciones del score de riesgo
    PENALIZACIONES = {
        "sin_https":         20,
        "usa_ip":            25,
        "url_larga":         10,
        "chars_raros":       15,
        "acortador":         20,
        "muchos_subdominios": 15,
        "phishing_word":     10,   # por cada palabra sospechosa (máx 30)
        "vt_malicious":      50,
        "vt_suspicious":     20,
    }

    def __init__(self) -> None:
        self.vt_client = VirusTotalClient()

    # ─────────────────────────────────────────
    # Métodos de validación individuales
    # ─────────────────────────────────────────

    def _es_url_valida(self, url: str) -> bool:
        """Verifica si la URL tiene un formato válido."""
        return bool(validators.url(url))

    def _usa_https(self, parsed: urlparse) -> bool:
        """Comprueba si el esquema es HTTPS."""
        return parsed.scheme == "https"

    def _usa_ip(self, hostname: str) -> bool:
        """Detecta si el host es una dirección IP en lugar de un dominio."""
        ip_pattern = re.compile(
            r"^(\d{1,3}\.){3}\d{1,3}$"   # IPv4
            r"|^\[.*\]$"                   # IPv6 entre corchetes
        )
        return bool(ip_pattern.match(hostname or ""))

    def _es_url_larga(self, url: str, limite: int = 100) -> bool:
        """Retorna True si la URL supera el límite de caracteres."""
        return len(url) > limite

    def _tiene_chars_raros(self, url: str) -> bool:
        """
        Detecta caracteres inusuales frecuentes en URLs maliciosas:
        @, %, codificaciones dobles, guiones excesivos, etc.
        """
        patrones_sospechosos = [
            r"@",           # Usuario embebido en URL
            r"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}",  # Doble codificación
            r"-{2,}",       # Múltiples guiones seguidos
            r"\.\.",        # Puntos dobles
        ]
        return any(re.search(p, url) for p in patrones_sospechosos)

    def _es_acortador(self, hostname: str) -> bool:
        """Comprueba si el dominio pertenece a un servicio de acortamiento."""
        dominio = hostname.lower().replace("www.", "")
        return any(acortador in dominio for acortador in ACORTADORES)

    def _tiene_muchos_subdominios(self, hostname: str, maximo: int = 3) -> bool:
        """Detecta una cantidad anormal de subdominios."""
        partes = hostname.split(".")
        return len(partes) > maximo

    def _detectar_phishing(self, url: str) -> list[str]:
        """Retorna las palabras sospechosas encontradas en la URL."""
        url_lower = url.lower()
        return [p for p in PALABRAS_SOSPECHOSAS if p in url_lower]

    # ─────────────────────────────────────────
    # Cálculo del score de riesgo
    # ─────────────────────────────────────────

    def _calcular_score(
        self,
        checks: dict,
        palabras: list[str],
        vt_data: dict,
    ) -> int:
        """
        Acumula penalizaciones y retorna el score final (0–100).
        Mayor score = mayor riesgo.
        """
        score = 0
        p = self.PENALIZACIONES

        if not checks["HTTPS"]:             score += p["sin_https"]
        if not checks["no_ip"]:             score += p["usa_ip"]
        if not checks["longitud_ok"]:       score += p["url_larga"]
        if not checks["sin_chars_raros"]:   score += p["chars_raros"]
        if not checks["no_acortador"]:      score += p["acortador"]
        if not checks["subdominios_ok"]:    score += p["muchos_subdominios"]

        # Palabras de phishing: +10 por palabra, máximo +30
        score += min(len(palabras) * p["phishing_word"], 30)

        # VirusTotal
        if not vt_data.get("error") and not vt_data.get("omitido"):
            if vt_data.get("malicious", 0) > 0:
                score += p["vt_malicious"]
            elif vt_data.get("suspicious", 0) > 0:
                score += p["vt_suspicious"]

        return min(score, 100)  # Máximo 100

    # ─────────────────────────────────────────
    # Método principal
    # ─────────────────────────────────────────

    def analyze(self, url: str) -> dict:
        """
        Punto de entrada principal.
        Ejecuta todos los análisis y retorna un diccionario con resultados.
        """
        # Validar formato básico
        if not self._es_url_valida(url):
            return {
                "url": url,
                "valida": False,
                "score": 100,
                "checks": {},
                "palabras_sospechosas": [],
                "virustotal": {"error": "URL con formato inválido"},
            }

        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Ejecutar todos los checks
        checks = {
            "HTTPS":           self._usa_https(parsed),
            "no_ip":           not self._usa_ip(hostname),
            "longitud_ok":     not self._es_url_larga(url),
            "sin_chars_raros": not self._tiene_chars_raros(url),
            "no_acortador":    not self._es_acortador(hostname),
            "subdominios_ok":  not self._tiene_muchos_subdominios(hostname),
        }

        palabras = self._detectar_phishing(url)
        vt_data = self.vt_client.check_url(url)
        score = self._calcular_score(checks, palabras, vt_data)

        return {
            "url":                 url,
            "valida":              True,
            "score":               score,
            "checks":              checks,
            "palabras_sospechosas": palabras,
            "virustotal":          vt_data,
        }