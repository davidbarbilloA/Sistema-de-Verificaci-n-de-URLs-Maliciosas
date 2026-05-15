"""
analyzer.py — Motor principal de análisis de URLs.
Orquesta validación, detección de phishing, VirusTotal, WHOIS, SSL, IP, HTML y ML.
"""

import re
from urllib.parse import urlparse

import tldextract
import validators

from src.services.virustotal import VirusTotalClient
from src.services.whois_client import WhoisClient
from src.services.ssl_client import SSLClient
from src.services.ip_client import IPClient
from src.services.browser_client import BrowserClient
from src.core.html_analyzer import HTMLAnalyzer
from src.core.ml_detector import MLDetector
from src.utils.utils import PALABRAS_SOSPECHOSAS, ACORTADORES


class URLAnalyzer:
    """
    Clase principal que centraliza todos los análisis sobre una URL.
    """

    PENALIZACIONES = {
        "sin_https":         20,
        "usa_ip":            25,
        "url_larga":         10,
        "chars_raros":       15,
        "acortador":         20,
        "muchos_subdominios": 15,
        "phishing_word":     10,
        "vt_malicious":      50,
        "vt_suspicious":     20,
        "dominio_nuevo":     25,
        "ssl_invalido":      40,
        "html_suspicious":   30,
        "ml_high_risk":      40,
    }

    def __init__(self) -> None:
        self.vt_client = VirusTotalClient()
        self.whois_client = WhoisClient()
        self.ssl_client = SSLClient()
        self.ip_client = IPClient()
        self.browser_client = BrowserClient()
        self.html_analyzer = HTMLAnalyzer()
        self.ml_detector = MLDetector()

    def _es_url_valida(self, url: str) -> bool:
        return bool(validators.url(url))

    def _usa_https(self, parsed: urlparse) -> bool:
        return parsed.scheme == "https"

    def _usa_ip(self, hostname: str) -> bool:
        ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^\[.*\]$")
        return bool(ip_pattern.match(hostname or ""))

    def _es_url_larga(self, url: str, limite: int = 100) -> bool:
        return len(url) > limite

    def _tiene_chars_raros(self, url: str) -> bool:
        patrones = [r"@", r"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}", r"-{2,}", r"\.\."]
        return any(re.search(p, url) for p in patrones)

    def _es_acortador(self, hostname: str) -> bool:
        dominio = hostname.lower().replace("www.", "")
        return any(acortador in dominio for acortador in ACORTADORES)

    def _tiene_muchos_subdominios(self, hostname: str, maximo: int = 3) -> bool:
        partes = hostname.split(".")
        return len(partes) > maximo

    def _detectar_phishing(self, url: str) -> list[str]:
        url_lower = url.lower()
        return [p for p in PALABRAS_SOSPECHOSAS if p in url_lower]

    def _calcular_score(
        self,
        checks: dict,
        palabras: list[str],
        vt_data: dict,
        whois_data: dict,
        ssl_data: dict,
        html_data: dict,
        ml_data: dict
    ) -> int:
        score = 0
        p = self.PENALIZACIONES

        if not checks["HTTPS"]:             score += p["sin_https"]
        if not checks["no_ip"]:             score += p["usa_ip"]
        if not checks["longitud_ok"]:       score += p["url_larga"]
        if not checks["sin_chars_raros"]:   score += p["chars_raros"]
        if not checks["no_acortador"]:      score += p["acortador"]
        if not checks["subdominios_ok"]:    score += p["muchos_subdominios"]

        score += min(len(palabras) * p["phishing_word"], 30)

        if not vt_data.get("error") and not vt_data.get("omitido"):
            if vt_data.get("malicious", 0) > 0: score += p["vt_malicious"]
            elif vt_data.get("suspicious", 0) > 0: score += p["vt_suspicious"]

        if whois_data.get("is_new"): score += p["dominio_nuevo"]
        if checks["HTTPS"] and not ssl_data.get("valid"): score += p["ssl_invalido"]
        
        if html_data.get("suspicious_iframes") or html_data.get("has_login_form"):
            score += p["html_suspicious"]
            
        if ml_data.get("probability", 0) > 60:
            score += p["ml_high_risk"]

        return min(score, 100)

    def analyze(self, url: str, follow_redirects: bool = True) -> dict:
        if not self._es_url_valida(url):
            return {"url": url, "valida": False, "score": 100, "error": "URL inválida"}

        # 1. Redirecciones
        redirect_data = {}
        if follow_redirects:
            redirect_data = self.browser_client.get_redirects(url)
            if not redirect_data.get("error"):
                url = redirect_data["final_url"]

        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # 2. Checks básicos
        checks = {
            "HTTPS":           self._usa_https(parsed),
            "no_ip":           not self._usa_ip(hostname),
            "longitud_ok":     not self._es_url_larga(url),
            "sin_chars_raros": not self._tiene_chars_raros(url),
            "no_acortador":    not self._es_acortador(hostname),
            "subdominios_ok":  not self._tiene_muchos_subdominios(hostname),
        }

        # 3. Consultas externas e internas
        palabras = self._detectar_phishing(url)
        vt_data = self.vt_client.check_url(url)
        whois_data = self.whois_client.get_domain_age(url) if checks["no_ip"] else {}
        ssl_data = self.ssl_client.check_ssl(url) if checks["HTTPS"] else {}
        ip_data = self.ip_client.get_ip_info(url)
        html_data = self.html_analyzer.analyze_html(url)
        ml_data = self.ml_detector.predict(url)

        score = self._calcular_score(checks, palabras, vt_data, whois_data, ssl_data, html_data, ml_data)

        return {
            "url":                 url,
            "valida":              True,
            "score":               score,
            "checks":              checks,
            "palabras_sospechosas": palabras,
            "virustotal":          vt_data,
            "whois":               whois_data,
            "ssl":                 ssl_data,
            "ip":                  ip_data,
            "redirects":           redirect_data,
            "html":                html_data,
            "ml":                  ml_data
        }