"""
virustotal.py — Integración con la API pública de VirusTotal v3.
Consulta la reputación de una URL y retorna estadísticas de detección.
"""

import base64
import os
import time

import requests
from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(env_path)

class VirusTotalClient:
    """
    Cliente para la API de VirusTotal v3.
    Documentación oficial: https://developers.virustotal.com/reference/overview
    """

    BASE_URL = "https://www.virustotal.com/api/v3"
    TIMEOUT = 15  # segundos

    def __init__(self) -> None:
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.headers = {"x-apikey": self.api_key}

    def _encode_url(self, url: str) -> str:
        """
        VirusTotal requiere la URL codificada en base64 URL-safe sin padding.
        Esto genera el identificador único del recurso.
        """
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    def _submit_url(self, url: str) -> str | None:
        """
        Envía la URL a VirusTotal para análisis.
        Retorna el analysis_id si fue aceptado, o None si falló.
        """
        endpoint = f"{self.BASE_URL}/urls"
        try:
            response = requests.post(
                endpoint,
                headers=self.headers,
                data={"url": url},
                timeout=self.TIMEOUT,
            )
            response.raise_for_status()
            return response.json().get("data", {}).get("id")
        except requests.RequestException as e:
            print(f"[VT] Error al enviar URL: {e}")
            return None

    def _get_url_report(self, url_id: str) -> dict:
        """
        Consulta el reporte de análisis usando el ID de la URL codificada.
        """
        endpoint = f"{self.BASE_URL}/urls/{url_id}"
        try:
            response = requests.get(
                endpoint,
                headers=self.headers,
                timeout=self.TIMEOUT,
            )
            if response.status_code == 404:
                return {"not_found": True}
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"error": f"Error al obtener reporte: {e}"}

    def _parse_stats(self, report: dict) -> dict:
        """
        Extrae las estadísticas relevantes del reporte de VirusTotal.
        """
        try:
            stats = (
                report
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
        except (KeyError, TypeError):
            return {"error": "No se pudieron parsear las estadísticas"}

    def check_url(self, url: str) -> dict:
        """
        Flujo completo:
        1. Verifica que exista API Key.
        2. Intenta obtener reporte existente.
        3. Si no existe, envía la URL y espera el análisis.
        4. Retorna estadísticas de detección.
        """
        if not self.api_key:
            return {"omitido": True, "razon": "API Key no configurada"}

        url_id = self._encode_url(url)

        # Intento 1: consultar reporte ya existente
        report = self._get_url_report(url_id)

        # Si no hay reporte previo (404), enviar para análisis
        if report.get("not_found"):
            analysis_id = self._submit_url(url)
            if not analysis_id:
                return {"error": "No se pudo enviar la URL a VirusTotal"}

            # Esperar un momento a que el análisis esté listo
            # (El plan gratuito demora un poco, aumentamos el tiempo de espera)
            time.sleep(15)
            report = self._get_url_report(url_id)

        if "error" in report:
            return report

        return self._parse_stats(report)