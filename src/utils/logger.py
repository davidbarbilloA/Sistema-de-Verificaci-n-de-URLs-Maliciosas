"""
logger.py — Sistema de logging en CSV para auditoría de análisis.
Guarda cada análisis con URL, fecha, score y clasificación.
"""

import csv
import os
from datetime import datetime


LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "url_analysis.csv")
CSV_HEADERS = ["timestamp", "url", "score", "clasificacion"]


class URLLogger:
    """
    Gestiona el guardado de resultados en un archivo CSV.
    Crea el directorio y el archivo automáticamente si no existen.
    """

    def __init__(self, filepath: str = LOG_FILE) -> None:
        self.filepath = filepath
        self._ensure_file()

    def _ensure_file(self) -> None:
        """Crea el directorio de logs y el archivo CSV con headers si no existen."""
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)

        # Solo escribir headers si el archivo es nuevo o está vacío
        if not os.path.exists(self.filepath) or os.path.getsize(self.filepath) == 0:
            with open(self.filepath, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
                writer.writeheader()

    def save(self, url: str, score: int, clasificacion: str) -> None:
        """
        Append de un registro de análisis al CSV.

        Args:
            url:           URL analizada.
            score:         Score de riesgo calculado (0–100).
            clasificacion: Etiqueta textual (SEGURO / SOSPECHOSO / MALICIOSO).
        """
        row = {
            "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "url":          url,
            "score":        score,
            "clasificacion": clasificacion,
        }
        try:
            with open(self.filepath, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
                writer.writerow(row)
        except OSError as e:
            print(f"[Logger] No se pudo guardar el log: {e}")

    def get_history(self, limit: int = 10) -> list[dict]:
        """
        Retorna los últimos N registros del log para consulta.

        Args:
            limit: Número máximo de registros a retornar.

        Returns:
            Lista de diccionarios con los registros más recientes.
        """
        try:
            with open(self.filepath, mode="r", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            return rows[-limit:]
        except OSError:
            return []