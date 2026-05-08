"""
ml_detector.py — Detector basado en Machine Learning (Heurístico Avanzado).
Analiza características de la URL para predecir si es maliciosa.
"""

import re

class MLDetector:
    """
    Simula un modelo de ML extrayendo características y aplicando un clasificador.
    """

    def predict(self, url: str) -> dict:
        """
        Extrae características (features) y calcula una probabilidad de riesgo.
        """
        features = {
            "length": len(url),
            "dot_count": url.count('.'),
            "hyphen_count": url.count('-'),
            "special_char_count": len(re.findall(r'[@?&=%]', url)),
            "digit_count": len(re.findall(r'\d', url)),
            "has_ip": 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0,
            "subdomain_count": len(url.split('.')) - 2
        }

        # Pesos simulados de un modelo de regresión logística
        score = 0
        score += (features["length"] / 100) * 10
        score += features["dot_count"] * 5
        score += features["hyphen_count"] * 3
        score += features["special_char_count"] * 8
        score += features["digit_count"] * 2
        score += features["has_ip"] * 30
        score += features["subdomain_count"] * 7

        # Normalizar a 0-100
        probability = min(max(score, 0), 100)

        return {
            "probability": round(probability, 2),
            "features": features,
            "prediction": "MALICIOSO" if probability > 60 else "SOSPECHOSO" if probability > 30 else "SEGURO"
        }
