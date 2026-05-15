"""
whois_client.py — Cliente para obtener información de registro de dominios (WHOIS).
Ayuda a determinar la antigüedad del dominio.
"""

import whois
from datetime import datetime
from urllib.parse import urlparse

class WhoisClient:
    """
    Cliente para consultar información WHOIS y calcular la antigüedad del dominio.
    """

    def get_domain_age(self, url: str) -> dict:
        """
        Obtiene la fecha de creación del dominio y calcula su antigüedad en días.
        """
        try:
            hostname = urlparse(url).hostname
            if not hostname:
                return {"error": "No se pudo extraer el hostname"}

            # Limpiar hostname (quitar subdominios si es necesario, 
            # aunque whois suele manejarlo bien para dominios principales)
            domain_info = whois.whois(hostname)
            
            creation_date = domain_info.creation_date

            # creation_date puede ser una lista o un solo objeto datetime
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if not creation_date:
                return {"error": "No se encontró fecha de creación"}

            # Asegurar que sea naive para la resta
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)

            now = datetime.now()
            age_days = (now - creation_date).days
            
            return {
                "creation_date": creation_date.strftime("%Y-%m-%d"),
                "age_days": age_days,
                "is_new": age_days < 365,  # Consideramos "nuevo" si tiene menos de un año
                "registrar": domain_info.registrar
            }
        except Exception as e:
            return {"error": f"Error al consultar WHOIS: {str(e)}"}
