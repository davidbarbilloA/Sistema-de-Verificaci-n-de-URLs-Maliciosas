"""
ip_client.py — Cliente para obtener información de la IP del servidor.
Proporciona geolocalización e información del ISP.
"""

import socket
import requests

class IPClient:
    """
    Obtiene información sobre la dirección IP asociada a un dominio.
    """

    def get_ip_info(self, url: str) -> dict:
        """
        Resuelve el dominio a IP y obtiene geolocalización.
        """
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname
        
        if not hostname:
            return {"error": "No se pudo extraer el hostname"}

        try:
            ip_address = socket.gethostbyname(hostname)
            # Usamos ip-api.com (gratuito para uso no comercial)
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            data = response.json()
            
            if data.get("status") == "fail":
                return {"ip": ip_address, "error": data.get("message")}

            return {
                "ip": ip_address,
                "country": data.get("country"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "lat": data.get("lat"),
                "lon": data.get("lon")
            }
        except Exception as e:
            return {"error": f"Error al obtener info de IP: {str(e)}"}
