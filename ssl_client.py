"""
ssl_client.py — Cliente para verificar certificados SSL/TLS.
Analiza la validez, emisor y fecha de expiración del certificado.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

class SSLClient:
    """
    Cliente para inspeccionar el certificado SSL de un sitio web.
    """

    def check_ssl(self, url: str) -> dict:
        """
        Obtiene información detallada del certificado SSL.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        if parsed.scheme != "https":
            return {"error": "URL no utiliza HTTPS"}

        if not hostname:
            return {"error": "No se pudo extraer el hostname"}

        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extraer emisor
                    issuer = dict(x[0] for x in cert['issuer'])
                    common_name = issuer.get('commonName', 'Desconocido')
                    
                    # Fechas
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    
                    now = datetime.now(timezone.utc)
                    days_to_expire = (not_after - now).days
                    
                    return {
                        "valid": True,
                        "issuer": common_name,
                        "expires": not_after.strftime("%Y-%m-%d"),
                        "days_to_expire": days_to_expire,
                        "is_expired": now > not_after,
                        "is_near_expiration": days_to_expire < 30
                    }
        except ssl.SSLError as e:
            return {"valid": False, "error": f"Error de SSL: {str(e)}"}
        except Exception as e:
            return {"valid": False, "error": f"No se pudo conectar: {str(e)}"}
