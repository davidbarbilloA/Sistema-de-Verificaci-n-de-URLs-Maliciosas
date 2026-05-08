"""
html_analyzer.py — Analizador de contenido HTML.
Busca elementos sospechosos como scripts maliciosos, iframes ocultos y enlaces externos masivos.
"""

from bs4 import BeautifulSoup
import requests

class HTMLAnalyzer:
    """
    Analiza el DOM de una página web en busca de indicadores de compromiso (IoC).
    """

    def analyze_html(self, url: str) -> dict:
        """
        Descarga el HTML y busca patrones sospechosos.
        """
        try:
            response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            html = response.text
            soup = BeautifulSoup(html, 'html.parser')
            
            # 1. Buscar iframes (especialmente los ocultos o pequeños)
            iframes = soup.find_all('iframe')
            suspicious_iframes = []
            for ifr in iframes:
                width = ifr.get('width', '100')
                height = ifr.get('height', '100')
                if width == '0' or height == '0':
                    suspicious_iframes.append(ifr.get('src'))

            # 2. Scripts externos
            scripts = [s.get('src') for s in soup.find_all('script') if s.get('src')]
            
            # 3. Formularios de login en sitios no HTTPS (ya lo cubrimos en score, pero aquí vemos el form)
            has_login_form = any(
                p in html.lower() for p in ['password', 'contraseña', 'login', 'signin']
            ) and len(soup.find_all('form')) > 0

            # 4. Enlaces externos
            links = [a.get('href') for a in soup.find_all('a') if a.get('href')]
            external_links = [l for l in links if l and l.startswith('http') and url not in l]

            return {
                "iframe_count": len(iframes),
                "suspicious_iframes": suspicious_iframes,
                "script_count": len(scripts),
                "has_login_form": has_login_form,
                "external_links_count": len(external_links),
                "title": soup.title.string if soup.title else "Sin título"
            }
        except Exception as e:
            return {"error": f"Error al analizar HTML: {str(e)}"}
