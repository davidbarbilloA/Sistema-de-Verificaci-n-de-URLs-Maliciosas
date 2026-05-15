"""
browser_client.py — Cliente para capturas de pantalla y redirecciones.
Usa Playwright para renderizar el sitio y requests para seguir redirecciones.
"""

import requests
import os
from urllib.parse import urlparse

class BrowserClient:
    """
    Maneja la navegación, capturas de pantalla y seguimiento de redirecciones.
    """

    def get_redirects(self, url: str) -> dict:
        """
        Sigue la cadena de redirecciones y retorna la lista de URLs.
        """
        try:
            response = requests.get(url, allow_redirects=True, timeout=10)
            chain = [r.url for r in response.history] + [response.url]
            return {
                "chain": chain,
                "final_url": response.url,
                "count": len(response.history)
            }
        except Exception as e:
            return {"error": f"Error al seguir redirecciones: {str(e)}"}

    async def take_screenshot(self, url: str, output_path: str) -> dict:
        """
        Captura una imagen del sitio web usando Playwright.
        """
        try:
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                page = await browser.new_page()
                await page.goto(url, timeout=30000)
                await page.screenshot(path=output_path)
                await browser.close()
                return {"success": True, "path": output_path}
        except ImportError:
            return {"error": "Playwright no está instalado. Ejecuta 'pip install playwright'"}
        except Exception as e:
            return {"error": f"Error al capturar pantalla: {str(e)}"}
