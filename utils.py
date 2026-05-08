"""
utils.py — Utilidades compartidas: constantes, helpers de consola y colores.
"""

from colorama import Fore, Style


# ─────────────────────────────────────────
# Constantes de análisis
# ─────────────────────────────────────────

PALABRAS_SOSPECHOSAS: list[str] = [
    "login", "verify", "secure", "account", "update",
    "paypal", "bank", "confirm", "password", "signin",
    "ebay", "amazon", "apple", "microsoft", "support",
    "wallet", "billing", "invoice", "urgent",
]

ACORTADORES: list[str] = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "is.gd", "cli.gs", "yfrog.com", "migre.me", "ff.im",
    "tiny.cc", "url4.eu", "twit.ac", "su.pr", "cutt.ly",
    "shorturl.at", "rb.gy", "qr.ae",
]


# ─────────────────────────────────────────
# Clasificación de riesgo
# ─────────────────────────────────────────

def get_risk_label(score: int) -> str:
    """Retorna la etiqueta textual según el score de riesgo."""
    if score <= 30:
        return "SEGURO"
    elif score <= 60:
        return "SOSPECHOSO"
    return "MALICIOSO"


def get_risk_color(score: int) -> str:
    """Retorna el color de colorama según el nivel de riesgo."""
    if score <= 30:
        return Fore.GREEN
    elif score <= 60:
        return Fore.YELLOW
    return Fore.RED


# ─────────────────────────────────────────
# Interfaz de consola
# ─────────────────────────────────────────

BANNER = r"""
  __  __       _  _      _                 _   _ ____  _
 |  \/  | __ _| |(_) ___(_) ___  _   _ __| | | |  _ \| |
 | |\/| |/ _` | || |/ __| |/ _ \| | | / _` | | | |_) | |
 | |  | | (_| | || | (__| | (_) | |_| \__,_| |_|  _ <| |___
 |_|  |_|\__,_|_|/ |\___|_|\___/ \__,_\__,_|\___/_| \_\_____|
                |__/
         URL  C H E C K E R  -  Defensive Security Tool
"""


def print_banner() -> None:
    """Imprime el banner de bienvenida con colores."""
    print(Fore.CYAN + BANNER + Style.RESET_ALL)
    print(f"  {Fore.WHITE}Analiza URLs en busca de phishing, malware y riesgos.")
    print(f"  {Fore.WHITE}Usa 'python main.py <url>' o modo interactivo sin argumentos.\n")