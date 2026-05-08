"""
Malicious URL Checker - Entry point
Autor: Tu Nombre
Descripción: Script principal para analizar URLs sospechosas.
"""

import sys
from colorama import init, Fore, Style
from analyzer import URLAnalyzer
from logger import URLLogger
from utils import print_banner, get_risk_label, get_risk_color

# Inicializar colorama (necesario en Windows)
init(autoreset=True)


def analyze_single_url(url: str, analyzer: URLAnalyzer, logger: URLLogger) -> None:
    """Analiza una sola URL y muestra los resultados en consola."""
    print(f"\n{Fore.CYAN}{'─'*55}")
    print(f"  Analizando: {Fore.WHITE}{url}")
    print(f"{Fore.CYAN}{'─'*55}{Style.RESET_ALL}")

    result = analyzer.analyze(url)
    score = result["score"]
    label, color = get_risk_label(score), get_risk_color(score)

    # --- Sección: Validación de URL ---
    print(f"\n{Fore.YELLOW}[ VALIDACIÓN DE URL ]{Style.RESET_ALL}")
    checks = result["checks"]
    flags = {
        "HTTPS":              ("✔ Usa HTTPS",              "✘ Sin HTTPS (HTTP)"),
        "no_ip":              ("✔ Usa dominio",             "✘ Usa dirección IP"),
        "longitud_ok":        ("✔ Longitud normal",         "✘ URL demasiado larga"),
        "sin_chars_raros":    ("✔ Sin caracteres raros",    "✘ Caracteres sospechosos"),
        "no_acortador":       ("✔ No es acortador",         "✘ Acortador detectado"),
        "subdominios_ok":     ("✔ Subdominios normales",    "✘ Múltiples subdominios"),
    }
    for key, (ok_msg, fail_msg) in flags.items():
        if checks.get(key):
            print(f"  {Fore.GREEN}{ok_msg}")
        else:
            print(f"  {Fore.RED}{fail_msg}")

    # --- Sección: Phishing ---
    print(f"\n{Fore.YELLOW}[ DETECCIÓN DE PHISHING ]{Style.RESET_ALL}")
    palabras = result.get("palabras_sospechosas", [])
    if palabras:
        print(f"  {Fore.RED}✘ Palabras sospechosas encontradas: {', '.join(palabras)}")
    else:
        print(f"  {Fore.GREEN}✔ Sin palabras sospechosas")

    # --- Sección: VirusTotal ---
    print(f"\n{Fore.YELLOW}[ VIRUSTOTAL ]{Style.RESET_ALL}")
    vt = result.get("virustotal", {})
    if vt.get("error"):
        print(f"  {Fore.MAGENTA}⚠ {vt['error']}")
    elif vt.get("omitido"):
        print(f"  {Fore.MAGENTA}⚠ Análisis de VT omitido (sin API Key)")
    else:
        print(f"  Maliciosos:   {Fore.RED}{vt.get('malicious', 0)}")
        print(f"  Sospechosos:  {Fore.YELLOW}{vt.get('suspicious', 0)}")
        print(f"  Limpios:      {Fore.GREEN}{vt.get('harmless', 0)}")
        print(f"  Sin detectar: {Fore.WHITE}{vt.get('undetected', 0)}")

    # --- Score final ---
    print(f"\n{Fore.YELLOW}[ RESULTADO FINAL ]{Style.RESET_ALL}")
    print(f"  Score de riesgo: {color}{score}/100{Style.RESET_ALL}")
    print(f"  Clasificación:   {color}[ {label} ]{Style.RESET_ALL}\n")

    # Guardar log
    logger.save(url, score, label)


def run_interactive(analyzer: URLAnalyzer, logger: URLLogger) -> None:
    """Modo interactivo: el usuario ingresa URLs una por una."""
    print(f"\n{Fore.CYAN}Modo interactivo — escribe 'salir' para terminar.{Style.RESET_ALL}")
    while True:
        try:
            url = input(f"\n{Fore.WHITE}» URL a analizar: {Style.RESET_ALL}").strip()
            if url.lower() in ("salir", "exit", "q"):
                print(f"{Fore.CYAN}¡Hasta luego!{Style.RESET_ALL}")
                break
            if url:
                analyze_single_url(url, analyzer, logger)
        except KeyboardInterrupt:
            print(f"\n{Fore.CYAN}Interrumpido. ¡Hasta luego!{Style.RESET_ALL}")
            break


def main() -> None:
    print_banner()
    analyzer = URLAnalyzer()
    logger = URLLogger()

    # Si se pasa una URL como argumento: modo directo
    if len(sys.argv) > 1:
        url = sys.argv[1]
        analyze_single_url(url, analyzer, logger)
    else:
        run_interactive(analyzer, logger)


if __name__ == "__main__":
    main()