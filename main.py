"""
Malicious URL Checker - Entry point
"""

import sys
import os
import asyncio
from colorama import init, Fore, Style
from analyzer import URLAnalyzer
from logger import URLLogger
from utils import print_banner, get_risk_label, get_risk_color

# Inicializar colorama
init(autoreset=True)

def analyze_single_url(url: str, analyzer: URLAnalyzer, logger: URLLogger) -> None:
    """Analiza una sola URL y muestra los resultados en consola."""
    print(f"\n{Fore.CYAN}{'-'*65}")
    print(f"  Iniciando análisis profundo para: {Fore.WHITE}{url}")
    print(f"{Fore.CYAN}{'-'*65}{Style.RESET_ALL}")

    result = analyzer.analyze(url)
    if not result.get("valida"):
        print(f"{Fore.RED}[!] ERROR: {result.get('error', 'URL inválida')}")
        return

    score = result["score"]
    label, color = get_risk_label(score), get_risk_color(score)

    # --- Redirecciones ---
    reds = result.get("redirects", {})
    if reds.get("count", 0) > 0:
        print(f"\n{Fore.YELLOW}[ REDIRECCIONES ]{Style.RESET_ALL}")
        print(f"  Cadena: {Fore.WHITE} -> ".join(reds["chain"]))
        print(f"  Total:  {Fore.CYAN}{reds['count']} saltos")

    # --- IP Inteligente ---
    ip = result.get("ip", {})
    print(f"\n{Fore.YELLOW}[ IP INTELIGENTE ]{Style.RESET_ALL}")
    if ip.get("error"):
        print(f"  {Fore.MAGENTA}[!] {ip['error']}")
    else:
        print(f"  IP:      {Fore.WHITE}{ip.get('ip')}")
        print(f"  Ubic.:   {Fore.WHITE}{ip.get('city')}, {ip.get('country')}")
        print(f"  ISP:     {Fore.WHITE}{ip.get('isp')}")

    # --- Análisis HTML ---
    html = result.get("html", {})
    print(f"\n{Fore.YELLOW}[ ANALISIS HTML ]{Style.RESET_ALL}")
    if html.get("error"):
        print(f"  {Fore.MAGENTA}[!] {html['error']}")
    else:
        print(f"  Título:  {Fore.WHITE}{html.get('title')}")
        print(f"  Scripts: {Fore.WHITE}{html.get('script_count')}")
        print(f"  Iframes: {Fore.WHITE}{html.get('iframe_count')} ({len(html.get('suspicious_iframes', []))} sospechosos)")
        if html.get("has_login_form"):
            print(f"  {Fore.RED}[!] Detectado formulario de ingreso de credenciales")

    # --- Machine Learning ---
    ml = result.get("ml", {})
    print(f"\n{Fore.YELLOW}[ MACHINE LEARNING ]{Style.RESET_ALL}")
    prob_color = Fore.RED if ml.get("probability", 0) > 60 else Fore.YELLOW if ml.get("probability", 0) > 30 else Fore.GREEN
    print(f"  Predicción:    {prob_color}{ml.get('prediction')}")
    print(f"  Prob. Riesgo:  {prob_color}{ml.get('probability')}%")

    # --- VirusTotal & Otros ---
    # (Omitido por brevedad en consola, pero procesado en score)
    vt = result.get("virustotal", {})
    if vt.get("malicious", 0) > 0:
        print(f"\n{Fore.RED}[!] VirusTotal detectó {vt['malicious']} motores maliciosos")

    # --- Captura de pantalla (Async) ---
    print(f"\n{Fore.YELLOW}[ CAPTURA DE PANTALLA ]{Style.RESET_ALL}")
    shot_path = os.path.join("logs", f"screenshot_{url.replace('://', '_').replace('/', '_').replace(':', '_')}.png")
    print(f"  {Fore.WHITE}Generando captura...")
    
    try:
        shot_result = asyncio.run(analyzer.browser_client.take_screenshot(url, shot_path))
        if shot_result.get("success"):
            print(f"  {Fore.GREEN}[+] Captura guardada en: {shot_result['path']}")
        else:
            print(f"  {Fore.RED}[!] {shot_result.get('error')}")
    except Exception as e:
        print(f"  {Fore.RED}[!] Error inesperado en captura: {e}")

    # --- Score final ---
    print(f"\n{Fore.CYAN}{'='*65}")
    print(f"  SCORE FINAL DE RIESGO: {color}{score}/100")
    print(f"  CLASIFICACIÓN:         {color}[ {label} ]")
    print(f"{Fore.CYAN}{'='*65}\n")

    logger.save(url, score, label)

def run_interactive(analyzer: URLAnalyzer, logger: URLLogger) -> None:
    print(f"\n{Fore.CYAN}Modo interactivo activo. Escribe 'salir' para terminar.{Style.RESET_ALL}")
    while True:
        try:
            url = input(f"\n{Fore.WHITE}>> URL a analizar: {Style.RESET_ALL}").strip()
            if url.lower() in ("salir", "exit", "q"): break
            if url:
                if not url.startswith("http"): url = "http://" + url
                analyze_single_url(url, analyzer, logger)
        except KeyboardInterrupt: break

def main() -> None:
    print_banner()
    analyzer = URLAnalyzer()
    logger = URLLogger()
    if len(sys.argv) > 1:
        url = sys.argv[1]
        if not url.startswith("http"): url = "http://" + url
        analyze_single_url(url, analyzer, logger)
    else:
        run_interactive(analyzer, logger)

if __name__ == "__main__":
    main()