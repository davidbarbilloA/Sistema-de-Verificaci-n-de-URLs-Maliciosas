"""
report_generator.py — Generador de informes de ciberseguridad profesional (SOC/Blue Team).
Transforma los resultados del análisis técnico en un informe ejecutivo y técnico estructurado.
"""

import json
from datetime import datetime
from colorama import Fore, Style

class ReportGenerator:
    """
    Clase encargada de generar informes con formato SOC Corporativo.
    """

    def generate_soc_report(self, data: dict) -> str:
        """
        Genera un informe en texto plano siguiendo la estructura solicitada por el SOC.
        """
        # Extraer datos básicos
        url = data.get("url", "N/A")
        score = data.get("score", 0)
        ip_data = data.get("ip", {})
        vt_data = data.get("virustotal", {})
        whois_data = data.get("whois", {})
        ssl_data = data.get("ssl", {})
        html_data = data.get("html", {})
        ml_data = data.get("ml", {})
        redirects = data.get("redirects", {})

        # Inferir Riesgo y Amenaza
        riesgo = "LOW"
        if score > 80: riesgo = "CRITICAL"
        elif score > 60: riesgo = "HIGH"
        elif score > 30: riesgo = "MEDIUM"

        # Tipo de amenaza e impacto (Inferencia lógica SOC)
        tipo_amenaza = "No concluyente / Bajo Riesgo"
        impacto = "Riesgo bajo o no concluyente"
        
        if html_data.get("has_login_form") and (riesgo in ["HIGH", "CRITICAL"] or whois_data.get("is_new")):
            tipo_amenaza = "Credential Harvesting / Phishing"
            impacto = "Robo de credenciales corporativas y compromiso de identidad."
        elif vt_data.get("malicious", 0) > 0:
            tipo_amenaza = "Malware Delivery"
            impacto = "Infección de endpoint y potencial persistencia en la red corporativa."
        elif redirects.get("count", 0) > 3:
            tipo_amenaza = "Suspicious Redirect Chain"
            impacto = "Exposición de usuarios a contenido malicioso o evasión de controles."
        elif score > 30 and score <= 60:
            tipo_amenaza = "Suspicious Activity / Potential Scam"
            impacto = "Exposición de usuarios a sitios de dudosa reputación."

        if score == 0 or (data.get("valida") and score < 20 and not whois_data.get("is_new")):
            if "google" in url or "microsoft" in url or "github" in url:
                tipo_amenaza = "Posible Falso Positivo"
                riesgo = "LOW"

        # Construcción del informe
        report = []
        report.append("="*80)
        report.append("   INFORME DE ANÁLISIS DE CIBERSEGURIDAD - SOC UNIT")
        report.append("="*80)
        report.append(f"FECHA: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"ID DE ANÁLISIS: SOC-{datetime.now().strftime('%y%m%d%H%M')}")
        report.append("-"*80)
        
        report.append("\n1. RESUMEN EJECUTIVO")
        report.append(f"Se ha realizado un análisis técnico de la URL {url} tras una alerta del sistema corporativo.")
        report.append(f"El análisis heurístico y de inteligencia de amenazas otorga un nivel de riesgo {riesgo}.")
        
        report.append("\n2. CLASIFICACIÓN DE RIESGO")
        report.append(f"[{riesgo}]")
        
        report.append("\n3. TIPO DE AMENAZA DETECTADA")
        report.append(tipo_amenaza)
        
        report.append("\n4. INDICADORES TÉCNICOS")
        report.append(f"  • Dirección IP: {ip_data.get('ip', 'N/A')} ({ip_data.get('isp', 'Unknown')})")
        report.append(f"  • Geolocalización: {ip_data.get('city', 'N/A')}, {ip_data.get('country', 'N/A')}")
        report.append(f"  • Antigüedad del Dominio: {whois_data.get('age_days', 'N/A')} días")
        report.append(f"  • Redirecciones Detectadas: {redirects.get('count', 0)}")
        report.append(f"  • Certificado SSL: {'Válido' if ssl_data.get('valid') else 'Inválido/Ausente'}")
        
        report.append("\n5. EVIDENCIAS RELEVANTES")
        if html_data.get("has_login_form"):
            report.append("  • [!] Se detectó un formulario de captura de credenciales (Login/Password).")
        if vt_data.get("malicious", 0) > 0:
            report.append(f"  • [!] VirusTotal reporta {vt_data['malicious']} detecciones maliciosas.")
        if whois_data.get("is_new"):
            report.append(f"  • [!] Dominio recientemente registrado ({whois_data.get('age_days')} días).")
        if ml_data.get("probability", 0) > 50:
            report.append(f"  • [!] El modelo de ML clasifica la URL como {ml_data.get('prediction')} ({ml_data.get('probability')}%).")
        if not report[-1].startswith("  •"): # Si no hay evidencias específicas
            report.append("  • No se detectaron indicadores críticos inmediatos.")

        report.append("\n6. IMPACTO POTENCIAL")
        report.append(impacto)
        
        report.append("\n7. IOC IDENTIFICADOS (Indicators of Compromise)")
        report.append(f"  • URL: {url}")
        if ip_data.get('ip'): report.append(f"  • IP: {ip_data.get('ip')}")
        if redirects.get("final_url"): report.append(f"  • FINAL_URL: {redirects.get('final_url')}")
        
        report.append("\n8. RECOMENDACIONES")
        if riesgo in ["HIGH", "CRITICAL"]:
            report.append("  • BLOQUEO INMEDIATO: Mantener el bloqueo en el Firewall/Proxy corporativo.")
            report.append("  • INVESTIGACIÓN: Verificar si algún usuario ha interactuado con la URL.")
            report.append("  • PURGA: Eliminar cualquier correo electrónico que contenga este enlace.")
        elif riesgo == "MEDIUM":
            report.append("  • MONITOREO: Vigilar el tráfico hacia este dominio e IP.")
            report.append("  • EDUCACIÓN: Reforzar concienciación sobre phishing a los usuarios.")
        else:
            report.append("  • OBSERVACIÓN: Validar si es una herramienta de negocio necesaria.")
            report.append("  • WHITELISTING: Si se confirma legítimo, proceder con el desbloqueo.")

        report.append("\n9. CONCLUSIÓN FINAL")
        if riesgo in ["HIGH", "CRITICAL"]:
            report.append(f"La evidencia técnica sugiere una amenaza de tipo {tipo_amenaza}. Se recomienda proceder con el protocolo de contención.")
        else:
            report.append(f"Análisis finalizado con riesgo {riesgo}. La actividad observada no permite confirmar una intención maliciosa inmediata.")
        
        report.append("-"*80)
        report.append("FIN DEL INFORME")
        
        return "\n".join(report)
