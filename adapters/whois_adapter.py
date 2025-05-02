from scanners.whois_scan import resolve_whois
from typing import Dict

class WhoisAdapter:
    """
    Adaptador para la funcionalidad de escaneo Whois.
    """

    @staticmethod
    def scan_domain(domain: str) -> Dict:
        """
        Ejecuta un escaneo Whois para un dominio y maneja la salida.

        :param domain: Dominio a consultar.
        :return: Diccionario con resultados o mensajes de error.
        """
        if not domain:
            return {"error": "El dominio no puede estar vacío."}

        try:
            whois_data = resolve_whois(domain)
            if "error" in whois_data:
                return {"domain": domain, "status": "failed", "error": whois_data["error"]}
            return {"domain": domain, "status": "success", "data": whois_data}
        except Exception as e:
            return {"domain": domain, "status": "failed", "error": f"Error inesperado: {str(e)}"}
