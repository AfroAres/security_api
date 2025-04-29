from scanners.dns_scan import resolve_dns_records
from typing import List, Dict

class DNSAdapter:
    """
    Adaptador para la funcionalidad de escaneo DNS.
    """
    def scan_records(self, domain: str, record_types: List[str] = None) -> Dict:
        """
        Escanea los registros DNS para un dominio especificado.

        :param domain: Dominio a consultar.
        :param record_types: Lista opcional de tipos de registros DNS (A, MX, etc.).
        :return: Diccionario con los registros DNS o mensaje de error.
        """
        if not domain:
            return {"error": "El dominio no puede estar vacío."}

        try:
            dns_data = resolve_dns_records(domain, record_types)
            if "error" in dns_data:
                return {"domain": domain, "status": "failed", "error": dns_data["error"]}
            return {"domain": domain, "status": "success", "records": dns_data["records"]}
        except Exception as e:
            return {"domain": domain, "status": "failed", "error": f"Error inesperado: {str(e)}"}
