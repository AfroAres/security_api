from scanners.dns_scan import resolve_dns_records
from scanners.whois_scan import resolve_whois
from scanners.nmap_scan import perform_nmap_scan
from Security_api.scanners.google_dorks_scan import execute_google_dorks
from typing import Dict, List

class ScannerManager:
    """
    Gestor central para manejar múltiples herramientas de escaneo.
    """

    def dns_scan(self, domain: str, record_types: List[str] = None) -> Dict:
        """
        Escanea registros DNS para un dominio especificado.
        """
        return resolve_dns_records(domain, record_types)

    def whois_scan(self, domain: str) -> Dict:
        """
        Realiza un escaneo WHOIS para un dominio.
        """
        return resolve_whois(domain)

    def nmap_scan(self, ip: str) -> Dict:
        """
        Ejecuta un escaneo Nmap para una dirección IP.
        """
        return perform_nmap_scan(ip)

    def google_dorks_scan(self, dorks: List[str]) -> Dict:
        """
        Ejecuta búsquedas con Google Dorks.
        """
        return {"results": execute_google_dorks(dorks)}
