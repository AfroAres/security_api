# /Security_api/scanners/scanner.py

from adapters.dns_adapter import DNSAdapter
from adapters.whois_adapter import WhoisAdapter
from adapters.nmap_adapter import NmapAdapter
from adapters.google_dorks_adapter import GoogleDorksAdapter
from typing import List, Dict


class Scanner:
    """
    Gestor central para manejar múltiples herramientas de escaneo a través de sus adapters.
    Cada método delega a su adapter correspondiente usando la interfaz estandarizada.
    """

    def dns_scan(self, domain: str, record_types: List[str] = None) -> Dict:
        """
        Ejecuta un escaneo DNS para el dominio especificado.
        """
        return DNSAdapter.scan_records(domain, record_types)

    def whois_scan(self, domain: str) -> Dict:
        """
        Ejecuta una consulta WHOIS para el dominio especificado.
        """
        return WhoisAdapter.scan_domain(domain)

    def nmap_scan(self, ips: List[str]) -> Dict:
        """
        Ejecuta un escaneo Nmap sobre la lista de IPs especificada.
        """
        return NmapAdapter.scan(ips)

    def google_dorks_scan(self, dorks: List[str]) -> Dict:
        """
        Ejecuta búsquedas utilizando los dorks especificados.
        """
        return GoogleDorksAdapter.scan_dorks(dorks)
