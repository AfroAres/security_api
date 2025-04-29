import dns.resolver
from typing import Dict, List

def resolve_dns_records(domain: str, record_types: List[str] = None) -> Dict:
    """
    Resuelve los registros DNS del dominio para los tipos especificados.

    :param domain: Dominio a resolver.
    :param record_types: Lista de tipos de registros DNS a consultar (A, AAAA, MX, etc.).
    :return: Diccionario con los resultados de los registros DNS.
    """
    record_types = record_types or ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
    resolver = dns.resolver.Resolver()
    results = {"domain": domain, "records": {}}

    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            results["records"][record_type] = [str(data) for data in answers]
        except dns.resolver.NoAnswer:
            results["records"][record_type] = []
        except dns.resolver.NXDOMAIN:
            return {"error": f"El dominio {domain} no existe."}
        except Exception as e:
            results["records"][record_type] = {"error": str(e)}

    return results
