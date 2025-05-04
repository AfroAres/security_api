import dns.resolver
import logging
from typing import Dict, List, Union

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def resolve_dns_records(domain: str, record_types: List[str] = None) -> Dict[str, Union[str, Dict[str, List[Union[str, Dict[str, str]]]]]]:
    """
    Resuelve los registros DNS del dominio para los tipos especificados.

    :param domain: Dominio a resolver.
    :param record_types: Lista de tipos de registros DNS a consultar (A, AAAA, MX, etc.).
    :return: Diccionario con los resultados de los registros DNS o errores.
    """

    record_types = record_types or ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
    resolver = dns.resolver.Resolver()
    results = {"domain": domain, "records": {}}

    for record_type in record_types:
        try:
            logging.info(f"Resolviendo registros DNS para {domain} ({record_type})")
            answers = resolver.resolve(domain, record_type)
            results["records"][record_type] = [str(data) for data in answers]
        except dns.resolver.NoAnswer:
            logging.warning(f"No hay respuesta para el tipo de registro {record_type}")
            results["records"][record_type] = []
        except dns.resolver.NXDOMAIN:
            logging.error(f"El dominio {domain} no existe.")
            return {"status": "error", "message": f"El dominio {domain} no existe."}
        except dns.resolver.Timeout:
            logging.error(f"Tiempo de espera agotado al resolver {record_type} para {domain}")
            results["records"][record_type] = {"error": "Timeout al resolver registro"}
        except Exception as e:
            logging.error(f"Error al resolver {record_type} para {domain}: {e}")
            results["records"][record_type] = {"error": str(e)}

    results["status"] = "success"
    return results
