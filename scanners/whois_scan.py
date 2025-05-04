import whois
import re
import logging
from typing import Dict, Optional

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_valid_domain(domain: str) -> bool:
    """
    Valida si el dominio tiene un formato válido.

    :param domain: Dominio a validar.
    :return: True si es válido, False en caso contrario.
    """
    pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain) is not None

def resolve_whois(domain: str) -> Dict:
    """
    Realiza una consulta WHOIS para el dominio especificado y devuelve información estructurada.

    :param domain: Dominio a consultar.
    :return: Diccionario con los resultados del WHOIS o un mensaje de error.
    """
    if not is_valid_domain(domain):
        return {"status": "error", "message": "El dominio no tiene un formato válido."}

    try:
        logging.info(f"Realizando consulta WHOIS para el dominio: {domain}")
        w = whois.whois(domain)
        
        def format_date(value):
            if isinstance(value, list):
                return [str(date) for date in value]
            return str(value)

        return {
            "status": "success",
            "data": {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": format_date(w.creation_date),
                "expiration_date": format_date(w.expiration_date),
                "updated_date": format_date(w.updated_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "country": w.country,
                "whois_server": w.whois_server,
            },
        }
    except whois.parser.PywhoisError as e:
        logging.error(f"Error en consulta WHOIS: {e}")
        return {"status": "error", "message": f"No se encontró información para el dominio {domain}."}
    except Exception as e:
        logging.error(f"Error inesperado durante la consulta WHOIS: {e}")
        return {"status": "error", "message": f"Error inesperado: {e}"}
