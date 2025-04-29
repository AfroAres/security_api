import whois
from typing import Dict

def resolve_whois(domain: str) -> Dict:
    """
    Realiza una consulta WHOIS para el dominio especificado.

    :param domain: Dominio a consultar.
    :return: Diccionario con los resultados del WHOIS.
    """
    try:
        w = whois.whois(domain)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "country": w.country,
            "whois_server": w.whois_server,
            "updated_date": str(w.updated_date),
        }
    except Exception as e:
        return {"error": f"Error en consulta Whois: {str(e)}"}
