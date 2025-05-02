import nmap
import logging
from typing import Dict, List, Union

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def perform_nmap_scan(ip: str, ports: str = "1-1024", options: str = "-sV") -> Dict:
    """
    Realiza un escaneo Nmap para una dirección IP y rango de puertos especificados.

    :param ip: Dirección IP a escanear.
    :param ports: Rango de puertos para escanear (por defecto "1-1024").
    :param options: Opciones adicionales para Nmap (por defecto "-sV" para detección de servicios).
    :return: Diccionario con el estado y los resultados del escaneo.
    """
    scanner = nmap.PortScanner()
    results = {}

    try:
        logging.info(f"Iniciando escaneo Nmap para IP: {ip}, Puertos: {ports}, Opciones: {options}")
        scan_data = scanner.scan(ip, ports, arguments=options)

        # Procesar resultados
        results["status"] = "success"
        results["data"] = process_scan_results(scan_data.get("scan", {}))
    except nmap.PortScannerError as e:
        logging.error(f"Error del escáner Nmap: {e}")
        results["status"] = "error"
        results["message"] = f"Error del escáner Nmap: {e}"
    except Exception as e:
        logging.error(f"Error inesperado durante el escaneo Nmap: {e}")
        results["status"] = "error"
        results["message"] = f"Error inesperado: {e}"

    return results

def process_scan_results(scan_data: Dict) -> List[Dict[str, Union[str, int]]]:
    """
    Procesa los resultados del escaneo Nmap para convertirlos en un formato estructurado.

    :param scan_data: Resultados sin procesar del escaneo.
    :return: Lista de diccionarios con detalles del escaneo (host, puertos, estado, servicios).
    """
    structured_results = []

    for host, host_data in scan_data.items():
        host_info = {
            "host": host,
            "state": host_data.get("status", {}).get("state", "desconocido"),
            "ports": []
        }

        if "tcp" in host_data:
            for port, port_info in host_data["tcp"].items():
                host_info["ports"].append({
                    "port": port,
                    "state": port_info.get("state", "desconocido"),
                    "service": port_info.get("name", "desconocido"),
                    "version": port_info.get("version", "N/A")
                })

        structured_results.append(host_info)

    return structured_results

def save_scan_results(results: List[Dict], filename: str) -> None:
    """
    Guarda los resultados del escaneo en un archivo JSON para análisis posterior.

    :param results: Resultados procesados del escaneo Nmap.
    :param filename: Nombre del archivo donde se guardarán los resultados.
    """
    import json
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        logging.info(f"Resultados del escaneo guardados en {filename}")
    except Exception as e:
        logging.error(f"Error al guardar los resultados: {e}")
