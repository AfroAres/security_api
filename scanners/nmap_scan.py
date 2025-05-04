import nmap
import logging

# Configuración de logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def perform_nmap_scan(ip: str, ports: str = "80,443") -> dict:
    """
    Realiza un escaneo básico de Nmap en los puertos más comunes.

    :param ip: Dirección IP o dominio a escanear.
    :param ports: Puertos específicos a escanear (por defecto "80,443").
    :return: Diccionario con el estado y los resultados del escaneo.
    """
    scanner = nmap.PortScanner()
    results = {}

    try:
        logging.info(f"Iniciando escaneo Nmap para IP: {ip}, Puertos: {ports}")
        scan_data = scanner.scan(ip, ports, arguments="-Pn -T4 -sV")

        if "scan" not in scan_data or not scan_data["scan"]:
            logging.error(f"Nmap no devolvió datos para la IP: {ip}")
            return {"status": "failed", "error": "Nmap no detectó el host o no hay datos disponibles."}

        results["status"] = "success"
        results["data"] = process_scan_results(scan_data["scan"])
    except nmap.PortScannerError as e:
        logging.error(f"Error del escáner Nmap: {e}")
        results["status"] = "error"
        results["message"] = f"Error del escáner Nmap: {e}"
    except Exception as e:
        logging.error(f"Error inesperado durante el escaneo Nmap: {e}")
        results["status"] = "error"
        results["message"] = f"Error inesperado: {e}"

    return results

def process_scan_results(scan_data: dict) -> list:
    """
    Procesa los resultados del escaneo Nmap para mostrarlos de forma clara.

    :param scan_data: Resultados sin procesar del escaneo.
    :return: Lista de diccionarios con detalles del escaneo.
    """
    structured_results = []

    for host, host_data in scan_data.items():
        host_status = host_data.get("status", {}).get("state", "desconocido")
        if host_status != "up":
            logging.warning(f"El host {host} no está activo según Nmap.")
            continue

        host_info = {
            "host": host,
            "state": host_status,
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

def format_scan_results_to_text(results: dict) -> str:
    """
    Convierte los resultados del escaneo Nmap en texto legible.
    :param results: Diccionario retornado por perform_nmap_scan.
    :return: Texto plano para guardar en un archivo.
    """
    if results.get("status") != "success":
        return f"[NMAP] Error: {results.get('message', results.get('error', 'Escaneo fallido o sin datos.'))}\n"

    text_output = "[NMAP] Resultados del escaneo:\n"
    for host_result in results["data"]:
        text_output += f"- Host: {host_result['host']} (Estado: {host_result['state']})\n"
        for port in host_result["ports"]:
            text_output += f"    • Puerto {port['port']}/tcp: {port['state']} - {port['service']} ({port['version']})\n"
    return text_output

if __name__ == "__main__":
    ip = input("Ingrese la dirección IP o dominio a escanear: ")
    results = perform_nmap_scan(ip)
    print(format_scan_results_to_text(results))
