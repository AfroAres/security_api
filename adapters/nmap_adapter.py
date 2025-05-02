import subprocess
import os
import xml.etree.ElementTree as ET
import tempfile
import logging

# Configuración básica para logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class NmapAdapter:
    @staticmethod
    def scan(ips: list) -> dict:
        """
        Ejecuta un escaneo Nmap sobre una lista de IPs y devuelve un diccionario con los resultados.
        
        :param ips: Lista de direcciones IP a escanear.
        :return: Diccionario donde cada clave es una IP y su valor es otro diccionario
                 con 'status', 'data' (en caso de éxito) o 'error' (en caso de fallo).
        """
        results = {}
        for ip in ips:
            xml_output = None
            try:
                # Crear archivo temporal para la salida XML
                with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp_file:
                    xml_output = tmp_file.name
                logging.info(f"Escaneando IP: {ip} - Archivo temporal: {xml_output}")

                # Ejecuta Nmap con las opciones especificadas
                subprocess.run(
                    ["nmap", "-A", "-Pn", "-T4", "-oX", xml_output, ip],
                    check=True,
                    capture_output=True
                )
                
                # Parsear el resultado XML en un diccionario estructurado
                parsed_data = NmapAdapter.parse_nmap(xml_output)
                results[ip] = {"status": "success", "data": parsed_data}
            except subprocess.CalledProcessError as e:
                logging.error(f"Error al ejecutar nmap para {ip}: {e}")
                results[ip] = {"status": "failed", "error": str(e)}
            except ET.ParseError as e:
                logging.error(f"Error al parsear el XML para {ip}: {e}")
                results[ip] = {"status": "failed", "error": f"Error de parseo XML: {str(e)}"}
            except Exception as e:
                logging.error(f"Error inesperado para {ip}: {e}")
                results[ip] = {"status": "failed", "error": f"Error inesperado: {str(e)}"}
            finally:
                # Intentar eliminar el archivo temporal si fue creado
                if xml_output and os.path.exists(xml_output):
                    os.remove(xml_output)
        return results

    @staticmethod
    def parse_nmap(xml_path: str) -> dict:
        """
        Parsea el archivo XML generado por Nmap y extrae la información del host y sus puertos.
        
        :param xml_path: Camino al archivo XML generado por Nmap.
        :return: Diccionario con la información del host (IP y puertos).
        """
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        host_info = {"ip": "", "ports": []}
        host = root.find("host")
        if host is not None:
            address = host.find("address")
            if address is not None:
                host_info["ip"] = address.attrib.get("addr", "")
            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    port_data = {
                        "port": port.attrib.get("portid", ""),
                        "protocol": port.attrib.get("protocol", ""),
                        "state": port.find("state").attrib.get("state", "") if port.find("state") is not None else "",
                        "service": {}
                    }
                    service = port.find("service")
                    if service is not None:
                        port_data["service"] = {
                            "name": service.attrib.get("name", ""),
                            "product": service.attrib.get("product", ""),
                            "version": service.attrib.get("version", "")
                        }
                    host_info["ports"].append(port_data)
        return host_info
