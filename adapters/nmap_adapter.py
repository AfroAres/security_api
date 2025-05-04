import subprocess
import os
import logging

# Configuración básica para logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class NmapAdapter:
    @staticmethod
    def scan(ips: list) -> dict:
        results = {}

        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nmap_scaner.py")

        if not os.path.exists(script_path):
            logging.error(f"Script no encontrado: {script_path}")
            return {"status": "error", "message": "Script nmap_scaner.py no encontrado."}

        for ip in ips:
            try:
                logging.info(f"Ejecutando escaneo Nmap para {ip} usando {script_path}")
                process = subprocess.run(
                    ["python3", script_path],
                    input=ip,
                    text=True,
                    capture_output=True,
                    check=True
                )

                output = process.stdout.strip()
                logging.info(f"Resultado del escaneo:\n{output}")
                results[ip] = {"status": "success", "output": output}

            except subprocess.CalledProcessError as e:
                logging.error(f"Error ejecutando el script para {ip}: {e.stderr}")
                results[ip] = {"status": "failed", "error": str(e)}
            except Exception as e:
                logging.error(f"Error inesperado para {ip}: {e}")
                results[ip] = {"status": "failed", "error": f"Error inesperado: {str(e)}"}

        return results
