from Security_api.scanners.google_dorks_scan import execute_google_dorks
from typing import List, Dict

class GoogleDorksAdapter:
    """
    Adaptador para la funcionalidad de escaneo con Google Dorks.
    """

    @staticmethod
    def scan_dorks(dorks: List[str]) -> Dict:
        """
        Ejecuta búsquedas utilizando Google Dorks para una lista de dorks especificada.

        :param dorks: Lista de consultas Google Dorks.
        :return: Diccionario con los resultados del escaneo o mensaje de error.
        """
        if not dorks:
            return {"error": "La lista de dorks no puede estar vacía."}

        try:
            results = execute_google_dorks(dorks)
            # Aseguramos un formato de respuesta uniforme
            if results.get("status") != "success":
                return {
                    "status": "failed",
                    "error": results.get("message", "Error desconocido en Google Dorks")
                }
            return {"status": "success", "data": results.get("data")}
        except Exception as e:
            return {
                "status": "failed",
                "error": f"Error inesperado en Google Dorks: {str(e)}"
            }
