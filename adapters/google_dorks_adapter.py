from scanners.google_dorks import execute_google_dorks
from typing import List, Dict

class GoogleDorksAdapter:
    """
    Adaptador para la funcionalidad de búsqueda con Google Dorks.
    """
    def search_dorks(self, dorks: List[str]) -> Dict:
        """
        Ejecuta múltiples búsquedas de Google Dorks utilizando el módulo `google_dorks.py`.

        :param dorks: Lista de consultas Dorks a ejecutar.
        :return: Diccionario con los resultados o mensajes de error.
        """
        if not dorks:
            return {"error": "La lista de Dorks no puede estar vacía."}

        try:
            results = execute_google_dorks(dorks)
            if not results:
                return {"status": "success", "message": "No se encontraron resultados para las búsquedas realizadas."}
            return {"status": "success", "data": results}
        except Exception as e:
            return {"status": "failed", "error": f"Error inesperado durante la búsqueda: {str(e)}"}
