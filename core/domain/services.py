import shodan
import os

class ShodanService:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        if not self.api_key:
            raise ValueError("Falta la API Key de Shodan (usa SHODAN_API_KEY como variable de entorno)")
        self.client = shodan.Shodan(self.api_key)

    def search_dvwa(self):
        try:
            # Buscar máquinas con DVWA
            results = self.client.search("DVWA")
            return results
        except shodan.APIError as e:
            raise RuntimeError(f"Error en la API de Shodan: {e}")
