import os
import requests
from requests.exceptions import ConnectionError, Timeout, RequestException
from dotenv import load_dotenv
import logging
from typing import List, Dict

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def load_env_variables() -> Dict[str, str]:
    load_dotenv()
    api_key = os.getenv('GOOGLE_API_KEY')
    search_engine_id = os.getenv('GOOGLE_SEARCH_ENGINE_ID')


    if not api_key or not search_engine_id:
        raise ValueError("API Key o Search Engine ID no encontrados en el archivo .env")
    return {
        'api_key': api_key,
        'search_engine_id': search_engine_id
    }

def perform_google_search(api_key: str, search_engine_id: str, query: str, start: int = 1, lang: str = "lang_es") -> List[Dict]:
    base_url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": api_key,
        "cx": search_engine_id,
        "q": query,
        "start": start,
        "lr": lang,
    }

    try:
        response = requests.get(base_url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("items", [])
    except (ConnectionError, Timeout, RequestException, ValueError) as e:
        logging.error(f"Error durante la solicitud: {e}")
        return []
    
def save_results_to_file(results: List[Dict], filename: str) -> None:
    with open(filename, "w", encoding="utf-8") as f:
        for result in results:
            f.write("------- Nuevo resultado -------\n")
            f.write(f"Título: {result.get('title')}\n")
            f.write(f"Descripción: {result.get('snippet')}\n")
            f.write(f"Enlace: {result.get('link')}\n")
            f.write("-------------------------------\n\n")
    logging.info(f"Resultados guardados en {filename}")

def execute_google_dorks(dorks: List[str]) -> Dict:
    try:
        env_vars = load_env_variables()
    except ValueError as e:
        logging.error(e)
        return {"status": "error", "message": str(e)}

    all_results = []
    for query in dorks:
        logging.info(f"Ejecutando búsqueda: {query}")
        results = perform_google_search(env_vars['api_key'], env_vars['search_engine_id'], query)
        if results:
            all_results.extend(results)

    return {"status": "success", "data": all_results} if all_results else {"status": "error", "message": "No se encontraron resultados"}
