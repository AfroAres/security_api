#!/usr/bin/env python3
import sys
import logging
from scanners.nmap_scan import perform_nmap_scan, format_scan_results_to_text
from adapters.dns_adapter import DNSAdapter
import json
from scanners.scanner import Scanner


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def save_scanner_results(domain: str, filename: str) -> None:
    if not domain:
        logging.error("El dominio no puede estar vacío.")
        print("Error: Debes ingresar un dominio válido.")
        return
    
    results_text = []

    # ------------------------
    # DNS Scan (utilizando el adaptador)
    # ------------------------
    logging.info(f"Ejecutando DNS Scan para {domain}")
    results_text.append("----- DNS Scan Results -----")
    dns_result = DNSAdapter.scan_records(domain)
    if dns_result["status"] == "success":
        for record_type, records in dns_result["records"].items():
            results_text.append(f"{record_type}: {', '.join(records)}")
    else:
        results_text.append(f"Error en DNS Scan: {dns_result.get('error', 'Desconocido')}")
    results_text.append("")  # Separador

    # ------------------------
    # Nmap Scan (utilizando el scanner adaptado)
    # ------------------------
    logging.info(f"Ejecutando Nmap Scan para {domain}")
    ip = domain 
    nmap_result = perform_nmap_scan(ip)

    # Convertir los resultados del Nmap a texto
    nmap_text = format_scan_results_to_text(nmap_result)
    results_text.append("----- Nmap Scan Results -----")
    results_text.append(nmap_text)
    results_text.append("")

    # ------------------------
    # Whois Scan
    # ------------------------
    logging.info(f"Ejecutando Whois Scan para {domain}")
    scanner = Scanner()
    whois_result = scanner.whois_scan(domain) 
    results_text.append("----- Whois Scan Results -----")
    if whois_result.get("status") == "success":
        for key, value in whois_result.items():
            results_text.append(f"{key}: {value}")
    else:
        error_message = whois_result.get("error", "Error desconocido en Whois Scan.")
        logging.error(f"Whois Scan falló: {error_message}")
        results_text.append(f"Error en Whois Scan: {error_message}")
    results_text.append("")

    # ------------------------
    # Google Dorks Scan
    # ------------------------
    logging.info(f"Ejecutando Google Dorks Scan para {domain}")
    dorks_query = [f"inurl:admin", f"site:{domain}"]
    dorks_result = scanner.google_dorks_scan(dorks_query)
    results_text.append("----- Google Dorks Scan Results -----")
    if dorks_result.get("status") == "success":
        for idx, result in enumerate(dorks_result.get("data", []), start=1):
            results_text.append(f"--- Resultado #{idx} ---")
            results_text.append(f"Título: {result.get('title','N/A')}")
            results_text.append(f"Link: {result.get('link','N/A')}")
            results_text.append(f"Descripción: {result.get('snippet','N/A')}")
            results_text.append("-" * 40)
    else:
        error_message = dorks_result.get("error", "Error desconocido en Google Dorks Scan.")
        logging.error(f"Google Dorks Scan falló: {error_message}")
        results_text.append(f"Error en Google Dorks Scan: {error_message}")
    results_text.append("")

    with open(filename, "w", encoding="utf-8") as f:
        for line in results_text:
            f.write(line + "\n")
    
    logging.info(f"Resultados guardados en {filename}")
    print("Resultados guardados en", filename)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python scanner_script.py <DOMINIO>")
        sys.exit(1)
    
    domain = sys.argv[1]
    output_filename = f"scanner_results_{domain}.txt"
    save_scanner_results(domain, output_filename)
