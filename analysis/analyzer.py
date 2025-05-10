import re  # Para trabajar con expresiones regulares (útil para analizar texto)
import ipaddress  # Para validar y trabajar con direcciones IP
from datetime import datetime  # Para manejar fechas en los resultados WHOIS
import json  # Para manejar datos en formato JSON si es necesario

# Funciones de análisis (se implementarán una por una)
def analizar_dns(dns_results):
    """
    Procesa los resultados DNS y devuelve un análisis organizado.
    """
    analysis = {}

    # Analizar registros A (direcciones IP)
    registros_a = dns_results.get('records', {}).get('A', [])
    analysis['registros_a'] = {
        'total': len(registros_a),
        'ips': registros_a,
        'validas': [ip for ip in registros_a if validar_ip(ip)],
    }

    # Analizar registros NS (servidores de nombres)
    registros_ns = dns_results.get('records', {}).get('NS', [])
    analysis['registros_ns'] = {
        'total': len(registros_ns),
        'servidores': registros_ns,
    }

    # Analizar registros TXT
    registros_txt = dns_results.get('records', {}).get('TXT', [])
    analysis['registros_txt'] = {
        'total': len(registros_txt),
        'detalles': registros_txt,
    }

    # Otros registros (AAAA, CNAME, MX, SOA)
    analysis['otros_registros'] = {
        'AAAA': dns_results.get('records', {}).get('AAAA', []),
        'CNAME': dns_results.get('records', {}).get('CNAME', []),
        'MX': dns_results.get('records', {}).get('MX', []),
        'SOA': dns_results.get('records', {}).get('SOA', []),
    }

    return analysis


def validar_ip(ip):
    """
    Valida si una dirección IP es válida.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def analizar_whois(whois_results):
    """
    Procesa los resultados WHOIS y devuelve un análisis organizado.
    """
    analysis = {}
    data = whois_results.get('data', {}).get('data', {})  # Acceder a los datos anidados

    # Fechas importantes
    creation_date = data.get('creation_date', 'No disponible')
    expiration_date = data.get('expiration_date', 'No disponible')
    updated_date = data.get('updated_date', 'No disponible')

    analysis['fechas'] = {
        'creacion': creation_date,
        'expiracion': expiration_date,
        'actualizacion': updated_date,
        'expira_pronto': calcular_dias_para_expiracion(expiration_date) if expiration_date != 'No disponible' else None,
    }

    # Servidores de nombres
    name_servers = data.get('name_servers', [])
    analysis['servidores_de_nombres'] = {
        'total': len(name_servers),
        'servidores': name_servers,
    }

    # Estado del dominio
    status = data.get('status', [])
    if isinstance(status, list):
        clean_status = [s.split(' ')[0] for s in status]  # Eliminar enlaces
        analysis['estado'] = ', '.join(clean_status)
    else:
        analysis['estado'] = 'No disponible'

    # Correos electrónicos
    emails = data.get('emails', 'No disponible')
    analysis['correos'] = emails if emails else 'No disponible'

    # País
    country = data.get('country', 'No disponible')
    analysis['pais'] = country

    return analysis

def calcular_dias_para_expiracion(expiration_date):
    """
    Calcula los días restantes para la expiración del dominio.
    """
    try:
        exp_date = datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S')
        delta = exp_date - datetime.now()
        return delta.days
    except (ValueError, TypeError):
        return None

def analizar_nmap(nmap_results):
    """
    Procesa los resultados de Nmap y devuelve un análisis simplificado.
    """
    # analysis = {
    #     'host': {'ip': 'No disponible', 'estado': 'No disponible'},
    #     'puertos_abiertos': {'total': 0, 'detalles': []}
    # }

    # # Obtener el campo 'output' de los resultados
    # output = nmap_results.get('test.com', {}).get('output', '')

    # if not output:
    #     return analysis  # Si no hay salida, devolver valores predeterminados

    # # Dividir la salida en líneas
    # lines = output.split('\n')

    # # Buscar la línea del host
    # for line in lines:
    #     if 'Host:' in line:
    #         parts = line.split()
    #         analysis['host']['ip'] = parts[1] if len(parts) > 1 else 'No disponible'
    #         analysis['host']['estado'] = parts[3].strip('()') if len(parts) > 3 else 'No disponible'
    #         break

    # # Buscar líneas de puertos abiertos
    # for line in lines:
    #     if 'tcp' in line:
    #         try:
    #             # Ejemplo de línea: "• Puerto 80/tcp: open - http ()"
    #             parts = line.split(':', 1)
    #             puerto_info = parts[1].strip().split(' - ') if len(parts) > 1 else []
    #             analysis['puertos_abiertos']['detalles'].append({
    #                 'puerto': puerto_info[0].strip() if len(puerto_info) > 0 else 'No disponible',
    #                 'servicio': puerto_info[1].strip().replace('()', '') if len(puerto_info) > 1 else 'No disponible',
    #             })
    #         except Exception:
    #             # Manejar errores en el formato de la línea
    #             analysis['puertos_abiertos']['detalles'].append({
    #                 'puerto': 'No disponible',
    #                 'servicio': 'No disponible',
    #             })

    # # Contar el total de puertos abiertos
    # analysis['puertos_abiertos']['total'] = len(analysis['puertos_abiertos']['detalles'])

    # return analysis
    pass

def analizar_google_dorks(google_dorks_results):
    """
    Procesa los resultados de Google Dorks y devuelve un análisis organizado.
    """
    analysis = {}

    # Acceder a los datos anidados
    dorks_data = google_dorks_results.get('data', [])

    # Total de resultados
    analysis['total_resultados'] = len(dorks_data)

    # Detalles de los resultados
    detalles = []
    for result in dorks_data:
        if isinstance(result, dict):  # Verificar si el elemento es un diccionario
            detalles.append({
                'titulo': result.get('title', 'Sin título'),
                'enlace': result.get('link', 'Sin enlace'),
                'snippet': result.get('snippet', 'Sin descripción'),
            })
        else:
            # Manejar el caso en que el elemento no sea un diccionario
            detalles.append({
                'titulo': 'Formato no válido',
                'enlace': str(result),
                'snippet': 'No disponible',
            })

    analysis['detalles'] = detalles

    return analysis

def procesar_datos(results):
    """
    Procesa todos los resultados y devuelve un análisis combinado.
    """
    return {
        'dns': analizar_dns(results['dns']),
        'whois': analizar_whois(results['whois']),
        'nmap': results['nmap'],  # Pasar los datos de Nmap sin procesar
        'google_dorks': analizar_google_dorks(results['google_dorks']),
    }