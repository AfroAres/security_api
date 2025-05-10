from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from scanners.scanner import Scanner
import json
from analysis.analyzer import procesar_datos


@csrf_exempt
def scan_view(request):
    """
    Vista para manejar el escaneo de dominios.
    Recibe un dominio como parámetro y realiza los escaneos.
    """
    if request.method == 'POST':
        try:
            # Parsear el cuerpo de la solicitud
            body = json.loads(request.body)
            domain = body.get('domain')

            if not domain:
                return JsonResponse({'status': 'error', 'message': 'El parámetro "domain" es obligatorio.'}, status=400)

            # Crear una instancia del Scanner y realizar los escaneos
            scanner = Scanner()
            dns_results = scanner.dns_scan(domain)
            whois_results = scanner.whois_scan(domain)
            nmap_results = scanner.nmap_scan([domain])
            google_dorks_results = scanner.google_dorks_scan([f"site:{domain}", "intitle:index.of"])  # Escaneo de Google Dorks

            # Devolver los resultados en formato JSON
            return JsonResponse({
                'status': 'success',
                'results': {
                    'dns': dns_results,
                    'whois': whois_results,
                    'nmap': nmap_results,
                    'google_dorks': google_dorks_results,  # Resultados de Google Dorks
                }
            })

        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'El cuerpo de la solicitud debe ser un JSON válido.'}, status=400)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'Error interno: {str(e)}'}, status=500)

    return JsonResponse({'status': 'error', 'message': 'Método no permitido. Usa POST.'}, status=405)


def scan_form_view(request):
    """
    Vista para manejar el formulario de escaneo de dominios.
    Permite ingresar un dominio y muestra los resultados en la misma página.
    """
    domain = None  # Inicializar el dominio como None
    results = None

    if request.method == 'POST':
        domain = request.POST.get('domain')  # Obtener el dominio ingresado en el formulario

        if domain:
            # Crear una instancia del Scanner y realizar los escaneos
            scanner = Scanner()
            try:
                dns_results = scanner.dns_scan(domain)
                whois_results = scanner.whois_scan(domain)
                nmap_results = scanner.nmap_scan([domain])
                google_dorks_results = scanner.google_dorks_scan([f"site:{domain}", "intitle:index.of"])

                # Almacenar los resultados en bruto
                raw_results = {
                    'dns': dns_results,
                    'whois': whois_results,
                    'nmap': nmap_results,
                    'google_dorks': google_dorks_results,
                }

                # Registrar los resultados en bruto para depuración
                print("Resultados en bruto:", json.dumps(raw_results, indent=4))

                # Procesar los resultados con el módulo de análisis
                results = procesar_datos(raw_results)

                # Guardar los resultados procesados en la sesión
                request.session['scan_results'] = results

            except Exception as e:
                # Manejar errores durante el escaneo o procesamiento
                print(f"Error durante el escaneo o procesamiento: {e}")
                results = {'error': f"Error durante el escaneo: {e}"}

    # Pasar el dominio ingresado al contexto junto con los resultados
    return render(request, 'scan.html', {'results': results, 'domain': domain})

def download_results_as_text(request):
    """
    Vista para generar y descargar los resultados como un archivo de texto.
    """
    # Recuperar los resultados desde la sesión
    results = request.session.get('scan_results')

    if not results:
        return HttpResponse("No hay resultados disponibles para descargar.", content_type="text/plain")

    # Crear la respuesta HTTP con el archivo de texto
    response = HttpResponse(content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="results.txt"'

    # Escribir los resultados en el archivo de texto
    response.write("Resultados DNS:\n")
    response.write(json.dumps(results['dns'], indent=4))
    response.write("\n\nResultados WHOIS:\n")
    response.write(json.dumps(results['whois'], indent=4))
    response.write("\n\nResultados Nmap:\n")
    response.write(json.dumps(results['nmap'], indent=4))
    response.write("\n\nResultados Google Dorks:\n")

    # Formatear los resultados de Google Dorks
    google_dorks_results = results['google_dorks']
    detalles = google_dorks_results.get('detalles', [])
    for i, dork in enumerate(detalles, start=1):
        response.write(f"{i}. Título: {dork.get('titulo', 'Sin título')}\n")
        response.write(f"   Enlace: {dork.get('enlace', 'Sin enlace')}\n")
        response.write(f"   Snippet: {dork.get('snippet', 'Sin descripción')}\n\n")

    return response