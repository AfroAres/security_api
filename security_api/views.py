from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from scanners.scanner import Scanner
import json

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
    results = None

    if request.method == 'POST':
        domain = request.POST.get('domain')

        if domain:
            # Crear una instancia del Scanner y realizar los escaneos
            scanner = Scanner()
            dns_results = scanner.dns_scan(domain)
            whois_results = scanner.whois_scan(domain)
            nmap_results = scanner.nmap_scan([domain])
            google_dorks_results = scanner.google_dorks_scan([f"site:{domain}", "intitle:index.of"])

            # Almacenar los resultados organizados por secciones
            results = {
                'dns': dns_results,
                'whois': whois_results,
                'nmap': nmap_results,
                'google_dorks': google_dorks_results,
            }

            # Guardar los resultados en la sesión
            request.session['scan_results'] = results

    return render(request, 'scan.html', {'results': results})

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
    response.write(results['dns'])
    response.write("\n\nResultados WHOIS:\n")
    response.write(results['whois'])
    response.write("\n\nResultados Nmap:\n")
    response.write(results['nmap'])
    response.write("\n\nResultados Google Dorks:\n")

    # Formatear los resultados de Google Dorks
    google_dorks_results = results['google_dorks']
    for i, result in enumerate(google_dorks_results, start=1):
        response.write(f"{i}. {result}\n\n")  # Agrega numeración y un espacio entre cada resultado

    return response