from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.renderers import JSONRenderer
from rest_framework import status
from django.shortcuts import render
from django.views import View  # Cambiamos a una vista basada en clases genérica
from ..services.deep_seek_service import consultar_deepseek
import json

class DeepSeekView(View):
    def post(self, request):
        # Recuperar los resultados desde la sesión
        scan_results = request.session.get('scan_results', {})

        # Crear un prompt dinámico con los datos
        prompt = (
            "Analiza la siguiente respuesta en busca de vulnerabilidades, configuraciones incorrectas y riesgos de seguridad. "
            "Proporciona un resumen técnico con los hallazgos clave y recomendaciones específicas para mitigarlos. "
            "Evita explicaciones extensas y enfócate en los puntos críticos.\n\n"
            f"Resultados procesados:\n{json.dumps(scan_results, indent=4)}"
        )

        # Llamar a la función consultar_deepseek con el prompt dinámico
        respuesta = consultar_deepseek(prompt)

        # Renderizar la plantilla con la respuesta
        return render(request, 'scan.html', {'deepseek_response': respuesta})