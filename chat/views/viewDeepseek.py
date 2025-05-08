from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.renderers import JSONRenderer
from rest_framework import status
from django.shortcuts import render
from django.views import View  # Cambiamos a una vista basada en clases genérica
from ..services.deep_seek_service import consultar_deepseek

class DeepSeekView(View):
    def post(self, request):
        # Prompt detallado para análisis de vulnerabilidades
        prompt = (
            "Actúa como un analista de ciberseguridad especializado en pruebas de penetración. "
            "Analiza la respuesta proporcionada en busca de fallas de seguridad, vulnerabilidades conocidas, "
            "y posibles configuraciones incorrectas. Proporciona un resumen detallado con recomendaciones "
            "para mitigar los riesgos identificados."
        )

        # Llamar a la función consultar_deepseek con el prompt predefinido
        respuesta = consultar_deepseek(prompt)
        # Renderizar la plantilla con la respuesta
        return render(request, 'scan.html', {'deepseek_response': respuesta})