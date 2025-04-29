from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),  # URL para el panel administrativo de Django
    path('api/', include('api.urls')),  # Aquí conectas las rutas de la app `api`
]
