from django.urls import path
from .views import ShodanDVWAView

urlpatterns = [
    path('shodan/dvwa/', ShodanDVWAView.as_view(), name='shodan_dvwa'),
]