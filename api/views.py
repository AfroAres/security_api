from rest_framework.views import APIView
from rest_framework.response import Response
from core.domain.services import DNSService
from adapters.nmap_adapter import NmapAdapter

class DNSScanView(APIView):
    def get(self, request, domain):
        dns_service = DNSService()
        nmap_adapter = NmapAdapter()
        try:
            record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
            dns_report = dns_service.resolve_records(domain, record_types)
            whois_report = dns_service.resolve_whois(domain)

            ips_to_scan = dns_report["records"].get("A", [])
            nmap_report = nmap_adapter.scan(ips_to_scan)

            full_report = {
                "dns_report": dns_report,
                "whois_report": whois_report,
                "nmap_report": nmap_report,
            }
            return Response(full_report)
        except ValueError as e:
            return Response({"error": str(e)}, status=400)
        except Exception as e:
            return Response({"error": f"Error inesperado: {e}"}, status=500)
