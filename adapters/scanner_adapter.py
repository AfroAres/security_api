from core.domain.services import ShodanService

class ShodanAdapter:
    def __init__(self):
        self.service = ShodanService()

    def get_dvwa_results(self):
        results = self.service.search_dvwa()
        formatted_results = [
            {
                "ip": result['ip_str'],
                "port": result['port'],
                "organization": result.get('org', 'N/A'),
                "banner": result['data']
            }
            for result in results['matches']
        ]
        return {
            "total": results['total'],
            "matches": formatted_results
        }
