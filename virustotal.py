import requests


class VirusTotal:
    """
        VirusTotal : VT-API
        https://developers.virustotal.com/v2.0/reference
    """
    base_url = 'https://www.virustotal.com/vtapi/v2'
    is_private_api = False

    def __init__(self, api_key, api_type='Public'):
        self.api_key = api_key
        self.is_private_api = True if api_type == 'Private' else False

    def _vt_request(self, url, params):
        params['apikey'] = self.api_key
        response = requests.get(url, params=params)
        if response.status_code == requests.codes.ok:
            return response.json()

    # -------- FILE -------------- #
    def file_report(self, resource, allinfo=False):
        url = '{0}/file/report'.format(self.base_url)
        allinfo = True if allinfo is True and self.is_private_api is True else False
        params = {'resource': resource, 'allinfo': allinfo}
        return self._vt_request(url=url, params=params)

    # -------- URL -------------- #
    # -------- IPADDR -------------- #
    def ipaddress_report(self, ip):
        url = '{0}/ip-address/report'.format(self.base_url)
        params = {'ip': ip}
        return self._vt_request(url=url, params=params)

    # -------- DOMAIN -------------- #
    def domain_report(self, domain):
        url = '{0}/domain/report'.format(self.base_url)
        params = {'domain': domain}
        return self._vt_request(url=url, params=params)

    # -------- COMMENT -------------- #
