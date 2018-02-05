from .context import virustotal
from ..settings import API_KEY
import unittest


class ConnectTestSuite(unittest.TestCase):

    def setUp(self):
        self._vt = virustotal.VirusTotal(api_type='Public', api_key=API_KEY)

    def test_file_report(self):
        resource = '0f2c5c39494f15b7ee637ad5b6b5d00a3e2f407b4f27d140cd5a821ff08acfac'
        result = self._vt.file_report(resource=resource)
        self.assertEqual(result['sha256'], resource, 'Invalid Result from VirusTotal.')

    def test_domain_report(self):
        domain = '027.ru'
        result = self._vt.domain_report(domain=domain)
        self.assertEqual(result['verbose_msg'], 'Domain found in dataset', 'Invalid Result from VirusTotal.')

    def test_ipaddress_report(self):
        ipaddress = '4.4.4.4'
        result = self._vt.ipaddress_report(ip=ipaddress)
        self.assertEqual(result['country'], 'US', 'Invalid Result from VirusTotal.')


if __name__ == '__main__':
    unittest.main()