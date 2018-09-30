from .context import virustotal
from ..settings import API_KEY
import unittest


class ConnectTestSuite(unittest.TestCase):

    def setUp(self):
        self._vt = virustotal.VirusTotal(api_type='Private', api_key=API_KEY)

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

    def test_query(self):
        if self._vt.is_private_api:
            print('here')
            query = 'tag:email AND fs:2018-09-22T00:00:00+ AND fs:2018-09-22T03:00:00-'
            hashes, offset = self._vt.file_search(query, offset=None)
            self.assertGreater(len(hashes), 10, 'Invalid Query Result from VirusTotal.')

    def test_user_comments(self):
        comments = self._vt.user_comments(user='threatlead', page=1)
        self.assertEqual(len(comments['comments']), 5, 'Invalid UserComment Results from VirusTotal.')


if __name__ == '__main__':
    unittest.main()
