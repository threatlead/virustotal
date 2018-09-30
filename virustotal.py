import requests
from pyquery import PyQuery


class VirusTotal:
    """
        VirusTotal : VT-API
        https://developers.virustotal.com/v2.0/reference
        public:
            # Sending and scanning files
            # Rescanning already submitted files
            # Retrieving file scan reports
            # Sending and scanning URLs
            # Retrieving URL scan reports
            # Retrieving IP address reports(includes Passive DNS)
            # Retrieving domain reports(includes Passive DNS)
            # Making comments on files and URLs
        private:

    """
    base_url = 'https://www.virustotal.com/'
    v2api_url = base_url + 'vtapi/v2'
    is_private_api = False

    def __init__(self, api_key, api_type='Public'):
        self.api_key = api_key
        self.is_private_api = True if api_type == 'Private' else False

    def _vt_request(self, url, params):
        params['apikey'] = self.api_key
        response = requests.get(url, params=params)
        if response.status_code == 204:
            raise Exception('Reached Limit for this API Key')
        if response.status_code == 403:
            raise Exception('VTAPI endpoint is forbidden. API key doesnt have access to private endpoint')
        elif response.status_code == requests.codes.ok:
            return response.json()
        else:
            raise Exception('Unknown error code: {0}'.format(response.status_code))

    def file_report(self, resource, allinfo=False):
        """
        VT File Report for a given set of hashes.
        :param resource: hash(es) of files separated by comma
        :param allinfo: allinfo vs. partial_file_info default is partial
        :return: list of return-dicts
        """
        url = '{0}/file/report'.format(self.v2api_url)
        allinfo = True if allinfo is True and self.is_private_api is True else False
        params = {'resource': resource, 'allinfo': allinfo}
        return self._vt_request(url=url, params=params)

    # -------- URL -------------- #

    # -------- IPADDR -------------- #
    def ipaddress_report(self, ip):
        url = '{0}/ip-address/report'.format(self.v2api_url)
        params = {'ip': ip}
        return self._vt_request(url=url, params=params)

    # -------- DOMAIN -------------- #
    def domain_report(self, domain):
        url = '{0}/domain/report'.format(self.v2api_url)
        params = {'domain': domain}
        return self._vt_request(url=url, params=params)

    def user_comments(self, user, page=1):
        """
        Scrape user comments from VT website.
        :param user: User whose comments need to be scraped
        :param page: VT response with 5 comments per page
        :return:
        """
        url = self.base_url + 'en/user/{0}/comments/?page={1}'.format(user, page)
        response = requests.get(url)
        if response.status_code != requests.codes.ok:
            raise Exception('Unable to retrieve user comments')
        else:
            data = response.json()
            html, page, next_page = data['html'], data['page'], data['next']
            pq = PyQuery(html)
            comments = []
            for div_comment in pq('div.comment').items():
                comment = dict(comment=None, hash=None, link=None)
                comment['comment'] = div_comment('table > tr > td').eq(1).text()
                comment['link'] = div_comment('span > a').attr('href')
                if '/file/' in comment['link'] and '/analysis/' in comment['link']:
                    comment['hash'] = comment['link'].split('/')[3]
                comments.append(comment)
            return dict(comments=comments, page=page, next=next_page)

    def file_search(self, query, offset, private=True):
        """
        Search Virustotal
        :param query: Query based on VT specifications
        :param offset: Determines which page to be downloaded
        :return: list of matching hashes & offset for next page
        """
        if self.is_private_api is not private:
            raise Exception('Cannot access Private VTAPI using Public key.')
        hashes = list()
        url = self.v2api_url + '/file/search'
        params = dict(query=query, apikey=self.api_key)
        params['offset'] = offset if offset else None
        data = self._vt_request(url, params)
        if data['response_code'] == 1:
            hashes = hashes + data['hashes']
            offset = data['offset'] if 'offset' in data else None
        else:
            offset = None
        return hashes, offset

