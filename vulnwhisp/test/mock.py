import os
import logging
import httpretty


class mockAPI(object):
    def __init__(self, mock_dir=None, debug=False):
        self.mock_dir = mock_dir

        if not self.mock_dir:
            # Try to guess the mock_dir if python setup.py develop was used
            self.mock_dir = '/'.join(__file__.split('/')[:-3]) + '/tests/data'

        self.logger = logging.getLogger('mockAPI')
        if debug:
            self.logger.setLevel(logging.DEBUG)

        self.logger.info('mockAPI initialised, API requests will be mocked')
        self.logger.debug('Test path resolved as {}'.format(self.mock_dir))

    def get_directories(self, path):
        dir, subdirs, files = next(os.walk(path))
        return subdirs

    def get_files(self, path):
        dir, subdirs, files = next(os.walk(path))
        return files

    def qualys_vuln_callback(self, request, uri, response_headers):
        self.logger.debug('Simulating response for {} ({})'.format(uri, request.body))
        if 'list' in request.parsed_body['action']:
            return [200,
                    response_headers,
                    open('{}/{}'.format(self.qualys_vuln_path, 'scans')).read()]
        elif 'fetch' in request.parsed_body['action']:
            try:
                response_body = open('{}/{}'.format(
                                      self.qualys_vuln_path,
                                      request.parsed_body['scan_ref'][0].replace('/', '_'))
                                    ).read()
            except:
                # Can't find the file, just send an empty response
                response_body = ''
        return [200, response_headers, response_body]

    def create_nessus_resource(self, framework):
        for filename in self.get_files('{}/{}'.format(self.mock_dir, framework)):
            method, resource = filename.split('_', 1)
            resource = resource.replace('_', '/')
            self.logger.debug('Adding mocked {} endpoint {} {}'.format(framework, method, resource))
            httpretty.register_uri(
                getattr(httpretty, method), 'https://{}:443/{}'.format(framework, resource),
                body=open('{}/{}/{}'.format(self.mock_dir, framework, filename)).read()
            )

    def create_qualys_vuln_resource(self, framework):
        # Create health check endpoint
        self.logger.debug('Adding mocked {} endpoint {} {}'.format(framework, 'GET', 'msp/about.php'))
        httpretty.register_uri(
                httpretty.GET,
                'https://{}:443/{}'.format(framework, 'msp/about.php'),
                body='')

        self.logger.debug('Adding mocked {} endpoint {} {}'.format(framework, 'POST', 'api/2.0/fo/scan'))
        httpretty.register_uri(
            httpretty.POST, 'https://{}:443/{}'.format(framework, 'api/2.0/fo/scan/'),
            body=self.qualys_vuln_callback)

    def mock_endpoints(self):
        for framework in self.get_directories(self.mock_dir):
            if framework in ['nessus', 'tenable']:
                self.create_nessus_resource(framework)
            elif framework == 'qualys_vuln':
                self.qualys_vuln_path = self.mock_dir + '/' + framework
                self.create_qualys_vuln_resource(framework)
        httpretty.enable()