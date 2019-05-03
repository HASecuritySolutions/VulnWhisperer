import logging
import os

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
        self.logger.info('Test path resolved as {}'.format(self.mock_dir))

    def get_directories(self, path):
        dir, subdirs, files = next(os.walk(path))
        return sorted(subdirs)

    def get_files(self, path):
        dir, subdirs, files = next(os.walk(path))
        return sorted(files)

    def create_nessus_resource(self, framework):
        for filename in self.get_files('{}/{}'.format(self.mock_dir, framework)):
            method, resource = filename.split('_', 1)
            resource = resource.replace('_', '/')
            self.logger.info('Adding mocked {} endpoint {} {}'.format(framework, method, resource))
            httpretty.register_uri(
                getattr(httpretty, method), 'https://{}:443/{}'.format(framework, resource),
                body=open('{}/{}/{}'.format(self.mock_dir, framework, filename)).read()
            )

    def qualys_vm_callback(self, request, uri, response_headers):
        self.logger.info('Simulating response for {} ({})'.format(uri, request.body))
        if 'list' in request.parsed_body['action']:
            return [200,
                    response_headers,
                    open(self.qualys_vm_path + '/scans').read()]
        elif 'fetch' in request.parsed_body['action']:
            try:
                response_body = open('{}/{}'.format(
                                      self.qualys_vm_path,
                                      request.parsed_body['scan_ref'][0].replace('/', '_'))
                                    ).read()
            except:
                # Can't find the file, just send an empty response
                response_body = ''
        return [200, response_headers, response_body]

    def create_qualys_vm_resource(self, framework):
        # Create health check endpoint
        self.logger.info('Adding mocked {} endpoint GET msp/about.php'.format(framework))
        httpretty.register_uri(
                httpretty.GET,
                'https://{}:443/msp/about.php'.format(framework),
                body='')

        self.logger.info('Adding mocked {} endpoint {} {}'.format(framework, 'POST', 'api/2.0/fo/scan'))
        httpretty.register_uri(
            httpretty.POST, 'https://{}:443/api/2.0/fo/scan/'.format(framework),
            body=self.qualys_vm_callback)

    def qualys_was_callback(self, request, uri, response_headers):
        self.logger.info('Simulating response for {} ({})'.format(uri, request.body))
        report_id = request.parsed_body.split('<WasScan><id>')[1].split('<')[0]
        response_body = open('{}/create_{}'.format(self.qualys_was_path, report_id)).read()
        return [200, response_headers, response_body]

    def create_qualys_was_resource(self, framework):
        for filename in self.get_files('{}/{}'.format(self.mock_dir, framework)):
            if filename.startswith('POST') or filename.startswith('GET'):
                method, resource = filename.split('_', 1)
                resource = resource.replace('_', '/')
                self.logger.info('Adding mocked {} endpoint {} {}'.format(framework, method, resource))
                httpretty.register_uri(
                    getattr(httpretty, method), 'https://{}:443/{}'.format(framework, resource),
                    body=open('{}/{}/{}'.format(self.mock_dir, framework, filename)).read()
                )

        self.logger.info('Adding mocked {} endpoint {} {}'.format(framework, 'POST', 'qps/rest/3.0/create/was/report'))
        httpretty.register_uri(
            httpretty.POST, 'https://{}:443/qps/rest/3.0/create/was/report'.format(framework),
            body=self.qualys_was_callback)

    def openvas_callback(self, request, uri, response_headers):
        self.logger.info('Simulating response for {} ({})'.format(uri, request.body))
        if request.querystring['cmd'][0] in ['get_reports', 'get_report_formats']:
            response_body = open('{}/{}'.format(self.openvas_path, request.querystring['cmd'][0])).read()

        if request.querystring['cmd'][0] == 'get_report':
                response_body = open('{}/report_{}'.format(self.openvas_path, request.querystring['report_id'][0])).read()

        return [200, response_headers, response_body]

    def create_openvas_resource(self, framework):
        # Create login endpoint
        httpretty.register_uri(
            httpretty.POST, 'https://{}:4000/omp'.format(framework),
            body=open('{}/{}/{}'.format(self.mock_dir, framework, 'login')).read()
        )

        # Create GET requests endpoint
        httpretty.register_uri(
            httpretty.GET, 'https://{}:4000/omp'.format(framework),
            body=self.openvas_callback
        )

    def mock_endpoints(self):
        for framework in self.get_directories(self.mock_dir):
            if framework in ['nessus', 'tenable']:
                self.create_nessus_resource(framework)
            elif framework == 'qualys_vm':
                self.qualys_vm_path = self.mock_dir + '/' + framework
                self.create_qualys_vm_resource(framework)
            elif framework == 'qualys_was':
                self.qualys_was_path = self.mock_dir + '/' + framework
                self.create_qualys_was_resource(framework)
            elif framework == 'openvas':
                self.openvas_path = self.mock_dir + '/' + framework
                self.create_openvas_resource(framework)
        httpretty.enable()
