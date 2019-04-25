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

        self.openvas_requests = {
            'request_1': ('POST', 200, 'omp'),
            'request_2': ('GET', 200, 'omp?cmd=get_reports&token=efbe7076-4ae9-4e57-89cc-bcd6bd93f1f3&max_results=1&ignore_pagination=1&filter=apply_overrides%3D1+min_qod%3D70+autofp%3D0+first%3D1+rows%3D0+levels%3Dhml+sort-reverse%3Dseverity'),
            'request_3': ('GET', 200, 'omp?cmd=get_report_formats&token=efbe7076-4ae9-4e57-89cc-bcd6bd93f1f3'),
            'request_4': ('GET', 200, 'omp?token=efbe7076-4ae9-4e57-89cc-bcd6bd93f1f3&cmd=get_report&report_id=4c6c900c-71f5-42f7-91e2-1b19b7976606&filter=apply_overrides%3D0+min_qod%3D70+autofp%3D0+levels%3Dhml+first%3D1+rows%3D0+sort-reverse%3Dseverity&ignore_pagination=1&report_format_id=c1645568-627a-11e3-a660-406186ea4fc5&submit=Download')
        }

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
            self.logger.debug('Adding mocked {} endpoint {} {}'.format(framework, method, resource))
            httpretty.register_uri(
                getattr(httpretty, method), 'https://{}:443/{}'.format(framework, resource),
                body=open('{}/{}/{}'.format(self.mock_dir, framework, filename)).read()
            )

    def qualys_vuln_callback(self, request, uri, response_headers):
        self.logger.debug('Simulating response for {} ({})'.format(uri, request.body))
        if 'list' in request.parsed_body['action']:
            return [200,
                    response_headers,
                    open(self.qualys_vuln_path + '/scans').read()]
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

    def create_qualys_vuln_resource(self, framework):
        # Create health check endpoint
        self.logger.debug('Adding mocked {} endpoint GET msp/about.php'.format(framework))
        httpretty.register_uri(
                httpretty.GET,
                'https://{}:443/msp/about.php'.format(framework),
                body='')

        self.logger.debug('Adding mocked {} endpoint {} {}'.format(framework, 'POST', 'api/2.0/fo/scan'))
        httpretty.register_uri(
            httpretty.POST, 'https://{}:443/api/2.0/fo/scan/'.format(framework),
            body=self.qualys_vuln_callback)

    def qualys_web_callback(self, request, uri, response_headers):
        self.logger.debug('Simulating response for {} ({})'.format(uri, request.body))
        report_id = request.parsed_body.split('<WasScan><id>')[1].split('<')[0]
        response_body = open('{}/create_{}'.format(self.qualys_web_path, report_id)).read()
        return [200, response_headers, response_body]

    def create_qualys_web_resource(self, framework):
        for filename in self.get_files('{}/{}'.format(self.mock_dir, framework)):
            if filename.startswith('POST') or filename.startswith('GET'):
                method, resource = filename.split('_', 1)
                resource = resource.replace('_', '/')
                self.logger.debug('Adding mocked {} endpoint {} {}'.format(framework, method, resource))
                httpretty.register_uri(
                    getattr(httpretty, method), 'https://{}:443/{}'.format(framework, resource),
                    body=open('{}/{}/{}'.format(self.mock_dir, framework, filename)).read()
                )
        
        self.logger.debug('Adding mocked {} endpoint {} {}'.format(framework, 'POST', 'qps/rest/3.0/create/was/report'))
        httpretty.register_uri(
            httpretty.POST, 'https://{}:443/qps/rest/3.0/create/was/report'.format(framework),
            body=self.qualys_web_callback)

    def openvas_callback(self, request, uri, response_headers):
        self.logger.debug('Simulating response for {} ({})'.format(uri, request.body))
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
            # try:
            #     method, status, resource = self.openvas_requests[filename]
            #     self.logger.debug('Adding mocked {} endpoint {} {}'.format(framework, method, resource))
            # except:
            #     self.logger.error('Cound not find mocked {} endpoint for file {}/{}/{}'.format(framework, self.mock_dir, framework, filename))
            #     continue
            # httpretty.register_uri(
            #     getattr(httpretty, method), 'https://{}:4000/{}'.format(framework, resource),
            #     body=open('{}/{}/{}'.format(self.mock_dir, framework, filename)).read(),
            #     status=status
            # )

    def mock_endpoints(self):
        for framework in self.get_directories(self.mock_dir):
            if framework in ['nessus', 'tenable']:
                self.create_nessus_resource(framework)
            elif framework == 'qualys_vuln':
                self.qualys_vuln_path = self.mock_dir + '/' + framework
                self.create_qualys_vuln_resource(framework)
            elif framework == 'qualys_web':
                self.qualys_web_path = self.mock_dir + '/' + framework
                self.create_qualys_web_resource(framework)
            elif framework == 'openvas':
                self.openvas_path = self.mock_dir + '/' + framework
                self.create_openvas_resource(framework)
        httpretty.enable()
