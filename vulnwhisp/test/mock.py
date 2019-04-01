import os
import logging
import httpretty

logger = logging.getLogger('mock-http')
logger.setLevel(logging.DEBUG)

tests_path = '/'.join(__file__.split('/')[:-3]) + '/test'

logger.info('Tests path resolved as {}'.format(tests_path))

def get_directories(path):
    dir, subdirs, files = next(os.walk(path))
    return subdirs

def get_files(path):
    dir, subdirs, files = next(os.walk(path))
    return files

def create_nessus_resource(framework):
    for filename in get_files('{}/{}'.format(tests_path, framework)):
        method, resource = filename.split('_',1)
        resource = resource.replace('_', '/')
        logger.debug('Adding mocked {} endpoint {} {}'.format(framework, method, resource))
        httpretty.register_uri(
            getattr(httpretty, method), 'https://{}:443/{}'.format(framework, resource),
            body=open('{}/{}/{}'.format(tests_path, framework, filename)).read()
        )

def qualys_vuln_callback(request, uri, response_headers):
    logger.info('Simulating response for {}'.format(uri))
    # print '\n\nURI:{}\nHeaders\n{line}\n{}\nContent\n{line}\n{}'.format(uri, request.headers, request.body, line='-' * 80)
    if 'list' in request.parsed_body['action']:
        return [ 200,
                 response_headers,
                 open('{}/{}'.format(qualys_vuln_path, 'scans')).read()
               ]

    elif 'fetch' in request.parsed_body['action']:
        try:
            response_body = open('{}/{}'.format(
                                    qualys_vuln_path, 
                                    request.parsed_body['scan_ref'][0].replace('/', '_'))
                                ).read()
        except:
            # Can't find the file, just send an empty response
            response_body = ''
        return [200, response_headers, response_body] 

def create_qualys_vuln_resource(framework):
    # Create health check endpoint
    logger.debug('Adding mocked {} endpoint {} {}'.format(framework, 'GET', 'msp/about.php'))
    httpretty.register_uri(
            httpretty.GET,
            'https://{}:443/{}'.format(framework, 'msp/about.php'),
            body='')
    
    logger.debug('Adding mocked {} endpoint {} {}'.format(framework, 'POST', 'api/2.0/fo/scan'))
    httpretty.register_uri(
        httpretty.POST, 'https://{}:443/{}'.format(framework, 'api/2.0/fo/scan/'),
        body=qualys_vuln_callback)

for framework in get_directories(tests_path):
    if framework in ['nessus', 'tenable']:
        create_nessus_resource(framework)
    elif framework == 'qualys_vuln':
        qualys_vuln_path = tests_path + '/' + framework
        create_qualys_vuln_resource(framework)

httpretty.enable()