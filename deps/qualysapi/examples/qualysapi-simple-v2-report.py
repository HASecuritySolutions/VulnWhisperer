#!/usr/bin/env python
import sys
import logging

import qualysapi

if __name__ == '__main__':
    # Basic command line processing.
    if len(sys.argv) != 3:
        print('A report template and scan reference respectively are expected as the only arguments.')
        sys.exit(2)
    
    # Set the MAXIMUM level of log messages displayed @ runtime. 
    logging.basicConfig(level=logging.DEBUG)
    
    # Call helper that creates a connection w/ HTTP-Basic to QualysGuard v1 API
    qgs=qualysapi.connect()

    # Logging must be set after instanciation of connector class.
    logger = logging.getLogger('qualysapi.connector')
    logger.setLevel(logging.DEBUG)

    # Log to sys.out.
    logger_console = logging.StreamHandler()
    logger_console.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
    logging.getLogger(__name__).addHandler(logger)


    # Formulate a request to the QualysGuard V1 API 
    #  docs @
    #  https://community.qualys.com/docs/DOC-1324
    #  http://www.qualys.com/docs/QualysGuard_API_User_Guide.pdf
    #
    ret = qgs.request('/api/2.0/fo/report',{'action': 'launch', 'report_refs': sys.argv[2], 'output_format': 'xml', 'template_id': sys.argv[1], 'report_type': 'Scan'})

    print(ret)
