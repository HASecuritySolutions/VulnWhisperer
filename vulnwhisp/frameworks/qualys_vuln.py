#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Nathan Young'

import logging
import sys
import xml.etree.ElementTree as ET

import dateutil.parser as dp
import pandas as pd
import qualysapi


class qualysWhisperAPI(object):
    SCANS = 'api/2.0/fo/scan'

    def __init__(self, config=None):
        self.logger = logging.getLogger('qualysWhisperAPI')
        self.config = config
        try:
            self.qgc = qualysapi.connect(config, 'qualys_vuln')
            # Fail early if we can't make a request or auth is incorrect
            self.qgc.request('about.php')
            self.logger.info('Connected to Qualys at {}'.format(self.qgc.server))
        except Exception as e:
            self.logger.error('Could not connect to Qualys: {}'.format(str(e)))
            sys.exit(1)

    def scan_xml_parser(self, xml):
        all_records = []
        root = ET.XML(xml.encode("utf-8"))
        for child in root.find('.//SCAN_LIST'):
            all_records.append({
                'name': child.find('TITLE').text,
                'id': child.find('REF').text,
                'date': child.find('LAUNCH_DATETIME').text,
                'type': child.find('TYPE').text,
                'duration': child.find('DURATION').text,
                'status': child.find('.//STATE').text,
            })
        return pd.DataFrame(all_records)

    def get_all_scans(self):
        parameters = {
            'action': 'list',
            'echo_request': 0,
            'show_op': 0,
            'launched_after_datetime': '0001-01-01'
        }
        scans_xml = self.qgc.request(self.SCANS, parameters)
        return self.scan_xml_parser(scans_xml)

    def get_scan_details(self, scan_id=None):
        parameters = {
            'action': 'fetch',
            'echo_request': 0,
            'output_format': 'json_extended',
            'mode': 'extended',
            'scan_ref': scan_id
        }
        scan_json = self.qgc.request(self.SCANS, parameters)

        # First two columns are metadata we already have
        # Last column corresponds to "target_distribution_across_scanner_appliances" element
        # which doesn't follow the schema and breaks the pandas data manipulation
        return pd.read_json(scan_json).iloc[2:-1]


class qualysUtils:
    def __init__(self):
        self.logger = logging.getLogger('qualysUtils')

    def iso_to_epoch(self, dt):
        out = dp.parse(dt).strftime('%s')
        self.logger.info('Converted {} to {}'.format(dt, out))
        return out


class qualysVulnScan:

    def __init__(
        self,
        config=None,
        file_in=None,
        file_stream=False,
        delimiter=',',
        quotechar='"',
    ):
        self.logger = logging.getLogger('qualysVulnScan')
        self.file_in = file_in
        self.file_stream = file_stream
        self.report = None
        self.utils = qualysUtils()

        if config:
            try:
                self.qw = qualysWhisperAPI(config=config)
            except Exception as e:
                self.logger.error('Could not load config! Please check settings. Error: {}'.format(str(e)))

        if file_stream:
            self.open_file = file_in.splitlines()
        elif file_in:
            self.open_file = open(file_in, 'rb')

        self.downloaded_file = None

    def process_data(self, scan_id=None):
        """Downloads a file from Qualys and normalizes it"""
        self.logger.info('Downloading scan ID: {}'.format(scan_id))
        scan_report = self.qw.get_scan_details(scan_id=scan_id)
        if not scan_report.empty:
            keep_columns = ['category', 'cve_id', 'cvss3_base', 'cvss3_temporal', 'cvss_base',
                'cvss_temporal', 'dns', 'exploitability', 'fqdn', 'impact', 'ip', 'ip_status',
                'netbios', 'os', 'pci_vuln', 'port', 'protocol', 'qid', 'results', 'severity',
                'solution', 'ssl', 'threat', 'title', 'type', 'vendor_reference']
            scan_report = scan_report.filter(keep_columns)
            scan_report['severity'] = scan_report['severity'].astype(int).astype(str)
            scan_report['qid'] = scan_report['qid'].astype(int).astype(str)
        else:
            self.logger.warn('Scan ID {} has no vulnerabilities, skipping.'.format(scan_id))
            return scan_report

        return scan_report
