#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Austin Taylor'

from lxml import objectify
from lxml.builder import E
import xml.etree.ElementTree as ET
import pandas as pd
import qualysapi
import qualysapi.config as qcconf
import requests
import sys
import os
import csv
import logging
import dateutil.parser as dp


class qualysWhisperAPI(object):
    COUNT_WEBAPP = '/count/was/webapp'
    COUNT_WASSCAN = '/count/was/wasscan'
    DELETE_REPORT = '/delete/was/report/{report_id}'
    GET_WEBAPP_DETAILS = '/get/was/webapp/{was_id}'
    QPS_REST_3 = '/qps/rest/3.0'
    REPORT_DETAILS = '/get/was/report/{report_id}'
    REPORT_STATUS = '/status/was/report/{report_id}'
    REPORT_CREATE = '/create/was/report'
    REPORT_DOWNLOAD = '/download/was/report/{report_id}'
    SCAN_DETAILS = '/get/was/wasscan/{scan_id}'
    SCAN_DOWNLOAD = '/download/was/wasscan/{scan_id}'
    SEARCH_REPORTS = '/search/was/report'
    SEARCH_WEB_APPS = '/search/was/webapp'
    SEARCH_WAS_SCAN = '/search/was/wasscan'
    VERSION = '/qps/rest/portal/version'

    def __init__(self, config=None):
        self.logger = logging.getLogger('qualysWhisperAPI')
        self.config = config
        try:
            self.qgc = qualysapi.connect(config, 'qualys_web')
            self.logger.info('Connected to Qualys at {}'.format(self.qgc.server))
        except Exception as e:
            self.logger.error('Could not connect to Qualys: {}'.format(str(e)))
        self.headers = {
            #"content-type": "text/xml"}
            "Accept" : "application/json",
            "Content-Type": "application/json"}
        self.config_parse = qcconf.QualysConnectConfig(config, 'qualys_web')
        try:
            self.template_id = self.config_parse.get_template_id()
        except:
            self.logger.error('Could not retrieve template ID')

    ####
    #### GET SCANS TO PROCESS
    ####

    def get_was_scan_count(self, status):
        """
        Checks number of scans, used to control the api limits
        """
        parameters = (
            E.ServiceRequest(
                E.filters(
                    E.Criteria({'field': 'status', 'operator': 'EQUALS'}, status))))
        xml_output = self.qgc.request(self.COUNT_WASSCAN, parameters)
        root = objectify.fromstring(xml_output.encode('utf-8'))
        return root.count.text

    def generate_scan_result_XML(self, limit=1000, offset=1, status='FINISHED'):
        report_xml = E.ServiceRequest(
            E.filters(
                E.Criteria({'field': 'status', 'operator': 'EQUALS'}, status
                           ),
            ),
            E.preferences(
                E.startFromOffset(str(offset)),
                E.limitResults(str(limit))
            ),
        )
        return report_xml

    def get_scan_info(self, limit=1000, offset=1, status='FINISHED'):
        """ Returns XML of ALL WAS Scans"""
        data = self.generate_scan_result_XML(limit=limit, offset=offset, status=status)
        return self.qgc.request(self.SEARCH_WAS_SCAN, data)

    def xml_parser(self, xml, dupfield=None):
        all_records = []
        root = ET.XML(xml)
        for i, child in enumerate(root):
            for subchild in child:
                record = {}
                dup_tracker = 0
                for p in subchild:
                    record[p.tag] = p.text
                    for o in p:
                        if o.tag in record:
                            dup_tracker += 1
                            record[o.tag + '_%s' % dup_tracker] = o.text
                        else:
                            record[o.tag] = o.text
                all_records.append(record)
        return pd.DataFrame(all_records)

    def get_all_scans(self, limit=1000, offset=1, status='FINISHED'):
        qualys_api_limit = limit
        dataframes = []
        _records = []
        try:
            total = int(self.get_was_scan_count(status=status))
            self.logger.error('Already have WAS scan count')
            self.logger.info('Retrieving information for {} scans'.format(total))
            for i in range(0, total):
                if i % limit == 0:
                    if (total - i) < limit:
                        qualys_api_limit = total - i
                    self.logger.info('Making a request with a limit of {} at offset {}'.format((str(qualys_api_limit)), str(i + 1)))
                    scan_info = self.get_scan_info(limit=qualys_api_limit, offset=i + 1, status=status)
                    _records.append(scan_info)
            self.logger.debug('Converting XML to DataFrame')
            dataframes = [self.xml_parser(xml) for xml in _records]
        except Exception as e:
            self.logger.error("Couldn't process all scans: {}".format(e))

        return pd.concat(dataframes, axis=0).reset_index().drop('index', axis=1)

    ####
    #### CREATE VULNERABILITY REPORT AND DOWNLOAD IT
    ####

    def get_report_status(self, report_id):
        return self.qgc.request(self.REPORT_STATUS.format(report_id=report_id))

    def download_report(self, report_id):
        return self.qgc.request(self.REPORT_DOWNLOAD.format(report_id=report_id))

    def generate_scan_report_XML(self, scan_id):
        """Generates a CSV report for an asset based on template defined in .ini file"""
        report_xml = E.ServiceRequest(
            E.data(
                E.Report(
                    E.name('<![CDATA[API Scan Report generated by VulnWhisperer]]>'),
                    E.description('<![CDATA[CSV Scanning report for VulnWhisperer]]>'),
                    E.format('CSV'),
                    #type is not needed, as the template already has it
                    E.type('WAS_SCAN_REPORT'),
                    E.template(
                        E.id(self.template_id)
                    ),
                    E.config(
                        E.scanReport(
                            E.target(
                                E.scans(
                                    E.WasScan(
                                        E.id(scan_id)
                                    )
                                ),
                            ),
                        ),
                    )
                )
            )
        )
        return report_xml

    def create_report(self, report_id, kind='scan'):
        mapper = {'scan': self.generate_scan_report_XML}
        try:
            data = mapper[kind](report_id)
        except Exception as e:
            self.logger.error('Error creating report: {}'.format(str(e)))
        return self.qgc.request(self.REPORT_CREATE, data).encode('utf-8')

    def delete_report(self, report_id):
        return self.qgc.request(self.DELETE_REPORT.format(report_id=report_id))


class qualysReportFields:
    CATEGORIES = ['VULNERABILITY',
                  'SENSITIVECONTENT',
                  'INFORMATION_GATHERED']

    # URL Vulnerability Information

    VULN_BLOCK = [
        CATEGORIES[0],
        'ID',
        'QID',
        'Url',
        'Param',
        'Function',
        'Form Entry Point',
        'Access Path',
        'Authentication',
        'Ajax Request',
        'Ajax Request ID',
        'Ignored',
        'Ignore Reason',
        'Ignore Date',
        'Ignore User',
        'Ignore Comments',
        'First Time Detected',
        'Last Time Detected',
        'Last Time Tested',
        'Times Detected',
        'Payload #1',
        'Request Method #1',
        'Request URL #1',
        'Request Headers #1',
        'Response #1',
        'Evidence #1',
    ]

    INFO_HEADER = [
        'Vulnerability Category',
        'ID',
        'QID',
        'Response #1',
        'Last Time Detected',
    ]
    INFO_BLOCK = [
        CATEGORIES[2],
        'ID',
        'QID',
        'Results',
        'Detection Date',
    ]

    QID_HEADER = [
        'QID',
        'Id',
        'Title',
        'Category',
        'Severity Level',
        'Groups',
        'OWASP',
        'WASC',
        'CWE',
        'CVSS Base',
        'CVSS Temporal',
        'Description',
        'Impact',
        'Solution',
    ]
    GROUP_HEADER = ['GROUP', 'Name', 'Category']
    OWASP_HEADER = ['OWASP', 'Code', 'Name']
    WASC_HEADER = ['WASC', 'Code', 'Name']
    SCAN_META = ['Web Application Name', 'URL', 'Owner', 'Scope', 'Operating System']
    CATEGORY_HEADER = ['Category', 'Severity', 'Level', 'Description']


class qualysUtils:
    def __init__(self):
        self.logger = logging.getLogger('qualysUtils')

    def grab_section(
            self,
            report,
            section,
            end=[],
            pop_last=False,
    ):
        temp_list = []
        max_col_count = 0
        with open(report, 'rb') as csvfile:
            q_report = csv.reader(csvfile, delimiter=',', quotechar='"')
            for line in q_report:
                if set(line) == set(section):
                    break

            # Reads text until the end of the block:
            for line in q_report:  # This keeps reading the file
                temp_list.append(line)

                if line in end:
                    break
            if pop_last and len(temp_list) > 1:
                temp_list.pop(-1)
        return temp_list

    def iso_to_epoch(self, dt):
        return dp.parse(dt).strftime('%s')

    def cleanser(self, _data):
        repls = (('\n', '|||'), ('\r', '|||'), (',', ';'), ('\t', '|||'))
        if _data:
            _data = reduce(lambda a, kv: a.replace(*kv), repls, str(_data))
        return _data

class qualysScanReport:
    # URL Vulnerability Information
    WEB_SCAN_VULN_BLOCK = list(qualysReportFields.VULN_BLOCK)
    WEB_SCAN_VULN_BLOCK.insert(WEB_SCAN_VULN_BLOCK.index('QID'), 'Detection ID')

    WEB_SCAN_VULN_HEADER = list(WEB_SCAN_VULN_BLOCK)
    WEB_SCAN_VULN_HEADER[WEB_SCAN_VULN_BLOCK.index(qualysReportFields.CATEGORIES[0])] = \
        'Vulnerability Category'

    WEB_SCAN_SENSITIVE_HEADER = list(WEB_SCAN_VULN_HEADER)
    WEB_SCAN_SENSITIVE_HEADER.insert(WEB_SCAN_SENSITIVE_HEADER.index('Url'
                                                                     ), 'Content')

    WEB_SCAN_SENSITIVE_BLOCK = list(WEB_SCAN_SENSITIVE_HEADER)
    WEB_SCAN_SENSITIVE_BLOCK.insert(WEB_SCAN_SENSITIVE_BLOCK.index('QID'), 'Detection ID')
    WEB_SCAN_SENSITIVE_BLOCK[WEB_SCAN_SENSITIVE_BLOCK.index('Vulnerability Category'
                                                            )] = qualysReportFields.CATEGORIES[1]

    WEB_SCAN_INFO_HEADER = list(qualysReportFields.INFO_HEADER)
    WEB_SCAN_INFO_HEADER.insert(WEB_SCAN_INFO_HEADER.index('QID'), 'Detection ID')

    WEB_SCAN_INFO_BLOCK = list(qualysReportFields.INFO_BLOCK)
    WEB_SCAN_INFO_BLOCK.insert(WEB_SCAN_INFO_BLOCK.index('QID'), 'Detection ID')

    QID_HEADER = list(qualysReportFields.QID_HEADER)
    GROUP_HEADER = list(qualysReportFields.GROUP_HEADER)
    OWASP_HEADER = list(qualysReportFields.OWASP_HEADER)
    WASC_HEADER = list(qualysReportFields.WASC_HEADER)
    SCAN_META = list(qualysReportFields.SCAN_META)
    CATEGORY_HEADER = list(qualysReportFields.CATEGORY_HEADER)

    def __init__(
            self,
            config=None,
            file_in=None,
            file_stream=False,
            delimiter=',',
            quotechar='"',
    ):
        self.logger = logging.getLogger('qualysScanReport')
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

    def grab_sections(self, report):
        all_dataframes = []
        dict_tracker = {}
        with open(report, 'rb') as csvfile:
            dict_tracker['WEB_SCAN_VULN_BLOCK'] = pd.DataFrame(self.utils.grab_section(report,
                                                                                       self.WEB_SCAN_VULN_BLOCK,
                                                                                       end=[
                                                                                           self.WEB_SCAN_SENSITIVE_BLOCK,
                                                                                           self.WEB_SCAN_INFO_BLOCK],
                                                                                       pop_last=True),
                                                               columns=self.WEB_SCAN_VULN_HEADER)
            dict_tracker['WEB_SCAN_SENSITIVE_BLOCK'] = pd.DataFrame(self.utils.grab_section(report,
                                                                                            self.WEB_SCAN_SENSITIVE_BLOCK,
                                                                                            end=[
                                                                                                self.WEB_SCAN_INFO_BLOCK,
                                                                                                self.WEB_SCAN_SENSITIVE_BLOCK],
                                                                                            pop_last=True),
                                                                columns=self.WEB_SCAN_SENSITIVE_HEADER)
            dict_tracker['WEB_SCAN_INFO_BLOCK'] = pd.DataFrame(self.utils.grab_section(report,
                                                                                       self.WEB_SCAN_INFO_BLOCK,
                                                                                       end=[self.QID_HEADER],
                                                                                       pop_last=True),
                                                                columns=self.WEB_SCAN_INFO_HEADER)
            dict_tracker['QID_HEADER'] = pd.DataFrame(self.utils.grab_section(report,
                                                                              self.QID_HEADER,
                                                                              end=[self.GROUP_HEADER],
                                                                              pop_last=True),
                                                                columns=self.QID_HEADER)
            dict_tracker['GROUP_HEADER'] = pd.DataFrame(self.utils.grab_section(report,
                                                                                self.GROUP_HEADER,
                                                                                end=[self.OWASP_HEADER],
                                                                                pop_last=True),
                                                                columns=self.GROUP_HEADER)
            dict_tracker['OWASP_HEADER'] = pd.DataFrame(self.utils.grab_section(report,
                                                                                self.OWASP_HEADER,
                                                                                end=[self.WASC_HEADER],
                                                                                pop_last=True),
                                                                columns=self.OWASP_HEADER)
            dict_tracker['WASC_HEADER'] = pd.DataFrame(self.utils.grab_section(report,
                                                                               self.WASC_HEADER, end=[['APPENDIX']],
                                                                               pop_last=True),
                                                                columns=self.WASC_HEADER)

            dict_tracker['SCAN_META'] = pd.DataFrame(self.utils.grab_section(report,
                                                                             self.SCAN_META,
                                                                             end=[self.CATEGORY_HEADER],
                                                                             pop_last=True),
                                                                columns=self.SCAN_META)

            dict_tracker['CATEGORY_HEADER'] = pd.DataFrame(self.utils.grab_section(report,
                                                                                   self.CATEGORY_HEADER),
                                                                columns=self.CATEGORY_HEADER)
            all_dataframes.append(dict_tracker)

        return all_dataframes

    def data_normalizer(self, dataframes):
        """
        Merge and clean data
        :param dataframes:
        :return:
        """
        df_dict = dataframes[0]
        merged_df = pd.concat([df_dict['WEB_SCAN_VULN_BLOCK'], df_dict['WEB_SCAN_SENSITIVE_BLOCK'],
                               df_dict['WEB_SCAN_INFO_BLOCK']], axis=0,
                              ignore_index=False)
        merged_df = pd.merge(merged_df, df_dict['QID_HEADER'], left_on='QID',
                             right_on='Id')

        if 'Content' not in merged_df:
            merged_df['Content'] = ''

        columns_to_cleanse = ['Payload #1', 'Request Method #1', 'Request URL #1',
                              'Request Headers #1', 'Response #1', 'Evidence #1',
                              'Description', 'Impact', 'Solution', 'Url', 'Content']

        for col in columns_to_cleanse:
            merged_df[col] = merged_df[col].apply(self.utils.cleanser)

        merged_df = merged_df.drop(['QID_y', 'QID_x'], axis=1)
        merged_df = merged_df.rename(columns={'Id': 'QID'})

        merged_df = merged_df.assign(**df_dict['SCAN_META'].to_dict(orient='records')[0])

        merged_df = pd.merge(merged_df, df_dict['CATEGORY_HEADER'], how='left', left_on=['Category', 'Severity Level'],
                             right_on=['Category', 'Severity'], suffixes=('Severity', 'CatSev'))

        merged_df = merged_df.replace('N/A', '').fillna('')

        try:
            merged_df = \
                merged_df[~merged_df.Title.str.contains('Links Crawled|External Links Discovered')]
        except Exception as e:
            self.logger.error('Error normalizing: {}'.format(str(e)))
        return merged_df

    def download_file(self, path='', file_id=None):
        report = self.qw.download_report(file_id)
        filename = path + str(file_id) + '.csv'
        file_out = open(filename, 'w')
        for line in report.splitlines():
            file_out.write(line + '\n')
        file_out.close()
        self.logger.info('File written to {}'.format(filename))
        return filename

    def process_data(self, path='', file_id=None, cleanup=True):
        """Downloads a file from qualys and normalizes it"""

        download_file = self.download_file(path=path, file_id=file_id)
        self.logger.info('Downloading file ID: {}'.format(file_id))
        report_data = self.grab_sections(download_file)
        merged_data = self.data_normalizer(report_data)
        merged_data.sort_index(axis=1, inplace=True)

        return merged_data
