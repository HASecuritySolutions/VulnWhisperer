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
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import sys
import os
import csv
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
        self.config = config
        try:
            self.qgc = qualysapi.connect(config)
            print('[SUCCESS] - Connected to Qualys at %s' % self.qgc.server)
        except Exception as e:
            print('[ERROR] Could not connect to Qualys - %s' % e)
        self.headers = {
            "content-type": "text/xml"}
        self.config_parse = qcconf.QualysConnectConfig(config)
        try:
            self.template_id = self.config_parse.get_template_id()
        except:
            print('ERROR - Could not retrieve template ID')

    def request(self, path, method='get', data=None):
        methods = {'get': requests.get,
                   'post': requests.post}
        base = 'https://' + self.qgc.server + path
        req = methods[method](base, auth=self.qgc.auth, data=data, headers=self.headers).content
        return req

    def get_version(self):
        return self.request(self.VERSION)

    def get_scan_count(self, scan_name):
        parameters = (
            E.ServiceRequest(
                E.filters(
                    E.Criteria({'field': 'name', 'operator': 'CONTAINS'}, scan_name))))
        xml_output = self.qgc.request(self.COUNT_WEBAPP, parameters)
        root = objectify.fromstring(xml_output)
        return root.count.text

    def get_was_scan_count(self, status):
        parameters = (
            E.ServiceRequest(
                E.filters(
                    E.Criteria({'field': 'status', 'operator': 'EQUALS'}, status))))
        xml_output = self.qgc.request(self.COUNT_WASSCAN, parameters)
        root = objectify.fromstring(xml_output)
        return root.count.text

    def get_reports(self):
        return self.qgc.request(self.SEARCH_REPORTS)

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

    def get_report_list(self):
        """Returns a dataframe of reports"""
        return self.xml_parser(self.get_reports(), dupfield='user_id')

    def get_web_apps(self):
        """Returns webapps available for account"""
        return self.qgc.request(self.SEARCH_WEB_APPS)

    def get_web_app_list(self):
        """Returns dataframe of webapps"""
        return self.xml_parser(self.get_web_apps(), dupfield='user_id')

    def get_web_app_details(self, was_id):
        """Get webapp details - use to retrieve app ID tag"""
        return self.qgc.request(self.GET_WEBAPP_DETAILS.format(was_id=was_id))

    def get_scans_by_app_id(self, app_id):
        data = self.generate_app_id_scan_XML(app_id)
        return self.qgc.request(self.SEARCH_WAS_SCAN, data)

    def get_scan_info(self, limit=1000, offset=1, status='FINISHED'):
        """ Returns XML of ALL WAS Scans"""
        data = self.generate_scan_result_XML(limit=limit, offset=offset, status=status)
        return self.qgc.request(self.SEARCH_WAS_SCAN, data)

    def get_all_scans(self, limit=1000, offset=1, status='FINISHED'):
        qualys_api_limit = limit
        dataframes = []
        _records = []
        total = int(self.get_was_scan_count(status=status))
        print('Retrieving information for %s scans' % total)
        for i in range(0, total):
            if i % limit == 0:
                if (total - i) < limit:
                    qualys_api_limit = total - i
                print('Making a request with a limit of %s at offset %s' % (str(qualys_api_limit), str(i + 1)))
                scan_info = self.get_scan_info(limit=qualys_api_limit, offset=i + 1, status=status)
                _records.append(scan_info)
        print('Converting XML to DataFrame')
        dataframes = [self.xml_parser(xml) for xml in _records]

        return pd.concat(dataframes, axis=0).reset_index().drop('index', axis=1)

    def get_scan_details(self, scan_id):
        return self.qgc.request(self.SCAN_DETAILS.format(scan_id=scan_id))

    def get_report_details(self, report_id):
        return self.qgc.request(self.REPORT_DETAILS.format(report_id=report_id))

    def get_report_status(self, report_id):
        return self.qgc.request(self.REPORT_STATUS.format(report_id=report_id))

    def download_report(self, report_id):
        return self.qgc.request(self.REPORT_DOWNLOAD.format(report_id=report_id))

    def download_scan_results(self, scan_id):
        return self.qgc.request(self.SCAN_DOWNLOAD.format(scan_id=scan_id))

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

    def generate_scan_report_XML(self, scan_id):
        """Generates a CSV report for an asset based on template defined in .ini file"""
        report_xml = E.ServiceRequest(
            E.data(
                E.Report(
                    E.name('![CDATA[API Scan Report generated by VulnWhisperer]]>'),
                    E.description('<![CDATA[CSV Scanning report for VulnWhisperer]]>'),
                    E.format('CSV'),
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

    def generate_webapp_report_XML(self, app_id):
        """Generates a CSV report for an asset based on template defined in .ini file"""
        report_xml = E.ServiceRequest(
            E.data(
                E.Report(
                    E.name('![CDATA[API Web Application Report generated by VulnWhisperer]]>'),
                    E.description('<![CDATA[CSV WebApp report for VulnWhisperer]]>'),
                    E.format('CSV'),
                    E.template(
                        E.id(self.template_id)
                    ),
                    E.config(
                        E.webAppReport(
                            E.target(
                                E.webapps(
                                    E.WebApp(
                                        E.id(app_id)
                                    )
                                ),
                            ),
                        ),
                    )
                )
            )
        )
        return report_xml

    def generate_app_id_scan_XML(self, app_id):
        report_xml = E.ServiceRequest(
            E.filters(
                E.Criteria({'field': 'webApp.id', 'operator': 'EQUALS'}, app_id
                           ),
            ),
        )
        return report_xml

    def create_report(self, report_id, kind='scan'):
        mapper = {'scan': self.generate_scan_report_XML,
                  'webapp': self.generate_webapp_report_XML}
        try:
            # print lxml.etree.tostring(mapper[kind](report_id), pretty_print=True)
            data = mapper[kind](report_id)
        except Exception as e:
            print(e)

        return self.qgc.request(self.REPORT_CREATE, data)

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
        pass

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


class qualysWebAppReport:
    # URL Vulnerability Information
    WEB_APP_VULN_BLOCK = list(qualysReportFields.VULN_BLOCK)
    WEB_APP_VULN_BLOCK.insert(0, 'Web Application Name')
    WEB_APP_VULN_BLOCK.insert(WEB_APP_VULN_BLOCK.index('Ignored'), 'Status')

    WEB_APP_VULN_HEADER = list(WEB_APP_VULN_BLOCK)
    WEB_APP_VULN_HEADER[WEB_APP_VULN_BLOCK.index(qualysReportFields.CATEGORIES[0])] = \
        'Vulnerability Category'

    WEB_APP_SENSITIVE_HEADER = list(WEB_APP_VULN_HEADER)
    WEB_APP_SENSITIVE_HEADER.insert(WEB_APP_SENSITIVE_HEADER.index('Url'
                                                                   ), 'Content')

    WEB_APP_SENSITIVE_BLOCK = list(WEB_APP_SENSITIVE_HEADER)
    WEB_APP_SENSITIVE_BLOCK[WEB_APP_SENSITIVE_BLOCK.index('Vulnerability Category'
                                                          )] = qualysReportFields.CATEGORIES[1]

    WEB_APP_INFO_HEADER = list(qualysReportFields.INFO_HEADER)
    WEB_APP_INFO_HEADER.insert(0, 'Web Application Name')

    WEB_APP_INFO_BLOCK = list(qualysReportFields.INFO_BLOCK)
    WEB_APP_INFO_BLOCK.insert(0, 'Web Application Name')

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
        self.file_in = file_in
        self.file_stream = file_stream
        self.report = None
        self.utils = qualysUtils()

        if config:
            try:
                self.qw = qualysWhisperAPI(config=config)
            except Exception as e:
                print('Could not load config! Please check settings for %s' \
                      % e)

        if file_stream:
            self.open_file = file_in.splitlines()
        elif file_in:

            self.open_file = open(file_in, 'rb')

        self.downloaded_file = None

    def get_hostname(self, report):
        host = ''
        with open(report, 'rb') as csvfile:
            q_report = csv.reader(csvfile, delimiter=',', quotechar='"')
            for x in q_report:

                if 'Web Application Name' in x[0]:
                    host = q_report.next()[0]
        return host

    def get_scanreport_name(self, report):
        scan_name = ''
        with open(report, 'rb') as csvfile:
            q_report = csv.reader(csvfile, delimiter=',', quotechar='"')
            for x in q_report:

                if 'Scans' in x[0]:
                    scan_name = x[1]
        return scan_name

    def grab_sections(self, report):
        all_dataframes = []
        dict_tracker = {}
        with open(report, 'rb') as csvfile:
            dict_tracker['WEB_APP_VULN_BLOCK'] = pd.DataFrame(self.utils.grab_section(report,
                                                                       self.WEB_APP_VULN_BLOCK,
                                                                       end=[self.WEB_APP_SENSITIVE_BLOCK,
                                                                            self.WEB_APP_INFO_BLOCK],
                                                                       pop_last=True), columns=self.WEB_APP_VULN_HEADER)
            dict_tracker['WEB_APP_SENSITIVE_BLOCK'] = pd.DataFrame(self.utils.grab_section(report,
                                                                       self.WEB_APP_SENSITIVE_BLOCK,
                                                                       end=[self.WEB_APP_INFO_BLOCK,
                                                                            self.WEB_APP_SENSITIVE_BLOCK],
                                                                       pop_last=True), columns=self.WEB_APP_SENSITIVE_HEADER)
            dict_tracker['WEB_APP_INFO_BLOCK'] = pd.DataFrame(self.utils.grab_section(report,
                                                                       self.WEB_APP_INFO_BLOCK,
                                                                       end=[self.QID_HEADER],
                                                                       pop_last=True), columns=self.WEB_APP_INFO_HEADER)
            dict_tracker['QID_HEADER'] = pd.DataFrame(self.utils.grab_section(report,
                                                                       self.QID_HEADER,
                                                                       end=[self.GROUP_HEADER],
                                                                       pop_last=True), columns=self.QID_HEADER)
            dict_tracker['GROUP_HEADER'] = pd.DataFrame(self.utils.grab_section(report,
                                                                       self.GROUP_HEADER,
                                                                       end=[self.OWASP_HEADER],
                                                                       pop_last=True), columns=self.GROUP_HEADER)
            dict_tracker['OWASP_HEADER'] = pd.DataFrame(self.utils.grab_section(report,
                                                                       self.OWASP_HEADER,
                                                                       end=[self.WASC_HEADER],
                                                                       pop_last=True), columns=self.OWASP_HEADER)
            dict_tracker['WASC_HEADER'] = pd.DataFrame(self.utils.grab_section(report,
                                                                       self.WASC_HEADER, end=[['APPENDIX']],
                                                                       pop_last=True), columns=self.WASC_HEADER)
            dict_tracker['CATEGORY_HEADER'] =pd.DataFrame(self.utils.grab_section(report,
                                                                       self.CATEGORY_HEADER), columns=self.CATEGORY_HEADER)
            all_dataframes.append(dict_tracker)

        return all_dataframes

    def data_normalizer(self, dataframes):
        """
        Merge and clean data
        :param dataframes:
        :return:
        """
        df_dict = dataframes[0]
        merged_df = pd.concat([df_dict['WEB_APP_VULN_BLOCK'], df_dict['WEB_APP_SENSITIVE_BLOCK'],
                               df_dict['WEB_APP_INFO_BLOCK']], axis=0,
                              ignore_index=False)

        merged_df = pd.merge(merged_df, df_dict['QID_HEADER'], left_on='QID',
                             right_on='Id')

        merged_df = pd.concat([dataframes[0], dataframes[1],
                               dataframes[2]], axis=0,
                              ignore_index=False)
        merged_df = pd.merge(merged_df, dataframes[3], left_on='QID',
                             right_on='Id')

        if 'Content' not in merged_df:
            merged_df['Content'] = ''

        columns_to_cleanse = ['Payload #1', 'Request Method #1', 'Request URL #1',
                              'Request Headers #1', 'Response #1', 'Evidence #1',
                              'Description', 'Impact', 'Solution', 'Url', 'Content']

        for col in columns_to_cleanse:
            merged_df[col] = merged_df[col].astype(str).apply(self.utils.cleanser)

        merged_df = pd.merge(merged_df, df_dict['CATEGORY_HEADER'])
        merged_df = merged_df.drop(['QID_y', 'QID_x'], axis=1)
        merged_df = merged_df.rename(columns={'Id': 'QID'})
        merged_df = merged_df.replace('N/A','').fillna('')

        try:
            merged_df = \
                merged_df[~merged_df.Title.str.contains('Links Crawled|External Links Discovered'
                                                        )]
        except Exception as e:
            print(e)
        return merged_df

    def download_file(self, file_id):
        report = self.qw.download_report(file_id)
        filename = str(file_id) + '.csv'
        file_out = open(filename, 'w')
        for line in report.splitlines():
            file_out.write(line + '\n')
        file_out.close()
        print('[ACTION] - File written to %s' % filename)
        return filename

    def remove_file(self, filename):
        os.remove(filename)

    def process_data(self, file_id, scan=True, cleanup=True):
        """Downloads a file from qualys and normalizes it"""

        download_file = self.download_file(file_id)
        print('[ACTION] - Downloading file ID: %s' % file_id)
        report_data = self.grab_sections(download_file)
        merged_data = self.data_normalizer(report_data)
        if scan:
            scan_name = self.get_scanreport_name(download_file)
            merged_data['ScanName'] = scan_name

        # TODO cleanup old data (delete)

        return merged_data

    def whisper_reports(self, report_id, updated_date, cleanup=False):
        """
        report_id: App ID
        updated_date: Last time scan was ran for app_id
        """
        vuln_ready = None
        try:

            if 'Z' in updated_date:
                updated_date = self.utils.iso_to_epoch(updated_date)
            report_name = 'qualys_web_' + str(report_id) \
                          + '_{last_updated}'.format(last_updated=updated_date) \
                          + '.csv'
            if os.path.isfile(report_name):
                print('[ACTION] - File already exist! Skipping...')
                pass
            else:
                print('[ACTION] - Generating report for %s' % report_id)
                status = self.qw.create_report(report_id)
                root = objectify.fromstring(status)
                if root.responseCode == 'SUCCESS':
                    print('[INFO] - Successfully generated report for webapp: %s' \
                          % report_id)
                    generated_report_id = root.data.Report.id
                    print ('[INFO] - New Report ID: %s' \
                           % generated_report_id)
                    vuln_ready = self.process_data(generated_report_id)

                    vuln_ready.to_csv(report_name, index=False, header=True)  # add when timestamp occured
                    print('[SUCCESS] - Report written to %s' \
                          % report_name)
                    if cleanup:
                        print('[ACTION] - Removing report %s' \
                              % generated_report_id)
                        cleaning_up = \
                            self.qw.delete_report(generated_report_id)
                        self.remove_file(str(generated_report_id) + '.csv')
                        print('[ACTION] - Deleted report: %s' \
                              % generated_report_id)
                else:
                    print('Could not process report ID: %s' % status)
        except Exception as e:
            print('[ERROR] - Could not process %s - %s' % (report_id, e))
        return vuln_ready


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
        self.file_in = file_in
        self.file_stream = file_stream
        self.report = None
        self.utils = qualysUtils()

        if config:
            try:
                self.qw = qualysWhisperAPI(config=config)
            except Exception as e:
                print('Could not load config! Please check settings for %s' \
                      % e)

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
                merged_df[~merged_df.Title.str.contains('Links Crawled|External Links Discovered'
                                                        )]
        except Exception as e:
            print(e)
        return merged_df

    def download_file(self, path='', file_id=None):
        report = self.qw.download_report(file_id)
        filename = path + str(file_id) + '.csv'
        file_out = open(filename, 'w')
        for line in report.splitlines():
            file_out.write(line + '\n')
        file_out.close()
        print('[ACTION] - File written to %s' % filename)
        return filename

    def remove_file(self, filename):
        os.remove(filename)

    def process_data(self, path='', file_id=None, cleanup=True):
        """Downloads a file from qualys and normalizes it"""

        download_file = self.download_file(path=path, file_id=file_id)
        print('[ACTION] - Downloading file ID: %s' % file_id)
        report_data = self.grab_sections(download_file)
        merged_data = self.data_normalizer(report_data)
        merged_data.sort_index(axis=1, inplace=True)
        # TODO cleanup old data (delete)

        return merged_data

    def whisper_reports(self, report_id, updated_date, cleanup=False):
        """
        report_id: App ID
        updated_date: Last time scan was ran for app_id
        """
        vuln_ready = None
        try:

            if 'Z' in updated_date:
                updated_date = self.utils.iso_to_epoch(updated_date)
            report_name = 'qualys_web_' + str(report_id) \
                          + '_{last_updated}'.format(last_updated=updated_date) \
                          + '.csv'
            if os.path.isfile(report_name):
                print('[ACTION] - File already exist! Skipping...')
                pass
            else:
                print('[ACTION] - Generating report for %s' % report_id)
                status = self.qw.create_report(report_id)
                root = objectify.fromstring(status)
                if root.responseCode == 'SUCCESS':
                    print('[INFO] - Successfully generated report for webapp: %s' \
                          % report_id)
                    generated_report_id = root.data.Report.id
                    print ('[INFO] - New Report ID: %s' \
                           % generated_report_id)
                    vuln_ready = self.process_data(generated_report_id)

                    vuln_ready.to_csv(report_name, index=False, header=True)  # add when timestamp occured
                    print('[SUCCESS] - Report written to %s' \
                          % report_name)
                    if cleanup:
                        print('[ACTION] - Removing report %s from disk' \
                              % generated_report_id)
                        cleaning_up = \
                            self.qw.delete_report(generated_report_id)
                        self.remove_file(str(generated_report_id) + '.csv')
                        print('[ACTION] - Deleted report from Qualys Database: %s' \
                              % generated_report_id)
                else:
                    print('Could not process report ID: %s' % status)
        except Exception as e:
            print('[ERROR] - Could not process %s - %s' % (report_id, e))
        return vuln_ready


maxInt = sys.maxsize
decrement = True

while decrement:
    decrement = False
    try:
        csv.field_size_limit(maxInt)
    except OverflowError:
        maxInt = int(maxInt/10)
        decrement = True