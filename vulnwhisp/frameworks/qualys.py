__author__ = 'Austin Taylor'

import qualysapi
from lxml import objectify
from lxml.builder import E
import xml.etree.ElementTree as ET
import pandas as pd
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import sys
import csv


class qualysWhisper(object):
    COUNT = '/count/was/webapp'
    VERSION = '/qps/rest/portal/version'
    QPS_REST_3 = '/qps/rest/3.0'
    SEARCH_REPORTS = QPS_REST_3 + '/search/was/report'
    SEARCH_WEB_APPS = QPS_REST_3 + '/search/was/webapp'
    REPORT_DETAILS = QPS_REST_3 + '/get/was/report/{report_id}'
    REPORT_STATUS = QPS_REST_3 + '/status/was/report/{report_id}'
    REPORT_DOWNLOAD = QPS_REST_3 + '/download/was/report/{report_id}'

    def __init__(self, config=None):
        self.config = config
        try:
            self.qgc = qualysapi.connect(config)
            print('[SUCCESS] - Connected to Qualys at %s' % self.qgc.server)
        except Exception as e:
            print('[ERROR] Could not connect to Qualys - %s' % e)
        self.headers = {
            "content-type": "text/xml"}

    def request(self, path, method='get'):
        methods = {'get': requests.get,
                   'post': requests.post}
        base = 'https://' + self.qgc.server + path
        req = methods[method](base, auth=self.qgc.auth, headers=self.headers).content
        return req

    def get_version(self):
        return self.request(self.VERSION)

    def get_scan_count(self, scan_name):
        parameters = (
            E.ServiceRequest(
                E.filters(
                    E.Criteria(scan_name, field='name', operator='CONTAINS'))))
        xml_output = self.qgc.request(self.COUNT, parameters)
        root = objectify.fromstring(xml_output)
        return root.count.text

    def get_reports(self):
        return self.request(self.SEARCH_REPORTS, method='post')

    def xml_parser(self, xml, dupfield=None):
        all_records = []
        root = ET.XML(xml)
        for i, child in enumerate(root):
            for subchild in child:
                record = {}
                for p in subchild:
                    record[p.tag] = p.text
                    for o in p:
                        if o.tag == 'id':
                            record[dupfield] = o.text
                        else:
                            record[o.tag] = o.text
                all_records.append(record)
        return pd.DataFrame(all_records)

    def get_report_list(self):
        """Returns a dataframe of reports"""
        return self.xml_parser(self.get_reports(), dupfield='user_id')

    def get_web_apps(self):
        """Returns webapps available for account"""
        return self.request(self.SEARCH_WEB_APPS, method='post')

    def get_web_app_list(self):
        """Returns dataframe of webapps"""
        return self.xml_parser(self.get_web_apps(), dupfield='app_id')

    def get_report_details(self, report_id):
        r = self.REPORT_DETAILS.format(report_id=report_id)
        return self.request(r)

    def get_report_status(self, report_id):
        r = self.REPORT_STATUS.format(report_id=report_id)
        return self.request(r)

    def download_report(self, report_id):
        r = self.REPORT_DOWNLOAD.format(report_id=report_id)
        return self.request(r)


class qualysWebAppReport:
    WEB_APP_VULN_HEADER = ["Web Application Name", "VULNERABILITY", "ID", "QID", "Url", "Param", "Function",
                           "Form Entry Point",
                           "Access Path", "Authentication", "Ajax Request", "Ajax Request ID", "Status", "Ignored",
                           "Ignore Reason",
                           "Ignore Date", "Ignore User", "Ignore Comments", "First Time Detected",
                           "Last Time Detected", "Last Time Tested",
                           "Times Detected", "Payload #1", "Request Method #1", "Request URL #1",
                           "Request Headers #1", "Response #1", "Evidence #1"]
    WEB_APP_INFO_HEADER = ["Web Application Name", "INFORMATION GATHERED", "ID", "QID", "Results", "Detection Date"]
    QID_HEADER = ["QID", "Id", "Title", "Category", "Severity Level", "Groups", "OWASP", "WASC", "CWE", "CVSS Base",
                  "CVSS Temporal", "Description", "Impact", "Solution"]
    GROUP_HEADER = ["GROUP", "Name", "Category"]
    OWASP_HEADER = ["OWASP", "Code", "Name"]
    WASC_HEADER = ["WASC", "Code", "Name"]
    CATEGORY_HEADER = ["Category", "Severity", "Level", "Description"]

    def __init__(self, config=None, file_in=None, file_stream=False, delimiter=',', quotechar='"'):
        self.file_in = file_in
        self.file_stream = file_stream
        self.report = None
        self.get_sys_max()

        if config:
            try:
                self.qw = qualysWhisper(config=config)
            except Exception as e:
                print('Could not load config! Please check settings for %s' % config)

        if file_stream:
            self.open_file = file_in.splitlines()

        elif file_in:
            self.open_file = open(file_in, 'rb')

        # self.report = csv.reader(self.open_file, delimiter=delimiter, quotechar=quotechar)
        # self.hostname = self.get_hostname(file_in)
        self.downloaded_file = None

    def get_sys_max(self):
        maxInt = sys.maxsize
        decrement = True

        while decrement:
            # decrease the maxInt value by factor 10
            # as long as the OverflowError occurs.

            decrement = False
            try:
                csv.field_size_limit(maxInt)
            except OverflowError:
                maxInt = int(maxInt / 10)
                decrement = True

    def get_hostname(self, report):
        host = ''
        with open(report, 'rb') as csvfile:
            q_report = csv.reader(csvfile, delimiter=',', quotechar='"')
            for x in q_report:
                # if ('Web Application Name' and 'VULNERABILITY') in x:
                if 'Web Application Name' in x[0]:
                    host = q_report.next()[0]
        return host


    def grab_section(self, report, section, end='', pop_last=False):
        temp_list = []
        with open(report, 'rb') as csvfile:
            # q_report = csv.reader(self., delimiter=',', quotechar='"')
            q_report = csv.reader(csvfile, delimiter=',', quotechar='"')
            for line in q_report:
                if set(line) == set(section):  # Or whatever test is needed
                    break
            # Reads text until the end of the block:
            for line in q_report:  # This keeps reading the file
                temp_list.append(line)
                if set(line) == end:
                    break
            if pop_last and len(temp_list) > 1:
                last_line = temp_list.pop(-1)
        return temp_list

    def cleanser(self, _data):
        repls = ('\n', '|||'), ('\r', '|||'), (',', ';'), ('\t', '|||')
        data = reduce(lambda a, kv: a.replace(*kv), repls, _data)
        return data

    def grab_sections(self, report):
        all_dataframes = []
        category_list = []
        with open(report, 'rb') as csvfile:
            q_report = csv.reader(csvfile, delimiter=',', quotechar='"')
            all_dataframes.append(pd.DataFrame(
                self.grab_section(report, self.WEB_APP_VULN_HEADER, end=set(self.WEB_APP_INFO_HEADER), pop_last=True),
                columns=self.WEB_APP_VULN_HEADER))
            all_dataframes.append(pd.DataFrame(
                self.grab_section(report, self.WEB_APP_INFO_HEADER, end=set(self.QID_HEADER), pop_last=True),
                columns=self.WEB_APP_INFO_HEADER))
            all_dataframes.append(
                pd.DataFrame(self.grab_section(report, self.QID_HEADER, end=set(self.GROUP_HEADER), pop_last=True),
                             columns=self.QID_HEADER))
            all_dataframes.append(
                pd.DataFrame(self.grab_section(report, self.GROUP_HEADER, end=set(self.OWASP_HEADER), pop_last=True),
                             columns=self.GROUP_HEADER))
            all_dataframes.append(
                pd.DataFrame(self.grab_section(report, self.OWASP_HEADER, end=set(self.WASC_HEADER), pop_last=True),
                             columns=self.OWASP_HEADER))
            all_dataframes.append(
                pd.DataFrame(self.grab_section(report, self.WASC_HEADER, end=set(['APPENDIX']), pop_last=True),
                             columns=self.WASC_HEADER))
            all_dataframes.append(
                pd.DataFrame(self.grab_section(report, self.CATEGORY_HEADER, end=''), columns=self.CATEGORY_HEADER))
        return all_dataframes

    def data_normalizer(self, dataframes):
        """
        Merge and clean data
        :param dataframes:
        :return:
        """
        merged_df = pd.merge(dataframes[0], dataframes[2], left_on='QID', right_on='Id')
        merged_df['Payload #1'] = merged_df['Payload #1'].apply(self.cleanser)
        merged_df['Request Method #1'] = merged_df['Request Method #1'].apply(self.cleanser)
        merged_df['Request URL #1'] = merged_df['Request URL #1'].apply(self.cleanser)
        merged_df['Request Headers #1'] = merged_df['Request Headers #1'].apply(self.cleanser)
        merged_df['Response #1'] = merged_df['Response #1'].apply(self.cleanser)
        merged_df['Evidence #1'] = merged_df['Evidence #1'].apply(self.cleanser)
        merged_df['QID_y'] = merged_df['QID_y'].apply(self.cleanser)
        merged_df['Id'] = merged_df['Id'].apply(self.cleanser)
        merged_df['Title'] = merged_df['Title'].apply(self.cleanser)
        merged_df['Category'] = merged_df['Category'].apply(self.cleanser)
        merged_df['Severity Level'] = merged_df['Severity Level'].apply(self.cleanser)
        merged_df['Groups'] = merged_df['Groups'].apply(self.cleanser)
        merged_df['OWASP'] = merged_df['OWASP'].apply(self.cleanser)
        merged_df['WASC'] = merged_df['WASC'].apply(self.cleanser)
        merged_df['CWE'] = merged_df['CWE'].apply(self.cleanser)
        merged_df['CVSS Base'] = merged_df['CVSS Base'].apply(self.cleanser)
        merged_df['CVSS Temporal'] = merged_df['CVSS Temporal'].apply(self.cleanser)
        merged_df['Description'] = merged_df['Description'].apply(self.cleanser)
        merged_df['Impact'] = merged_df['Impact'].apply(self.cleanser)
        merged_df['Solution'] = merged_df['Solution'].apply(self.cleanser)
        merged_df = merged_df.drop(['QID_y', 'QID_x'], axis=1)
        merged_df = merged_df.rename(columns={'Id': 'QID'})
        return merged_df

    def download_file(self, file_id):
        report = self.qw.download_report(file_id)
        filename = file_id + '.csv'
        file_out = open(filename, 'w')
        for line in report.splitlines():
            file_out.write(line + '\n')
        file_out.close()
        print('File written to %s' % filename)
        return filename

    def process_data(self, file_id):
        """Downloads a file from qualys and normalizes it"""
        download_file = self.download_file(file_id)
        print('Downloading file ID: %s' % file_id)
        report_data = self.grab_sections(download_file)
        merged_data = self.data_normalizer(report_data)
        return merged_data