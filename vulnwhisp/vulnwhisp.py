#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Austin Taylor'

from base.config import vwConfig
from frameworks.nessus import NessusAPI
from frameworks.qualys import qualysScanReport
from frameworks.qualys_vuln import qualysVulnScan
from frameworks.openvas import OpenVAS_API
from reporting.jira_api import JiraAPI
from utils.cli import bcolors
import pandas as pd
from lxml import objectify
import sys
import os
import io
import time
import sqlite3
import json

# TODO Create logging option which stores data about scan

import logging


class vulnWhispererBase(object):

    CONFIG_SECTION = None

    def __init__(
            self,
            config=None,
            db_name='report_tracker.db',
            purge=False,
            verbose=None,
            debug=False,
            username=None,
            password=None,
            section=None,
            develop=False,
        ):


        if self.CONFIG_SECTION is None:
                raise Exception('Implementing class must define CONFIG_SECTION')

        self.db_name = db_name
        self.purge = purge
        self.develop = develop


        if config is not None:
            self.config = vwConfig(config_in=config)
            try:
                self.enabled = self.config.get(self.CONFIG_SECTION, 'enabled')
            except:
                self.enabled = False
            self.hostname = self.config.get(self.CONFIG_SECTION, 'hostname')
            self.username = self.config.get(self.CONFIG_SECTION, 'username')
            self.password = self.config.get(self.CONFIG_SECTION, 'password')
            self.write_path = self.config.get(self.CONFIG_SECTION, 'write_path')
            self.db_path = self.config.get(self.CONFIG_SECTION, 'db_path')
            self.verbose = self.config.getbool(self.CONFIG_SECTION, 'verbose')



        if self.db_name is not None:
            if self.db_path:
                self.database = os.path.join(self.db_path,
                                             db_name)
            else:
                self.database = \
                    os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 'database', db_name))
            if not os.path.exists(self.db_path):
                os.makedirs(self.db_path)
                self.vprint('{info} Creating directory {dir}'.format(info=bcolors.INFO, dir=self.db_path))

            if not os.path.exists(self.database):
                with open(self.database, 'w'):
                    self.vprint('{info} Creating file {dir}'.format(info=bcolors.INFO, dir=self.database))
                    pass

            try:
                self.conn = sqlite3.connect(self.database)
                self.cur = self.conn.cursor()
                self.vprint('{info} Connected to database at {loc}'.format(info=bcolors.INFO,
                                                                           loc=self.database))
            except Exception as e:
                self.vprint(
                    '{fail} Could not connect to database at {loc}\nReason: {e} - Please ensure the path exist'.format(
                        e=e,
                        fail=bcolors.FAIL, loc=self.database))
        else:

            self.vprint('{fail} Please specify a database to connect to!'.format(fail=bcolors.FAIL))
            exit(1)

        self.table_columns = [
            'scan_name',
            'scan_id',
            'last_modified',
            'filename',
            'download_time',
            'record_count',
            'source',
            'uuid',
            'processed',
        ]

        self.init()
        self.uuids = self.retrieve_uuids()
        self.processed = 0
        self.skipped = 0
        self.scan_list = []

    def vprint(self, msg):
        if self.verbose:
            print(msg)

    def create_table(self):
        self.cur.execute(
            'CREATE TABLE IF NOT EXISTS scan_history (id INTEGER PRIMARY KEY,'
            ' scan_name TEXT, scan_id INTEGER, last_modified DATE, filename TEXT,'
            ' download_time DATE, record_count INTEGER, source TEXT,'
            ' uuid TEXT, processed INTEGER)'
            )
        self.conn.commit()

    def delete_table(self):
        self.cur.execute('DROP TABLE IF EXISTS scan_history')
        self.conn.commit()

    def init(self):
        if self.purge:
            self.delete_table()
        self.create_table()

    def cleanser(self, _data):
        repls = (('\n', r'\n'), ('\r', r'\r'))
        data = reduce(lambda a, kv: a.replace(*kv), repls, _data)
        return data

    def path_check(self, _data):
        if self.write_path:
            if '/' or '\\' in _data[-1]:
                data = self.write_path + _data
            else:
                data = self.write_path + '/' + _data
        return data

    def record_insert(self, record):
        self.cur.execute('insert into scan_history({table_columns}) values (?,?,?,?,?,?,?,?,?)'.format(
            table_columns=', '.join(self.table_columns)),
                         record)
        self.conn.commit()

    def retrieve_uuids(self):
        """
        Retrieves UUIDs from database and checks list to determine which files need to be processed.
        :return:
        """
        try:
            self.conn.text_factory = str
            self.cur.execute('SELECT uuid FROM scan_history where source = "{config_section}"'.format(config_section=self.CONFIG_SECTION))
            results = frozenset([r[0] for r in self.cur.fetchall()])
        except:
            results = []
        return results

    def directory_check(self):
        if not os.path.exists(self.write_path):
            os.makedirs(self.write_path)
            self.vprint('{info} Directory created at {scan} - Skipping creation'.format(
                scan=self.write_path, info=bcolors.INFO))
        else:
            os.path.exists(self.write_path)
            self.vprint('{info} Directory already exist for {scan} - Skipping creation'.format(
                scan=self.write_path, info=bcolors.INFO))

    def get_latest_results(self, source, scan_name):
        try:
            self.conn.text_factory = str
            self.cur.execute('SELECT filename FROM scan_history WHERE source="{}" AND scan_name="{}" ORDER BY id DESC LIMIT 1;'.format(source, scan_name))
            #should always return just one filename
            results = [r[0] for r in self.cur.fetchall()][0]
        except:
            results = []
        return results

        return True

        
    def get_scan_profiles(self):
        # Returns a list of source.scan_name elements from the database
        
        # we get the list of sources
        try:
            self.conn.text_factory = str
            self.cur.execute('SELECT DISTINCT source FROM scan_history;')
            sources = [r[0] for r in self.cur.fetchall()]
        except:
            sources = []
            self.vprint("{fail} Process failed at executing 'SELECT DISTINCT source FROM scan_history;'".format(fail=bcolors.FAIL))
        
        results = []

        # we get the list of scans within each source
        for source in sources:
            scan_names = []
            try:
                self.conn.text_factory = str
                self.cur.execute("SELECT DISTINCT scan_name FROM scan_history WHERE source='{}';".format(source))
                scan_names = [r[0] for r in self.cur.fetchall()]
                for scan in scan_names:
                    results.append('{}.{}'.format(source,scan))
            except:
                scan_names = []

        return results

class vulnWhispererNessus(vulnWhispererBase):

    CONFIG_SECTION = None

    def __init__(
            self,
            config=None,
            db_name='report_tracker.db',
            purge=False,
            verbose=None,
            debug=False,
            username=None,
            password=None,
            profile='nessus'
    ):
        self.CONFIG_SECTION=profile

        super(vulnWhispererNessus, self).__init__(config=config)

        self.port = int(self.config.get(self.CONFIG_SECTION, 'port'))

        self.develop = True
        self.purge = purge

        if config is not None:
            try:
                self.nessus_port = self.config.get(self.CONFIG_SECTION, 'port')

                self.nessus_trash = self.config.getbool(self.CONFIG_SECTION,
                                                        'trash')

                try:
                    self.vprint('{info} Attempting to connect to nessus...'.format(info=bcolors.INFO))
                    self.nessus = \
                        NessusAPI(hostname=self.hostname,
                                  port=self.nessus_port,
                                  username=self.username,
                                  password=self.password)
                    self.nessus_connect = True
                    self.vprint('{success} Connected to nessus on {host}:{port}'.format(success=bcolors.SUCCESS,
                                                                                        host=self.hostname,
                                                                                        port=str(self.nessus_port)))
                except Exception as e:
                    self.vprint(e)
                    raise Exception(
                        '{fail} Could not connect to nessus -- Please verify your settings in {config} are correct and try again.\nReason: {e}'.format(
                            config=self.config.config_in,
                            fail=bcolors.FAIL, e=e))
            except Exception as e:

                self.vprint('{fail} Could not properly load your config!\nReason: {e}'.format(fail=bcolors.FAIL,
                                                                                              e=e))
                sys.exit(1)



    def scan_count(self, scans, completed=False):
        """

        :param scans: Pulls in available scans
        :param completed: Only return completed scans
        :return:
        """

        self.vprint('{info} Gathering all scan data... this may take a while...'.format(info=bcolors.INFO))
        scan_records = []
        for s in scans:
            if s:
                record = {}
                record['scan_id'] = s['id']
                record['scan_name'] = s.get('name', '')
                record['owner'] = s.get('owner', '')
                record['creation_date'] = s.get('creation_date', '')
                record['starttime'] = s.get('starttime', '')
                record['timezone'] = s.get('timezone', '')
                record['folder_id'] = s.get('folder_id', '')
                try:
                    for h in self.nessus.get_scan_history(s['id']):
                        record['uuid'] = h.get('uuid', '')
                        record['status'] = h.get('status', '')
                        record['history_id'] = h.get('history_id', '')
                        record['last_modification_date'] = \
                            h.get('last_modification_date', '')
                        record['norm_time'] = \
                            self.nessus.get_utc_from_local(int(record['last_modification_date'
                                                               ]),
                                                           local_tz=self.nessus.tz_conv(record['timezone'
                                                                                        ]))
                        scan_records.append(record.copy())
                except Exception as e:
                    # Generates error each time nonetype is encountered.
                    # print(e)

                    pass

        if completed:
            scan_records = [s for s in scan_records if s['status'] == 'completed']
        return scan_records


    def whisper_nessus(self):
        if self.nessus_connect:
            scan_data = self.nessus.get_scans()
            folders = scan_data['folders']
            scans = scan_data['scans'] if scan_data['scans'] else []
            all_scans = self.scan_count(scans)
            if self.uuids:
                scan_list = [scan for scan in all_scans if scan['uuid']
                             not in self.uuids and scan['status']
                             == 'completed']
            else:
                scan_list = all_scans
            self.vprint('{info} Identified {new} scans to be processed'.format(info=bcolors.INFO,
                                                                               new=len(scan_list)))

            if not scan_list:
                self.vprint('{info} No new scans to process. Exiting...'.format(info=bcolors.INFO))
                return 0

            # Create scan subfolders

            for f in folders:
                if not os.path.exists(self.path_check(f['name'])):
                    if f['name'] == 'Trash' and self.nessus_trash:
                        os.makedirs(self.path_check(f['name']))
                    elif f['name'] != 'Trash':
                        os.makedirs(self.path_check(f['name']))
                else:
                    os.path.exists(self.path_check(f['name']))
                    self.vprint('{info} Directory already exist for {scan} - Skipping creation'.format(
                        scan=self.path_check(f['name'
                                             ]), info=bcolors.INFO))

            # try download and save scans into each folder the belong to

            scan_count = 0

            # TODO Rewrite this part to go through the scans that have aleady been processed

            for s in scan_list:
                scan_count += 1
                (
                    scan_name,
                    scan_id,
                    history_id,
                    norm_time,
                    status,
                    uuid,
                ) = (
                    s['scan_name'],
                    s['scan_id'],
                    s['history_id'],
                    s['norm_time'],
                    s['status'],
                    s['uuid'],
                )

                # TODO Create directory sync function which scans the directory for files that exist already and populates the database

                folder_id = s['folder_id']
                scan_history = self.nessus.get_scan_history(scan_id)
                if self.CONFIG_SECTION == 'tenable':
                    folder_name = ''
                else:
                    folder_name = next(f['name'] for f in folders if f['id'] == folder_id)
                if status == 'completed':
                    file_name = '%s_%s_%s_%s.%s' % (scan_name, scan_id,
                                                    history_id, norm_time, 'csv')
                    repls = (('\\', '_'), ('/', '_'), ('/', '_'), (' ', '_'))
                    file_name = reduce(lambda a, kv: a.replace(*kv), repls, file_name)
                    relative_path_name = self.path_check(folder_name + '/' + file_name)

                    if os.path.isfile(relative_path_name):
                        if self.develop:
                            csv_in = pd.read_csv(relative_path_name)
                            record_meta = (
                                scan_name,
                                scan_id,
                                norm_time,
                                file_name,
                                time.time(),
                                csv_in.shape[0],
                                self.CONFIG_SECTION,
                                uuid,
                                1,
                            )
                            self.record_insert(record_meta)
                            self.vprint(
                                '{info} File {filename} already exist! Updating database'.format(info=bcolors.INFO,
                                                                                                 filename=relative_path_name))
                    else:
                        file_req = \
                            self.nessus.download_scan(scan_id=scan_id, history=history_id,
                                                      export_format='csv', profile=self.CONFIG_SECTION)
                        clean_csv = \
                            pd.read_csv(io.StringIO(file_req.decode('utf-8'
                                                                    )))
                        if len(clean_csv) > 2:
                            self.vprint('Processing %s/%s for scan: %s'
                                        % (scan_count, len(scan_list),
                                           scan_name))
                            columns_to_cleanse = ['CVSS','CVE','Description','Synopsis','Solution','See Also','Plugin Output']

                            for col in columns_to_cleanse:
                                clean_csv[col] = clean_csv[col].astype(str).apply(self.cleanser)

                            clean_csv.to_csv(relative_path_name, index=False)
                            record_meta = (
                                scan_name,
                                scan_id,
                                norm_time,
                                file_name,
                                time.time(),
                                clean_csv.shape[0],
                                self.CONFIG_SECTION,
                                uuid,
                                1,
                            )
                            self.record_insert(record_meta)
                            self.vprint('{info} {filename} records written to {path} '.format(info=bcolors.INFO,
                                                                                              filename=clean_csv.shape[
                                                                                                  0],
                                                                                              path=file_name))
                        else:
                            record_meta = (
                                scan_name,
                                scan_id,
                                norm_time,
                                file_name,
                                time.time(),
                                clean_csv.shape[0],
                                self.CONFIG_SECTION,
                                uuid,
                                1,
                            )
                            self.record_insert(record_meta)
                            self.vprint(file_name
                                        + ' has no host available... Updating database and skipping!'
                                        )
            self.conn.close()
            '{success} Scan aggregation complete! Connection to database closed.'.format(success=bcolors.SUCCESS)
        else:

            self.vprint('{fail} Failed to use scanner at {host}'.format(fail=bcolors.FAIL,
                                                                        host=self.hostname + ':'
                                                                             + self.nessus_port))


class vulnWhispererQualys(vulnWhispererBase):

    CONFIG_SECTION = 'qualys'
    COLUMN_MAPPING = {'Access Path': 'access_path',
                     'Ajax Request': 'ajax_request',
                     'Ajax Request ID': 'ajax_request_id',
                     'Authentication': 'authentication',
                     'CVSS Base': 'cvss',
                     'CVSS Temporal': 'cvss_temporal',
                     'CWE': 'cwe',
                     'Category': 'category',
                     'Content': 'content',
                     'DescriptionSeverity': 'severity_description',
                     'DescriptionCatSev': 'category_description',
                     'Detection ID': 'detection_id',
                     'Evidence #1': 'evidence_1',
                     'First Time Detected': 'first_time_detected',
                     'Form Entry Point': 'form_entry_point',
                     'Function': 'function',
                     'Groups': 'groups',
                     'ID': 'id',
                     'Ignore Comments': 'ignore_comments',
                     'Ignore Date': 'ignore_date',
                     'Ignore Reason': 'ignore_reason',
                     'Ignore User': 'ignore_user',
                     'Ignored': 'ignored',
                     'Impact': 'impact',
                     'Last Time Detected': 'last_time_detected',
                     'Last Time Tested': 'last_time_tested',
                     'Level': 'level',
                     'OWASP': 'owasp',
                     'Operating System': 'operating_system',
                     'Owner': 'owner',
                     'Param': 'param',
                     'Payload #1': 'payload_1',
                     'QID': 'plugin_id',
                     'Request Headers #1': 'request_headers_1',
                     'Request Method #1': 'request_method_1',
                     'Request URL #1': 'request_url_1',
                     'Response #1': 'response_1',
                     'Scope': 'scope',
                     'Severity': 'risk',
                     'Severity Level': 'security_level',
                     'Solution': 'solution',
                     'Times Detected': 'times_detected',
                     'Title': 'plugin_name',
                     'URL': 'url',
                     'Url': 'uri',
                     'Vulnerability Category': 'vulnerability_category',
                     'WASC': 'wasc',
                     'Web Application Name': 'web_application_name'}
    def __init__(
            self,
            config=None,
            db_name='report_tracker.db',
            purge=False,
            verbose=None,
            debug=False,
            username=None,
            password=None,
        ):

        super(vulnWhispererQualys, self).__init__(config=config)

        self.qualys_scan = qualysScanReport(config=config)
        self.latest_scans = self.qualys_scan.qw.get_all_scans()
        self.directory_check()
        self.scans_to_process = None

    def whisper_reports(self,
                        report_id=None,
                        launched_date=None,
                        scan_name=None,
                        scan_reference=None,
                        output_format='json',
                        cleanup=True):
        """
        report_id: App ID
        updated_date: Last time scan was ran for app_id
        """
        vuln_ready = None

        try:
            if 'Z' in launched_date:
                launched_date = self.qualys_scan.utils.iso_to_epoch(launched_date)
            report_name = 'qualys_web_' + str(report_id) \
                          + '_{last_updated}'.format(last_updated=launched_date) \
                          + '.{extension}'.format(extension=output_format)

            relative_path_name = self.path_check(report_name)

            if os.path.isfile(relative_path_name):
                #TODO Possibly make this optional to sync directories
                file_length = len(open(relative_path_name).readlines())
                record_meta = (
                    scan_name,
                    scan_reference,
                    launched_date,
                    report_name,
                    time.time(),
                    file_length,
                    self.CONFIG_SECTION,
                    report_id,
                    1,
                )
                self.record_insert(record_meta)
                self.vprint('{info} File {filename} already exist! Updating database'.format(info=bcolors.INFO, filename=relative_path_name))

            else:
                print('{action} - Generating report for %s'.format(action=bcolors.ACTION) % report_id)
                status = self.qualys_scan.qw.create_report(report_id)
                root = objectify.fromstring(status)
                if root.responseCode == 'SUCCESS':
                    print('{info} - Successfully generated report! ID: %s'.format(info=bcolors.INFO) \
                          % report_id)
                    generated_report_id = root.data.Report.id
                    print('{info} - New Report ID: %s'.format(info=bcolors.INFO) \
                          % generated_report_id)

                    vuln_ready = self.qualys_scan.process_data(path=self.write_path, file_id=str(generated_report_id))

                    vuln_ready['scan_name'] = scan_name
                    vuln_ready['scan_reference'] = scan_reference
                    vuln_ready.rename(columns=self.COLUMN_MAPPING, inplace=True)

                    record_meta = (
                        scan_name,
                        scan_reference,
                        launched_date,
                        report_name,
                        time.time(),
                        vuln_ready.shape[0],
                        self.CONFIG_SECTION,
                        report_id,
                        1,
                    )
                    self.record_insert(record_meta)

                    if output_format == 'json':
                        with open(relative_path_name, 'w') as f:
                            f.write(vuln_ready.to_json(orient='records', lines=True))
                            f.write('\n')

                    elif output_format == 'csv':
                       vuln_ready.to_csv(relative_path_name, index=False, header=True)  # add when timestamp occured

                    print('{success} - Report written to %s'.format(success=bcolors.SUCCESS) \
                          % report_name)

                    if cleanup:
                        print('{action} - Removing report %s from Qualys Database'.format(action=bcolors.ACTION) \
                              % generated_report_id)
                        cleaning_up = \
                            self.qualys_scan.qw.delete_report(generated_report_id)
                        os.remove(self.path_check(str(generated_report_id) + '.csv'))
                        print('{action} - Deleted report from local disk: %s'.format(action=bcolors.ACTION) \
                              % self.path_check(str(generated_report_id)))
                else:
                    print('{error} Could not process report ID: %s'.format(error=bcolors.FAIL) % status)

        except Exception as e:
            print('{error} - Could not process %s - %s'.format(error=bcolors.FAIL) % (report_id, e))
        return vuln_ready


    def identify_scans_to_process(self):
        if self.uuids:
            self.scans_to_process = self.latest_scans[~self.latest_scans['id'].isin(self.uuids)]
        else:
            self.scans_to_process = self.latest_scans
        self.vprint('{info} Identified {new} scans to be processed'.format(info=bcolors.INFO,
                                                                           new=len(self.scans_to_process)))


    def process_web_assets(self):
        counter = 0
        self.identify_scans_to_process()
        if self.scans_to_process.shape[0]:
            for app in self.scans_to_process.iterrows():
                counter += 1
                r = app[1]
                print('Processing %s/%s' % (counter, len(self.scans_to_process)))
                self.whisper_reports(report_id=r['id'],
                                     launched_date=r['launchedDate'],
                                     scan_name=r['name'],
                                     scan_reference=r['reference'])
        else:
            self.vprint('{info} No new scans to process. Exiting...'.format(info=bcolors.INFO))
        self.conn.close()
        return 0


class vulnWhispererOpenVAS(vulnWhispererBase):
    CONFIG_SECTION = 'openvas'
    COLUMN_MAPPING = {'IP': 'asset',
                      'Hostname': 'hostname',
                      'Port': 'port',
                      'Port Protocol': 'protocol',
                      'CVSS': 'cvss',
                      'Severity': 'severity',
                      'Solution Type': 'category',
                      'NVT Name': 'plugin_name',
                      'Summary': 'synopsis',
                      'Specific Result': 'plugin_output',
                      'NVT OID': 'nvt_oid',
                      'Task ID': 'task_id',
                      'Task Name': 'task_name',
                      'Timestamp': 'timestamp',
                      'Result ID': 'result_id',
                      'Impact': 'description',
                      'Solution': 'solution',
                      'Affected Software/OS': 'affected_software',
                      'Vulnerability Insight': 'vulnerability_insight',
                      'Vulnerability Detection Method': 'vulnerability_detection_method',
                      'Product Detection Result': 'product_detection_result',
                      'BIDs': 'bids',
                      'CERTs': 'certs',
                      'Other References': 'see_also'
                      }

    def __init__(
            self,
            config=None,
            db_name='report_tracker.db',
            purge=False,
            verbose=None,
            debug=False,
            username=None,
            password=None,
    ):
        super(vulnWhispererOpenVAS, self).__init__(config=config)

        self.port = int(self.config.get(self.CONFIG_SECTION, 'port'))
        self.develop = True
        self.purge = purge
        self.scans_to_process = None
        self.openvas_api = OpenVAS_API(hostname=self.hostname,
                                       port=self.port,
                                       username=self.username,
                                       password=self.password)

    def whisper_reports(self, output_format='json', launched_date=None, report_id=None, cleanup=True):
        report = None
        if report_id:
            print('Processing report ID: %s' % report_id)


            scan_name = report_id.replace('-', '')
            report_name = 'openvas_scan_{scan_name}_{last_updated}.{extension}'.format(scan_name=scan_name,
                                                                                       last_updated=launched_date,
                                                                                       extension=output_format)
            relative_path_name = self.path_check(report_name)
            scan_reference = report_id
            print relative_path_name

            if os.path.isfile(relative_path_name):
                # TODO Possibly make this optional to sync directories
                file_length = len(open(relative_path_name).readlines())
                record_meta = (
                    scan_name,
                    scan_reference,
                    launched_date,
                    report_name,
                    time.time(),
                    file_length,
                    self.CONFIG_SECTION,
                    report_id,
                    1,
                )
                self.record_insert(record_meta)
                self.vprint('{info} File {filename} already exist! Updating database'.format(info=bcolors.INFO,
                                                                                             filename=relative_path_name))

                record_meta = (
                    scan_name,
                    scan_reference,
                    launched_date,
                    report_name,
                    time.time(),
                    file_length,
                    self.CONFIG_SECTION,
                    report_id,
                    1,
                )

            else:
                vuln_ready = self.openvas_api.process_report(report_id=report_id)
                vuln_ready['scan_name'] = scan_name
                vuln_ready['scan_reference'] = report_id
                vuln_ready.rename(columns=self.COLUMN_MAPPING, inplace=True)
                vuln_ready.port = vuln_ready.port.fillna(0).astype(int)
                vuln_ready.fillna('', inplace=True)
                if output_format == 'json':
                    with open(relative_path_name, 'w') as f:
                        f.write(vuln_ready.to_json(orient='records', lines=True))
                        f.write('\n')
                print('{success} - Report written to %s'.format(success=bcolors.SUCCESS) \
                      % report_name)

        return report

    def identify_scans_to_process(self):
        if self.uuids:
            self.scans_to_process = self.openvas_api.openvas_reports[
                ~self.openvas_api.openvas_reports.report_ids.isin(self.uuids)]
        else:
            self.scans_to_process = self.openvas_api.openvas_reports
        self.vprint('{info} Identified {new} scans to be processed'.format(info=bcolors.INFO,
                                                                           new=len(self.scans_to_process)))

    def process_openvas_scans(self):
        counter = 0
        self.identify_scans_to_process()
        if self.scans_to_process.shape[0]:
            for scan in self.scans_to_process.iterrows():
                counter += 1
                info = scan[1]
                print(
                '[INFO] Processing %s/%s - Report ID: %s' % (counter, len(self.scans_to_process), info['report_ids']))
                self.whisper_reports(report_id=info['report_ids'],
                                     launched_date=info['epoch'])
            self.vprint('{info} Processing complete!'.format(info=bcolors.INFO))
        else:
            self.vprint('{info} No new scans to process. Exiting...'.format(info=bcolors.INFO))
        self.conn.close()
        return 0


class vulnWhispererQualysVuln(vulnWhispererBase):

    CONFIG_SECTION = 'qualys_vuln'
    COLUMN_MAPPING = {'cvss_base': 'cvss',
                     'cvss3_base': 'cvss3',
                     'cve_id': 'cve',
                     'os': 'operating_system',
                     'qid': 'plugin_id',
                     'severity': 'risk',
                     'title': 'plugin_name'}

    def __init__(
            self,
            config=None,
            db_name='report_tracker.db',
            purge=False,
            verbose=None,
            debug=False,
            username=None,
            password=None,
        ):

        super(vulnWhispererQualysVuln, self).__init__(config=config)

        self.qualys_scan = qualysVulnScan(config=config)
        self.directory_check()
        self.scans_to_process = None

    def whisper_reports(self,
                        report_id=None,
                        launched_date=None,
                        scan_name=None,
                        scan_reference=None,
                        output_format='json',
                        cleanup=True):
        try:
            launched_date
            if 'Z' in launched_date:
                launched_date = self.qualys_scan.utils.iso_to_epoch(launched_date)
            report_name = 'qualys_vuln_' + report_id.replace('/','_') \
                          + '_{last_updated}'.format(last_updated=launched_date) \
                          + '.json'

            relative_path_name = self.path_check(report_name)

            if os.path.isfile(relative_path_name):
                #TODO Possibly make this optional to sync directories
                file_length = len(open(relative_path_name).readlines())
                record_meta = (
                    scan_name,
                    scan_reference,
                    launched_date,
                    report_name,
                    time.time(),
                    file_length,
                    self.CONFIG_SECTION,
                    report_id,
                    1,
                )
                self.record_insert(record_meta)
                self.vprint('{info} File {filename} already exist! Updating database'.format(info=bcolors.INFO, filename=relative_path_name))

            else:
                print('Processing report ID: %s' % report_id)
                vuln_ready = self.qualys_scan.process_data(scan_id=report_id)
                vuln_ready['scan_name'] = scan_name
                vuln_ready['scan_reference'] = report_id
                vuln_ready.rename(columns=self.COLUMN_MAPPING, inplace=True)

                record_meta = (
                    scan_name,
                    scan_reference,
                    launched_date,
                    report_name,
                    time.time(),
                    vuln_ready.shape[0],
                    self.CONFIG_SECTION,
                    report_id,
                    1,
                )
                self.record_insert(record_meta)

                if output_format == 'json':
                    with open(relative_path_name, 'w') as f:
                        f.write(vuln_ready.to_json(orient='records', lines=True))
                        f.write('\n')

                print('{success} - Report written to %s'.format(success=bcolors.SUCCESS) \
                      % report_name)

        except Exception as e:
            print('{error} - Could not process %s - %s'.format(error=bcolors.FAIL) % (report_id, e))


    def identify_scans_to_process(self):
        self.latest_scans = self.qualys_scan.qw.get_all_scans()
        if self.uuids:
            self.scans_to_process = self.latest_scans.loc[
                (~self.latest_scans['id'].isin(self.uuids))
                & (self.latest_scans['status'] == 'Finished')]
        else:
            self.scans_to_process = self.latest_scans
        self.vprint('{info} Identified {new} scans to be processed'.format(info=bcolors.INFO,
                                                                           new=len(self.scans_to_process)))


    def process_vuln_scans(self):
        counter = 0
        self.identify_scans_to_process()
        if self.scans_to_process.shape[0]:
            for app in self.scans_to_process.iterrows():
                counter += 1
                r = app[1]
                print('Processing %s/%s' % (counter, len(self.scans_to_process)))
                self.whisper_reports(report_id=r['id'],
                                     launched_date=r['date'],
                                     scan_name=r['name'],
                                     scan_reference=r['type'])
        else:
            self.vprint('{info} No new scans to process. Exiting...'.format(info=bcolors.INFO))
        self.conn.close()
        return 0


class vulnWhispererJIRA(vulnWhispererBase):

    CONFIG_SECTION = 'jira'

    def __init__(
            self,
            config=None,
            db_name='report_tracker.db',
            purge=False,
            verbose=None,
            debug=False,
            username=None,
            password=None,
        ):
        super(vulnWhispererJIRA, self).__init__(config=config)
        self.config_path = config
        self.config = vwConfig(config)
     
                 
        if config is not None:
            try:
                self.vprint('{info} Attempting to connect to jira...'.format(info=bcolors.INFO))
                self.jira = \
                    JiraAPI(hostname=self.hostname,
                              username=self.username,
                              password=self.password)
                self.jira_connect = True
                self.vprint('{success} Connected to jira on {host}'.format(success=bcolors.SUCCESS,
                                                                                    host=self.hostname))
            except Exception as e:
                self.vprint(e)
                raise Exception(
                    '{fail} Could not connect to nessus -- Please verify your settings in {config} are correct and try again.\nReason: {e}'.format(
                        config=self.config.config_in,
                        fail=bcolors.FAIL, e=e))
                sys.exit(1)
   
        profiles = []
        profiles = self.get_scan_profiles()
        
        if not self.config.exists_jira_profiles(profiles):
            self.config.update_jira_profiles(profiles)
            self.vprint("{info} Jira profiles have been created in {config}, please fill the variables before rerunning the module.".format(info=bcolors.INFO ,config=self.config_path))
            sys.exit(0)
    
   
    def get_env_variables(self, source, scan_name):
        # function returns an array with [jira_project, jira_components, datafile_path]

        #Jira variables
        jira_section = self.config.normalize_section("{}.{}".format(source,scan_name))

        project = self.config.get(jira_section,'jira_project')
        if project == "":
            self.vprint('{fail} JIRA project is missing on the configuration file!'.format(fail=bcolors.FAIL))
            sys.exit(0)
        
        # check that project actually exists
        if not self.jira.project_exists(project):
            self.vprint("{fail} JIRA project '{project}' doesn't exist!".format(fail=bcolors.FAIL, project=project))
            sys.exit(0)
         
        components = self.config.get(jira_section,'components').split(',')
        
        #cleaning empty array from ''
        if not components[0]:
            components = []
        
        min_critical = self.config.get(jira_section,'min_critical_to_report')
        if not min_critical:
            self.vprint('{error} - "min_critical_to_report" variable on config file is empty.'.format(error=bcolors.FAIL))
            sys.exit(0)

        #datafile path
        filename = self.get_latest_results(source, scan_name)
        
        # search data files under user specified directory
        for root, dirnames, filenames in os.walk(vwConfig(self.config_path).get(source,'write_path')):
            if filename in filenames:
                fullpath = "{}/{}".format(root,filename)
        
        if not fullpath:
            self.vprint('{error} - Scan file path "{scan_name}" for source "{source}" has not been found.'.format(error=bcolors.FAIL, scan_name=scan_name, source=source))
            return 0

        return project, components, fullpath, min_critical


    def parse_nessus_vulnerabilities(self, fullpath, source, scan_name, min_critical):
        
        vulnerabilities = []

        # we need to parse the CSV
        risks = ['none', 'low', 'medium', 'high', 'critical'] 
        min_risk = int([i for i,x in enumerate(risks) if x == min_critical][0])
        df = pd.read_csv(fullpath, delimiter=',')
        
        #nessus fields we want - ['Host','Protocol','Port', 'Name', 'Synopsis', 'Description', 'Solution', 'See Also']
        for index in range(len(df)):
            # filtering vulnerabilities by criticality, discarding low risk
            to_report = int([i for i,x in enumerate(risks) if x == df.loc[index]['Risk'].lower()][0])
            if to_report < min_risk:
                continue
            
            if not vulnerabilities or df.loc[index]['Name'] not in [entry['title'] for entry in vulnerabilities]:
                vuln = {}
                #vulnerabilities should have all the info for creating all JIRA labels
                vuln['source'] = source
                vuln['scan_name'] = scan_name
                #vulnerability variables
                vuln['title'] = df.loc[index]['Name']
                vuln['diagnosis'] =  df.loc[index]['Synopsis'].replace('\\n',' ')
                vuln['consequence'] = df.loc[index]['Description'].replace('\\n',' ')
                vuln['solution'] = df.loc[index]['Solution'].replace('\\n',' ')
                vuln['ips'] = []
                vuln['ips'].append("{} - {}/{}".format(df.loc[index]['Host'], df.loc[index]['Protocol'], df.loc[index]['Port']))
                vuln['risk'] = df.loc[index]['Risk'].lower()
                
                # Nessus "nan" value gets automatically casted to float by python
                if not (type(df.loc[index]['See Also']) is float):
                    vuln['references'] = df.loc[index]['See Also'].split("\\n")
                else:
                    vuln['references'] = []
                vulnerabilities.append(vuln)

            else:
                # grouping assets by vulnerability to open on single ticket, as each asset has its own nessus entry
                for vuln in vulnerabilities:
                    if vuln['title'] == df.loc[index]['Name']:
                        vuln['ips'].append("{} - {}/{}".format(df.loc[index]['Host'], df.loc[index]['Protocol'], df.loc[index]['Port']))
        
        return vulnerabilities
    
    def parse_qualys_vuln_vulnerabilities(self, fullpath, source, scan_name, min_critical):
        #parsing of the qualys vulnerabilities schema
        #parse json
        vulnerabilities = []

        risks = ['info', 'low', 'medium', 'high', 'critical'] 
        min_risk = int([i for i,x in enumerate(risks) if x == min_critical][0])

        data=[json.loads(line) for line in open(fullpath).readlines()] 
       
        #qualys fields we want - []
        for index in range(len(data)):
            if int(data[index]['risk']) < min_risk:
                continue
            
            if not vulnerabilities or data[index]['plugin_name'] not in [entry['title'] for entry in vulnerabilities]:
                vuln = {}
                #vulnerabilities should have all the info for creating all JIRA labels
                vuln['source'] = source
                vuln['scan_name'] = scan_name
                #vulnerability variables
                vuln['title'] = data[index]['plugin_name']
                vuln['diagnosis'] =  data[index]['threat'].replace('\\n',' ')
                vuln['consequence'] = data[index]['impact'].replace('\\n',' ')
                vuln['solution'] = data[index]['solution'].replace('\\n',' ')
                vuln['ips'] = []
                #TODO ADDED DNS RESOLUTION FROM QUALYS! \n SEPARATORS INSTEAD OF \\n!
                
                vuln['ips'].append("{ip} - {protocol}/{port} - {dns}".format(**self.get_asset_fields(data[index])))

                #different risk system than Nessus!
                vuln['risk'] = risks[int(data[index]['risk'])-1]
                
                # Nessus "nan" value gets automatically casted to float by python
                if not (type(data[index]['vendor_reference']) is float or data[index]['vendor_reference'] == None):
                    vuln['references'] = data[index]['vendor_reference'].split("\\n")
                else:
                    vuln['references'] = []
                vulnerabilities.append(vuln)
            else:
                # grouping assets by vulnerability to open on single ticket, as each asset has its own nessus entry
                for vuln in vulnerabilities:
                    if vuln['title'] == data[index]['plugin_name']:
                        vuln['ips'].append("{ip} - {protocol}/{port} - {dns}".format(**self.get_asset_fields(data[index])))

        return vulnerabilities

    def get_asset_fields(self, vuln):
        values = {}
        values['ip'] = vuln['ip']
        values['protocol'] = vuln['protocol'] 
        values['port'] = vuln['port'] 
        values['dns'] = vuln['dns']
        for key in values.keys():
            if not values[key]:
                values[key] = 'N/A'

        return values

    def parse_vulnerabilities(self, fullpath, source, scan_name, min_critical):
        #TODO: SINGLE LOCAL SAVE FORMAT FOR ALL SCANNERS
        #JIRA standard vuln format - ['source', 'scan_name', 'title', 'diagnosis', 'consequence', 'solution', 'ips', 'references']

        return 0


    def jira_sync(self, source, scan_name):

        project, components, fullpath, min_critical = self.get_env_variables(source, scan_name)

        vulnerabilities = []

        #***Nessus parsing***
        if source == "nessus":
            vulnerabilities = self.parse_nessus_vulnerabilities(fullpath, source, scan_name, min_critical)

        #***Qualys VM parsing***
        if source == "qualys_vuln":
            vulnerabilities = self.parse_qualys_vuln_vulnerabilities(fullpath, source, scan_name, min_critical)
        
        #***JIRA sync***
        if vulnerabilities:
            self.vprint('{info} {source} data has been successfuly parsed'.format(info=bcolors.INFO, source=source.upper()))
            self.vprint('{info} Starting JIRA sync'.format(info=bcolors.INFO))
            
            self.jira.sync(vulnerabilities, project, components)
        else:
            self.vprint("{fail} Vulnerabilities from {source} has not been parsed! Exiting...".format(fail=bcolors.FAIL, source=source))
            sys.exit(0)

        return True


class vulnWhisperer(object):

    def __init__(self,
                 profile=None,
                 verbose=None,
                 username=None,
                 password=None,
                 config=None,
                 source=None,
                 scanname=None):

        self.profile = profile
        self.config = config
        self.username = username
        self.password = password
        self.verbose = verbose
        self.source = source
        self.scanname = scanname


    def whisper_vulnerabilities(self):

        if self.profile == 'nessus':
            vw = vulnWhispererNessus(config=self.config,
                                     username=self.username,
                                     password=self.password,
                                     verbose=self.verbose,
                                     profile=self.profile)
            vw.whisper_nessus()

        elif self.profile == 'qualys':
            vw = vulnWhispererQualys(config=self.config)
            vw.process_web_assets()

        elif self.profile == 'openvas':
            vw_openvas = vulnWhispererOpenVAS(config=self.config)
            vw_openvas.process_openvas_scans()

        elif self.profile == 'tenable':
            vw = vulnWhispererNessus(config=self.config,
                                     username=self.username,
                                     password=self.password,
                                     verbose=self.verbose,
                                     profile=self.profile)
            vw.whisper_nessus()

        elif self.profile == 'qualys_vuln':
            vw = vulnWhispererQualysVuln(config=self.config)
            vw.process_vuln_scans()
        
        elif self.profile == 'jira':
            #first we check config fields are created, otherwise we create them
            vw = vulnWhispererJIRA(config=self.config)
            if not (self.source and self.scanname):
                print('{error} - Source scanner and scan name needed!'.format(error=bcolors.FAIL))
                return 0
            vw.jira_sync(self.source, self.scanname)
