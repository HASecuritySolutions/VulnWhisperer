#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Austin Taylor'

from base.config import vwConfig
from frameworks.nessus import NessusAPI
from frameworks.qualys import qualysScanReport
from utils.cli import bcolors
import pandas as pd
from lxml import objectify
import sys
import os
import io
import time
import sqlite3

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
            self.enabled = self.config.get(self.CONFIG_SECTION, 'enabled')
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
            exit(0)

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
        repls = (('\n', '|||'), ('\r', '|||'), (',', ';'))
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

class vulnWhispererNessus(vulnWhispererBase):

    CONFIG_SECTION = 'nessus'

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
                            config=self.config,
                            fail=bcolors.FAIL, e=e))
            except Exception as e:

                self.vprint('{fail} Could not properly load your config!\nReason: {e}'.format(fail=bcolors.FAIL,
                                                                                              e=e))
                sys.exit(0)



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
            scans = scan_data['scans']
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
                exit(0)

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
                folder_name = next(f['name'] for f in folders if f['id'
                ] == folder_id)
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
                            self.nessus.download_scan(scan_id=scan_id,
                                                      history=history_id, export_format='csv')
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

                            clean_csv['Synopsis'] = \
                                clean_csv['Description'
                                ].astype(str).apply(self.cleanser)
                            clean_csv.to_csv(relative_path_name,
                                             index=False)
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

        super(vulnWhispererQualys, self).__init__(config=config, )

        self.qualys_scan = qualysScanReport(config=config)
        self.latest_scans = self.qualys_scan.qw.get_all_scans()
        self.directory_check()
        self.scans_to_process = None


    def directory_check(self):
        if not os.path.exists(self.write_path):
            os.makedirs(self.write_path)
            self.vprint('{info} Directory created at {scan} - Skipping creation'.format(
                scan=self.write_path, info=bcolors.INFO))
        else:
            os.path.exists(self.write_path)
            self.vprint('{info} Directory already exist for {scan} - Skipping creation'.format(
                scan=self.write_path, info=bcolors.INFO))

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
        exit(0)





class vulnWhisperer(object):

    def __init__(self,
                 profile=None,
                 verbose=None,
                 username=None,
                 password=None,
                 config=None):

        self.profile = profile
        self.config = config
        self.username = username
        self.password = password
        self.verbose = verbose


    def whisper_vulnerabilities(self):

        if self.profile == 'nessus':
            vw = vulnWhispererNessus(config=self.config,
                                     username=self.username,
                                     password=self.password,
                                     verbose=self.verbose)
            vw.whisper_nessus()

        elif self.profile == 'qualys':
            vw = vulnWhispererQualys(config=self.config)
            vw.process_web_assets()