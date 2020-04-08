#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Austin Taylor'

from base.config import vwConfig
from frameworks.nessus import NessusAPI
from frameworks.qualys_web import qualysScanReport
from frameworks.qualys_vuln import qualysVulnScan
from frameworks.openvas import OpenVAS_API
from reporting.jira_api import JiraAPI
import pandas as pd
from lxml import objectify
import sys
import os
import io
import time
import sqlite3
import json
import logging
import socket


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
        self.logger = logging.getLogger('vulnWhispererBase')
        if debug:
            self.logger.setLevel(logging.DEBUG)

        if self.CONFIG_SECTION is None:
                raise Exception('Implementing class must define CONFIG_SECTION')

        self.exit_code = 0
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
            try:
                self.username = self.config.get(self.CONFIG_SECTION, 'username')
                self.password = self.config.get(self.CONFIG_SECTION, 'password')
            except:
                self.username = None
                self.password = None
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
                self.logger.info('Creating directory {dir}'.format(dir=self.db_path))

            if not os.path.exists(self.database):
                with open(self.database, 'w'):
                    self.logger.info('Creating file {dir}'.format(dir=self.database))

            try:
                self.conn = sqlite3.connect(self.database)
                self.cur = self.conn.cursor()
                self.logger.info('Connected to database at {loc}'.format(loc=self.database))
            except Exception as e:
                self.logger.error('Could not connect to database at {loc}\nReason: {e} - Please ensure the path exist'.format(
                        e=e,
                        loc=self.database))
        else:

            self.logger.error('Please specify a database to connect to!')
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
            'reported',
        ]

        self.init()
        self.uuids = self.retrieve_uuids()
        self.processed = 0
        self.skipped = 0
        self.scan_list = []

    def create_table(self):
        self.cur.execute(
            'CREATE TABLE IF NOT EXISTS scan_history (id INTEGER PRIMARY KEY,'
            ' scan_name TEXT, scan_id INTEGER, last_modified DATE, filename TEXT,'
            ' download_time DATE, record_count INTEGER, source TEXT,'
            ' uuid TEXT, processed INTEGER, reported INTEGER)'
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
        #for backwards compatibility with older versions without "reported" field

        try:
            #-1 to get the latest column, 1 to get the column name (old version would be "processed", new "reported")
            #TODO delete backward compatibility check after some versions
            last_column_table = self.cur.execute('PRAGMA table_info(scan_history)').fetchall()[-1][1]
            if last_column_table == self.table_columns[-1]:
                self.cur.execute('insert into scan_history({table_columns}) values (?,?,?,?,?,?,?,?,?,?)'.format(
                    table_columns=', '.join(self.table_columns)), record)

            else:
                self.cur.execute('insert into scan_history({table_columns}) values (?,?,?,?,?,?,?,?,?)'.format(
                    table_columns=', '.join(self.table_columns[:-1])), record[:-1])
            self.conn.commit()
        except Exception as e:
            self.logger.error("Failed to insert record in database. Error: {}".format(e))
            sys.exit(1)

    def set_latest_scan_reported(self, filename):
        #the reason to use the filename instead of the source/scan_name is because the filename already belongs to
        #that latest scan, and we maintain integrity making sure that it is the exact scan we checked
        try:
            self.cur.execute('UPDATE scan_history SET reported = 1 WHERE filename="{}";'.format(filename))
            self.conn.commit()
            self.logger.info('Scan {} marked as successfully processed.'.format(filename))
            return True
        except Exception as e:
            self.logger.error('Failed while setting scan with file {} as processed'.format(filename))

        return False

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
            self.logger.info('Directory created at {scan} - Skipping creation'.format(
                scan=self.write_path.encode('utf8')))
        else:
            os.path.exists(self.write_path)
            self.logger.info('Directory already exist for {scan} - Skipping creation'.format(
                scan=self.write_path.encode('utf8')))

    def get_latest_results(self, source, scan_name):
        processed = 0
        results = []
        reported = ""

        try:
            self.conn.text_factory = str
            self.cur.execute('SELECT filename FROM scan_history WHERE source="{}" AND scan_name="{}" ORDER BY last_modified DESC LIMIT 1;'.format(source, scan_name))
            #should always return just one filename
            results = [r[0] for r in self.cur.fetchall()][0]

            #-1 to get the latest column, 1 to get the column name (old version would be "processed", new "reported")
            #TODO delete backward compatibility check after some versions
            last_column_table = self.cur.execute('PRAGMA table_info(scan_history)').fetchall()[-1][1]
            if results and last_column_table == self.table_columns[-1]:
                reported = self.cur.execute('SELECT reported FROM scan_history WHERE filename="{}"'.format(results)).fetchall()
                reported = reported[0][0]
                if reported:
                    self.logger.debug("Last downloaded scan from source {source} scan_name {scan_name} has already been reported".format(source=source, scan_name=scan_name))

        except Exception as e:
            self.logger.error("Error when getting latest results from {}.{} : {}".format(source, scan_name, e))

        return results, reported

    def get_scan_profiles(self):
        # Returns a list of source.scan_name elements from the database

        # we get the list of sources
        try:
            self.conn.text_factory = str
            self.cur.execute('SELECT DISTINCT source FROM scan_history;')
            sources = [r[0] for r in self.cur.fetchall()]
        except:
            sources = []
            self.logger.error("Process failed at executing 'SELECT DISTINCT source FROM scan_history;'")

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

        self.logger = logging.getLogger('vulnWhispererNessus')
        if debug:
            self.logger.setLevel(logging.DEBUG)
        self.port = int(self.config.get(self.CONFIG_SECTION, 'port'))

        self.develop = True
        self.purge = purge
        self.access_key = None
        self.secret_key = None

        if config is not None:
            try:
                self.nessus_port = self.config.get(self.CONFIG_SECTION, 'port')

                self.nessus_trash = self.config.getbool(self.CONFIG_SECTION,
                                                        'trash')

                try:
                    self.access_key = self.config.get(self.CONFIG_SECTION,'access_key')
                    self.secret_key = self.config.get(self.CONFIG_SECTION,'secret_key')
                except:
                    pass

                try:
                    self.logger.info('Attempting to connect to {}...'.format(self.CONFIG_SECTION))
                    self.nessus = \
                        NessusAPI(hostname=self.hostname,
                                  port=self.nessus_port,
                                  username=self.username,
                                  password=self.password,
                                  profile=self.CONFIG_SECTION,
                                  access_key=self.access_key,
                                  secret_key=self.secret_key
                                  )
                    self.nessus_connect = True
                    self.logger.info('Connected to {} on {host}:{port}'.format(self.CONFIG_SECTION, host=self.hostname,
                                                                                   port=str(self.nessus_port)))
                except Exception as e:
                    self.logger.error('Exception: {}'.format(str(e)))
                    raise Exception(
                        'Could not connect to {} -- Please verify your settings in {config} are correct and try again.\nReason: {e}'.format(
                            self.CONFIG_SECTION,
                            config=self.config.config_in,
                            e=e))
            except Exception as e:
                self.logger.error('Could not properly load your config!\nReason: {e}'.format(e=e))
                return False
                #sys.exit(1)



    def scan_count(self, scans, completed=False):
        """

        :param scans: Pulls in available scans
        :param completed: Only return completed scans
        :return:
        """

        self.logger.info('Gathering all scan data... this may take a while...')
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
                    pass

        if completed:
            scan_records = [s for s in scan_records if s['status'] == 'completed']
        return scan_records


    def whisper_nessus(self):
        if self.nessus_connect:
            scan_data = self.nessus.scans
            folders = scan_data['folders']
            scans = scan_data['scans'] if scan_data['scans'] else []
            all_scans = self.scan_count(scans)
            if self.uuids:
                scan_list = [scan for scan in all_scans if scan['uuid']
                             not in self.uuids and scan['status'] in ['completed', 'imported']]
            else:
                scan_list = all_scans
            self.logger.info('Identified {new} scans to be processed'.format(new=len(scan_list)))

            if not scan_list:
                self.logger.warn('No new scans to process. Exiting...')
                return self.exit_code

            # Create scan subfolders

            for f in folders:
                if not os.path.exists(self.path_check(f['name'])):
                    if f['name'] == 'Trash' and self.nessus_trash:
                        os.makedirs(self.path_check(f['name']))
                    elif f['name'] != 'Trash':
                        os.makedirs(self.path_check(f['name']))
                else:
                    os.path.exists(self.path_check(f['name']))
                    self.logger.info('Directory already exist for {scan} - Skipping creation'.format(
                        scan=self.path_check(f['name']).encode('utf8')))

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
                if self.CONFIG_SECTION == 'tenable':
                    folder_name = ''
                else:
                    folder_name = next(f['name'] for f in folders if f['id'] == folder_id)
                if status in ['completed', 'imported']:
                    file_name = '%s_%s_%s_%s.%s' % (scan_name, scan_id,
                                                    history_id, norm_time, 'csv')
                    repls = (('\\', '_'), ('/', '_'), (' ', '_'))
                    file_name = reduce(lambda a, kv: a.replace(*kv), repls, file_name)
                    relative_path_name = self.path_check(folder_name + '/' + file_name).encode('utf8')

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
                                0,
                            )
                            self.record_insert(record_meta)
                            self.logger.info('File {filename} already exist! Updating database'.format(filename=relative_path_name))
                    else:
                        try:
                            file_req = \
                                self.nessus.download_scan(scan_id=scan_id, history=history_id,
                                                        export_format='csv')
                        except Exception as e:
                            self.logger.error('Could not download {} scan {}: {}'.format(self.CONFIG_SECTION, scan_id, str(e)))
                            self.exit_code += 1
                            continue

                        clean_csv = \
                            pd.read_csv(io.StringIO(file_req.decode('utf-8')))
                        if len(clean_csv) > 2:
                            self.logger.info('Processing {}/{} for scan: {}'.format(scan_count, len(scan_list), scan_name.encode('utf8')))
                            columns_to_cleanse = ['CVSS','CVE','Description','Synopsis','Solution','See Also','Plugin Output', 'MAC Address']

                            for col in columns_to_cleanse:
                                if col in clean_csv:
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
                                0,
                            )
                            self.record_insert(record_meta)
                            self.logger.info('{filename} records written to {path} '.format(filename=clean_csv.shape[0],
                                                                                            path=file_name.encode('utf8')))
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
                                0,
                            )
                            self.record_insert(record_meta)
                            self.logger.warn('{} has no host available... Updating database and skipping!'.format(file_name))
            self.conn.close()
            self.logger.info('Scan aggregation complete! Connection to database closed.')
        else:
            self.logger.error('Failed to use scanner at {host}:{port}'.format(host=self.hostname, port=self.nessus_port))
            self.exit_code += 1
        return self.exit_code


class vulnWhispererQualys(vulnWhispererBase):

    CONFIG_SECTION = 'qualys_web'
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
        self.logger = logging.getLogger('vulnWhispererQualys')
        if debug:
            self.logger.setLevel(logging.DEBUG)
        try:
            self.qualys_scan = qualysScanReport(config=config)
        except Exception as e:
            self.logger.error("Unable to establish connection with Qualys scanner. Reason: {}".format(e))
            return False
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

            relative_path_name = self.path_check(report_name).encode('utf8')

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
                    0,
                )
                self.record_insert(record_meta)
                self.logger.info('File {filename} already exist! Updating database'.format(filename=relative_path_name))

            else:
                self.logger.info('Generating report for {}'.format(report_id))
                status = self.qualys_scan.qw.create_report(report_id)
                root = objectify.fromstring(status)
                if root.responseCode == 'SUCCESS':
                    self.logger.info('Successfully generated report! ID: {}'.format(report_id))
                    generated_report_id = root.data.Report.id
                    self.logger.info('New Report ID: {}'.format(generated_report_id))

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
                        0,
                    )
                    self.record_insert(record_meta)

                    if output_format == 'json':
                        with open(relative_path_name, 'w') as f:
                            f.write(vuln_ready.to_json(orient='records', lines=True))
                            f.write('\n')

                    elif output_format == 'csv':
                       vuln_ready.to_csv(relative_path_name, index=False, header=True)  # add when timestamp occured

                    self.logger.info('Report written to {}'.format(report_name))

                    if cleanup:
                        self.logger.info('Removing report {} from Qualys Database'.format(generated_report_id))
                        cleaning_up = self.qualys_scan.qw.delete_report(generated_report_id)
                        os.remove(self.path_check(str(generated_report_id) + '.csv'))
                        self.logger.info('Deleted report from local disk: {}'.format(self.path_check(str(generated_report_id))))
                else:
                    self.logger.error('Could not process report ID: {}'.format(status))

        except Exception as e:
            self.logger.error('Could not process {}: {}'.format(report_id, str(e)))
        return vuln_ready


    def identify_scans_to_process(self):
        if self.uuids:
            self.scans_to_process = self.latest_scans[~self.latest_scans['id'].isin(self.uuids)]
        else:
            self.scans_to_process = self.latest_scans
        self.logger.info('Identified {new} scans to be processed'.format(new=len(self.scans_to_process)))


    def process_web_assets(self):
        counter = 0
        self.identify_scans_to_process()
        if self.scans_to_process.shape[0]:
            for app in self.scans_to_process.iterrows():
                counter += 1
                r = app[1]
                self.logger.info('Processing {}/{}'.format(counter, len(self.scans_to_process)))
                self.whisper_reports(report_id=r['id'],
                                     launched_date=r['launchedDate'],
                                     scan_name=r['name'],
                                     scan_reference=r['reference'])
        else:
            self.logger.info('No new scans to process. Exiting...')
        self.conn.close()
        return self.exit_code


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
        self.logger = logging.getLogger('vulnWhispererOpenVAS')
        if debug:
            self.logger.setLevel(logging.DEBUG)

        self.directory_check()
        self.port = int(self.config.get(self.CONFIG_SECTION, 'port'))
        self.develop = True
        self.purge = purge
        self.scans_to_process = None
        try:
            self.openvas_api = OpenVAS_API(hostname=self.hostname,
                                           port=self.port,
                                           username=self.username,
                                           password=self.password)
        except Exception as e:
            self.logger.error("Unable to establish connection with OpenVAS scanner. Reason: {}".format(e))
            return False

    def whisper_reports(self, output_format='json', launched_date=None, report_id=None, cleanup=True):
        report = None
        if report_id:
            self.logger.info('Processing report ID: {}'.format(report_id))


            scan_name = report_id.replace('-', '')
            report_name = 'openvas_scan_{scan_name}_{last_updated}.{extension}'.format(scan_name=scan_name,
                                                                                       last_updated=launched_date,
                                                                                       extension=output_format)
            relative_path_name = self.path_check(report_name).encode('utf8')
            scan_reference = report_id

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
                    0,
                )
                self.record_insert(record_meta)
                self.logger.info('File {filename} already exist! Updating database'.format(filename=relative_path_name))

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
                self.logger.info('Report written to {}'.format(report_name))

        return report

    def identify_scans_to_process(self):
        if self.uuids:
            self.scans_to_process = self.openvas_api.openvas_reports[
                ~self.openvas_api.openvas_reports.report_ids.isin(self.uuids)]
        else:
            self.scans_to_process = self.openvas_api.openvas_reports
        self.logger.info('Identified {new} scans to be processed'.format(new=len(self.scans_to_process)))

    def process_openvas_scans(self):
        counter = 0
        self.identify_scans_to_process()
        if self.scans_to_process.shape[0]:
            for scan in self.scans_to_process.iterrows():
                counter += 1
                info = scan[1]
                self.logger.info('Processing {}/{} - Report ID: {}'.format(counter, len(self.scans_to_process), info['report_ids']))
                self.whisper_reports(report_id=info['report_ids'],
                                     launched_date=info['epoch'])
            self.logger.info('Processing complete')
        else:
            self.logger.info('No new scans to process. Exiting...')
        self.conn.close()
        return self.exit_code


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
        self.logger = logging.getLogger('vulnWhispererQualysVuln')
        if debug:
            self.logger.setLevel(logging.DEBUG)
        try:
            self.qualys_scan = qualysVulnScan(config=config)
        except Exception as e:
            self.logger.error("Unable to create connection with Qualys. Reason: {}".format(e))
            return False
        self.directory_check()
        self.scans_to_process = None

    def whisper_reports(self,
                        report_id=None,
                        launched_date=None,
                        scan_name=None,
                        scan_reference=None,
                        output_format='json',
                        cleanup=True):

            if 'Z' in launched_date:
                launched_date = self.qualys_scan.utils.iso_to_epoch(launched_date)
            report_name = 'qualys_vuln_' + report_id.replace('/','_') \
                          + '_{last_updated}'.format(last_updated=launched_date) \
                          + '.json'

            relative_path_name = self.path_check(report_name).encode('utf8')

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
                    0,
                )
                self.record_insert(record_meta)
                self.logger.info('File {filename} already exist! Updating database'.format(filename=relative_path_name))

            else:
                try:
                    self.logger.info('Processing report ID: {}'.format(report_id))
                    vuln_ready = self.qualys_scan.process_data(scan_id=report_id)
                    vuln_ready['scan_name'] = scan_name
                    vuln_ready['scan_reference'] = report_id
                    vuln_ready.rename(columns=self.COLUMN_MAPPING, inplace=True)
                except Exception as e:
                    self.logger.error('Could not process {}: {}'.format(report_id, str(e)))
                    self.exit_code += 1
                    return self.exit_code

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
                    0,
                )
                self.record_insert(record_meta)

                if output_format == 'json':
                    with open(relative_path_name, 'w') as f:
                        f.write(vuln_ready.to_json(orient='records', lines=True))
                        f.write('\n')

                self.logger.info('Report written to {}'.format(report_name))
            return self.exit_code


    def identify_scans_to_process(self):
        self.latest_scans = self.qualys_scan.qw.get_all_scans()
        if self.uuids:
            self.scans_to_process = self.latest_scans.loc[
                (~self.latest_scans['id'].isin(self.uuids))
                & (self.latest_scans['status'] == 'Finished')]
        else:
            self.scans_to_process = self.latest_scans
        self.logger.info('Identified {new} scans to be processed'.format(new=len(self.scans_to_process)))


    def process_vuln_scans(self):
        counter = 0
        self.identify_scans_to_process()
        if self.scans_to_process.shape[0]:
            for app in self.scans_to_process.iterrows():
                counter += 1
                r = app[1]
                self.logger.info('Processing {}/{}'.format(counter, len(self.scans_to_process)))
                self.exit_code += self.whisper_reports(report_id=r['id'],
                                     launched_date=r['date'],
                                     scan_name=r['name'],
                                     scan_reference=r['type'])
        else:
            self.logger.info('No new scans to process. Exiting...')
        self.conn.close()
        return self.exit_code


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
        self.logger = logging.getLogger('vulnWhispererJira')
        if debug:
            self.logger.setLevel(logging.DEBUG)
        self.config_path = config
        self.config = vwConfig(config)
        self.host_resolv_cache = {}
        self.host_no_resolv = []
        self.no_resolv_by_team_dict = {}
        #Save locally those assets without DNS entry for flag to system owners
        self.no_resolv_fname="no_resolv.txt"
        if os.path.isfile(self.no_resolv_fname):
            with open(self.no_resolv_fname, "r") as json_file:
                self.no_resolv_by_team_dict = json.load(json_file)
        self.directory_check()

        if config is not None:
            try:
                self.logger.info('Attempting to connect to jira...')
                self.jira = \
                    JiraAPI(hostname=self.hostname,
                              username=self.username,
                              password=self.password,
                              path=self.config.get('jira','write_path'))
                self.jira_connect = True
                self.logger.info('Connected to jira on {host}'.format(host=self.hostname))
            except Exception as e:
                self.logger.error('Exception: {}'.format(str(e)))
                raise Exception(
                    'Could not connect to nessus -- Please verify your settings in {config} are correct and try again.\nReason: {e}'.format(
                        config=self.config.config_in, e=e))
                return False
                #sys.exit(1)

        profiles = []
        profiles = self.get_scan_profiles()

        if not self.config.exists_jira_profiles(profiles):
            self.config.update_jira_profiles(profiles)
            self.logger.info("Jira profiles have been created in {config}, please fill the variables before rerunning the module.".format(config=self.config_path))
            sys.exit(0)


    def get_env_variables(self, source, scan_name):
        # function returns an array with [jira_project, jira_components, datafile_path]

        #Jira variables
        jira_section = self.config.normalize_section("{}.{}".format(source,scan_name))

        project = self.config.get(jira_section,'jira_project')
        if project == "":
            self.logger.error('JIRA project is missing on the configuration file!')
            sys.exit(0)

        # check that project actually exists
        if not self.jira.project_exists(project):
            self.logger.error("JIRA project '{project}' doesn't exist!".format(project=project))
            sys.exit(0)

        components = self.config.get(jira_section,'components').split(',')

        #cleaning empty array from ''
        if not components[0]:
            components = []

        min_critical = self.config.get(jira_section,'min_critical_to_report')
        if not min_critical:
            self.logger.error('"min_critical_to_report" variable on config file is empty.')
            sys.exit(0)

        #datafile path
        filename, reported = self.get_latest_results(source, scan_name)
        fullpath = ""

        # search data files under user specified directory
        for root, dirnames, filenames in os.walk(vwConfig(self.config_path).get(source,'write_path')):
            if filename in filenames:
                fullpath = "{}/{}".format(root,filename)

        if reported:
            self.logger.warn('Last Scan of "{scan_name}" for source "{source}" has already been reported; will be skipped.'.format(scan_name=scan_name, source=source))
            return [False] * 5

        if not fullpath:
            self.logger.error('Scan of "{scan_name}" for source "{source}" has not been found. Please check that the scanner data files are in place.'.format(scan_name=scan_name, source=source))
            sys.exit(1)

        dns_resolv = self.config.get('jira','dns_resolv')
        if dns_resolv in ('False', 'false', ''):
            dns_resolv = False
        elif dns_resolv in ('True', 'true'):
            dns_resolv = True
        else:
            self.logger.error("dns_resolv variable not setup in [jira] section; will not do dns resolution")
            dns_resolv = False

        return project, components, fullpath, min_critical, dns_resolv


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

    def parse_qualys_vuln_vulnerabilities(self, fullpath, source, scan_name, min_critical, dns_resolv = False):
        #parsing of the qualys vulnerabilities schema
        #parse json
        vulnerabilities = []

        risks = ['info', 'low', 'medium', 'high', 'critical']
        # +1 as array is 0-4, but score is 1-5
        min_risk = int([i for i,x in enumerate(risks) if x == min_critical][0])+1

        try:
            data=[json.loads(line) for line in open(fullpath).readlines()]
        except Exception as e:
            self.logger.warn("Scan has no vulnerabilities, skipping.")
            return vulnerabilities

        #qualys fields we want - []
        for index in range(len(data)):
            if int(data[index]['risk']) < min_risk:
                continue

            elif data[index]['type'] == 'Practice' or data[index]['type'] == 'Ig':
                self.logger.debug("Vulnerability '{vuln}' ignored, as it is 'Practice/Potential', not verified.".format(vuln=data[index]['plugin_name']))
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

                vuln['ips'].append("{ip} - {protocol}/{port} - {dns}".format(**self.get_asset_fields(data[index], dns_resolv)))

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
                        vuln['ips'].append("{ip} - {protocol}/{port} - {dns}".format(**self.get_asset_fields(data[index], dns_resolv)))

        return vulnerabilities

    def get_asset_fields(self, vuln, dns_resolv):
        values = {}
        values['ip'] = vuln['ip']
        values['protocol'] = vuln['protocol']
        values['port'] = vuln['port']
        values['dns'] = ''
        if dns_resolv:
            if vuln['dns']:
                values['dns'] = vuln['dns']
            else:
                if values['ip'] in self.host_resolv_cache.keys():
                    self.logger.debug("Hostname from {ip} cached, retrieving from cache.".format(ip=values['ip']))
                    values['dns'] = self.host_resolv_cache[values['ip']]
                else:
                    self.logger.debug("No hostname, trying to resolve {ip}'s  hostname.".format(ip=values['ip']))
                    try:
                        values['dns'] = socket.gethostbyaddr(vuln['ip'])[0]
                        self.host_resolv_cache[values['ip']] = values['dns']
                        self.logger.debug("Hostname found: {hostname}.".format(hostname=values['dns']))
                    except:
                        self.host_resolv_cache[values['ip']] = ''
                        self.host_no_resolv.append(values['ip'])
                        self.logger.debug("Hostname not found for: {ip}.".format(ip=values['ip']))

        for key in values.keys():
            if not values[key]:
                values[key] = 'N/A'

        return values

    def parse_vulnerabilities(self, fullpath, source, scan_name, min_critical):
        #TODO: SINGLE LOCAL SAVE FORMAT FOR ALL SCANNERS
        #JIRA standard vuln format - ['source', 'scan_name', 'title', 'diagnosis', 'consequence', 'solution', 'ips', 'references']

        return 0


    def jira_sync(self, source, scan_name):
        self.logger.info("Jira Sync triggered for source '{source}' and scan '{scan_name}'".format(source=source, scan_name=scan_name))

        project, components, fullpath, min_critical, dns_resolv = self.get_env_variables(source, scan_name)

        if not project:
            self.logger.debug("Skipping scan for source '{source}' and scan '{scan_name}': vulnerabilities have already been reported.".format(source=source, scan_name=scan_name))
            return False

        vulnerabilities = []

        #***Nessus parsing***
        if source == "nessus":
            vulnerabilities = self.parse_nessus_vulnerabilities(fullpath, source, scan_name, min_critical)

        #***Qualys VM parsing***
        if source == "qualys_vuln":
            vulnerabilities = self.parse_qualys_vuln_vulnerabilities(fullpath, source, scan_name, min_critical, dns_resolv)

        #***JIRA sync***
        try:
            if vulnerabilities:
                self.logger.info('{source} data has been successfuly parsed'.format(source=source.upper()))
                self.logger.info('Starting JIRA sync')

                self.jira.sync(vulnerabilities, project, components)
            else:
                self.logger.info("[{source}.{scan_name}] No vulnerabilities or vulnerabilities not parsed.".format(source=source, scan_name=scan_name))
                self.set_latest_scan_reported(fullpath.split("/")[-1])
                return False
        except Exception as e:
            self.logger.error("Error: {}".format(e))
            return False


        #writing to file those assets without DNS resolution
        #if its not empty
        if self.host_no_resolv:
            #we will replace old list of non resolved for the new one or create if it doesn't exist already
            self.no_resolv_by_team_dict[scan_name] = self.host_no_resolv
            with open(self.no_resolv_fname, 'w') as outfile:  
                    json.dump(self.no_resolv_by_team_dict, outfile)
        
        self.set_latest_scan_reported(fullpath.split("/")[-1])
        return True

    def sync_all(self):
        autoreport_sections = self.config.get_sections_with_attribute('autoreport')

        if autoreport_sections:
            for scan in autoreport_sections:
                try:
                    self.jira_sync(self.config.get(scan, 'source'), self.config.get(scan, 'scan_name'))
                except Exception as e:
                    self.logger.error(
                        "VulnWhisperer wasn't able to report the vulnerabilities from the '{}'s source, section {}.\
                         \nError: {}".format(
                            self.config.get(scan, 'source'), self.config.get(scan, 'scan_name'), e))
            return True
        return False

class vulnWhisperer(object):

    def __init__(self,
                 profile=None,
                 verbose=None,
                 username=None,
                 password=None,
                 config=None,
                 source=None,
                 scanname=None):

        self.logger = logging.getLogger('vulnWhisperer')
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        self.profile = profile
        self.config = config
        self.username = username
        self.password = password
        self.verbose = verbose
        self.source = source
        self.scanname = scanname
        self.exit_code = 0


    def whisper_vulnerabilities(self):

        if self.profile == 'nessus':
            vw = vulnWhispererNessus(config=self.config,
                                     profile=self.profile)
            if vw:
                self.exit_code += vw.whisper_nessus()

        elif self.profile == 'qualys_web':
            vw = vulnWhispererQualys(config=self.config)
            if vw:
                self.exit_code += vw.process_web_assets()

        elif self.profile == 'openvas':
            vw = vulnWhispererOpenVAS(config=self.config)
            if vw:
                self.exit_code += vw.process_openvas_scans()

        elif self.profile == 'tenable':
            vw = vulnWhispererNessus(config=self.config,
                                     profile=self.profile)
            if vw:
                self.exit_code += vw.whisper_nessus()

        elif self.profile == 'qualys_vuln':
            vw = vulnWhispererQualysVuln(config=self.config)
            if vw:
                self.exit_code += vw.process_vuln_scans()

        elif self.profile == 'jira':
            #first we check config fields are created, otherwise we create them
            vw = vulnWhispererJIRA(config=self.config)
            if vw:
                if not (self.source and self.scanname):
                    self.logger.info('No source/scan_name selected, all enabled scans will be synced')
                    success = vw.sync_all()
                    if not success:
                        self.logger.error('All scans sync failed!')
                        self.logger.error('Source scanner and scan name needed!')
                        return 0
                else:
                    vw.jira_sync(self.source, self.scanname)

        return self.exit_code
