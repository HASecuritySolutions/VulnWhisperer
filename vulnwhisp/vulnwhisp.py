
from base.config import vwConfig
from frameworks.nessus import NessusAPI
from utils.cli import bcolors
import pandas as pd
import sys
import os
import io
import time
import sqlite3

# TODO Create logging option which stores data about scan
import logging



class vulnWhisperer(object):

    def __init__(self, config=None, db_name='report_tracker.db', purge=False, verbose=None, debug=False):

        self.verbose = verbose
        self.nessus_connect = False
        self.develop = True
        self.purge = purge

        if config is not None:
            try:
                self.config = vwConfig(config_in=config)
                self.nessus_enabled = self.config.getbool('nessus', 'enabled')

                if self.nessus_enabled:
                    self.nessus_hostname = self.config.get('nessus', 'hostname')
                    self.nessus_port = self.config.get('nessus', 'port')
                    self.nessus_username = self.config.get('nessus', 'username')
                    self.nessus_password = self.config.get('nessus', 'password')
                    self.nessus_writepath = self.config.get('nessus', 'write_path')
                    self.nessus_dbpath = self.config.get('nessus', 'db_path')
                    self.nessus_trash = self.config.getbool('nessus', 'trash')
                    self.verbose = self.config.getbool('nessus', 'verbose')

                    try:
                        self.vprint(
                            '{info} Attempting to connect to nessus...'.format(info=bcolors.INFO))
                        self.nessus = NessusAPI(hostname=self.nessus_hostname,
                                                port=self.nessus_port,
                                                username=self.nessus_username,
                                                password=self.nessus_password)
                        self.nessus_connect = True
                        self.vprint(
                            '{success} Connected to nessus on {host}:{port}'.format(success=bcolors.SUCCESS,
                                                                                                        host=self.nessus_hostname,
                                                                                                        port=str(self.nessus_port)))
                    except Exception as e:
                        self.vprint(e)
                        raise Exception(
                            "{fail} Could not connect to nessus -- Please verify your settings in {config} are correct and try again.\nReason: {e}".format(config=self.config,
                                                                                                                                                           fail=bcolors.FAIL,
                                                                                                                                                           e=e))

            except Exception as e:

                self.vprint('{fail} Could not properly load your config!\nReason: {e}'.format(fail=bcolors.FAIL, e=e))
                sys.exit(0)

        if db_name is not None:
            if self.nessus_dbpath:
                self.database = os.path.join(self.nessus_dbpath, db_name)
            else:
                self.database = os.path.abspath(os.path.join(os.path.dirname( __file__ ), 'database', db_name))

            try:
                self.conn = sqlite3.connect(self.database)
                self.cur = self.conn.cursor()
                self.vprint("{info} Connected to database at {loc}".format(info=bcolors.INFO, loc=self.database))
            except Exception as e:
                self.vprint("{fail} Could not connect to database at {loc}\nReason: {e} - Please ensure the path exist".format(e=e, fail=bcolors.FAIL, loc=self.database))

        else:
            self.vprint('{fail} Please specify a database to connect to!'.format(fail=bcolors.FAIL))
            exit(0)

        self.table_columns = ['scan_name',
                              'scan_id',
                              'last_modified',
                              'filename',
                              'download_time',
                              'record_count',
                              'source',
                              'uuid',
                              'processed']
        self.init()
        self.uuids = self.retrieve_uuids()
        self.processed = 0
        self.skipped = 0
        self.scan_list = []



    def vprint(self, msg):
        if self.verbose:
            print(msg)


    def create_table(self):
        self.cur.execute("create table if not exists scan_history (id integer primary key, scan_name text, scan_id integer, last_modified date, filename text, download_time date, record_count integer, source text, uuid text, processed integer)")
        self.conn.commit()

    def delete_table(self):
        self.cur.execute('drop table if exists scan_history')
        self.conn.commit()

    def init(self):
        if self.purge:
            self.delete_table()
        self.create_table()

    def cleanser(self, _data):
        repls = ('\n', '|||'), ('\r', '|||'), (',',';')
        data = reduce(lambda a, kv: a.replace(*kv), repls, _data)
        return data

    def path_check(self, _data):
        if self.nessus_writepath:
            data = self.nessus_writepath + '/' + _data
        return data

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
                        record['last_modification_date'] = h.get('last_modification_date', '')
                        record['norm_time'] = self.nessus.get_utc_from_local(int(record['last_modification_date']),
                                                                   local_tz=self.nessus.tz_conv(record['timezone']))
                        scan_records.append(record.copy())


                except Exception as e:
                    print(e)
                    pass

        if completed:
            scan_records = [s for s in scan_records if s['status'] == 'completed']
        return scan_records


    def record_insert(self, record):
        self.cur.execute("insert into scan_history({table_columns}) values (?,?,?,?,?,?,?,?,?)".format(
            table_columns=', '.join(self.table_columns)), record)

    def retrieve_uuids(self):
        """
        Retrieves UUIDs from database and checks list to determine which files need to be processed.
        :return:
        """
        self.conn.text_factory = str
        self.cur.execute('select uuid from scan_history')
        results = frozenset([r[0] for r in self.cur.fetchall()])
        return results


    def whisper_nessus(self):
        if self.nessus_connect:
            scan_data = self.nessus.get_scans()
            # print scan_data
            folders = scan_data['folders']
            scans = scan_data['scans']
            all_scans = self.scan_count(scans)
            if self.uuids:
                scan_list = [scan for scan in all_scans if scan['uuid'] not in self.uuids]
            else:
                scan_list = all_scans
            self.vprint("{info} Identified {new} scans to be processed".format(info=bcolors.INFO, new=len(scan_list)))

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
                        scan=self.path_check(f['name']), info=bcolors.INFO))

            # try download and save scans into each folder the belong to
            scan_count = 0
            # TODO Rewrite this part to go through the scans that have aleady been processed
            for s in scan_list:
                scan_count += 1
                #self.vprint('%s/%s' % (scan_count, len(scan_list)))
                scan_name, scan_id, history_id,\
                norm_time, status, uuid = s['scan_name'], s['scan_id'], s['history_id'],\
                                          s['norm_time'], s['status'], s['uuid']

                # TODO Create directory sync function which scans the directory for files that exist already and populates the database

                folder_id = s['folder_id']
                scan_history = self.nessus.get_scan_history(scan_id)
                folder_name = next(f['name'] for f in folders if f['id'] == folder_id)
                if status == 'completed':
                    file_name = '%s_%s_%s_%s.%s' % (scan_name, scan_id, history_id, norm_time, 'csv')
                    repls = ('\\', '_'), ('/', '_'), ('/', '_'), (' ', '_')
                    file_name = reduce(lambda a, kv: a.replace(*kv), repls, file_name)
                    relative_path_name = self.path_check(folder_name + '/' + file_name)

                    if os.path.isfile(relative_path_name):
                        if self.develop:
                            csv_in = pd.read_csv(relative_path_name)
                            record_meta = (
                            scan_name, scan_id, norm_time, file_name, time.time(), csv_in.shape[0], 'nessus', uuid, 1)
                            self.record_insert(record_meta)
                            self.vprint(
                            "{info} File {filename} already exist! Updating database".format(info=bcolors.INFO, filename=relative_path_name))
                            self.conn.commit()
                    else:
                        file_req = self.nessus.download_scan(scan_id=scan_id, history=history_id, export_format='csv')
                        clean_csv = pd.read_csv(io.StringIO(file_req.decode('utf-8')))
                        if len(clean_csv) > 2:
                            self.vprint("Processing %s/%s for scan: %s" % (scan_count, len(scan_history), scan_name))
                            clean_csv['CVSS'] = clean_csv['CVSS'].astype(str).apply(self.cleanser)
                            clean_csv['CVE'] = clean_csv['CVE'].astype(str).apply(self.cleanser)
                            clean_csv['Description'] = clean_csv['Description'].astype(str).apply(self.cleanser)
                            clean_csv['Synopsis'] = clean_csv['Description'].astype(str).apply(self.cleanser)
                            clean_csv['Solution'] = clean_csv['Solution'].astype(str).apply(self.cleanser)
                            clean_csv['See Also'] = clean_csv['See Also'].astype(str).apply(self.cleanser)
                            clean_csv['Plugin Output'] = clean_csv['Plugin Output'].astype(str).apply(self.cleanser)
                            clean_csv.to_csv(relative_path_name, index=False)
                            record_meta = (
                            scan_name, scan_id, norm_time, file_name, time.time(), clean_csv.shape[0], 'nessus', uuid,
                            1)
                            self.record_insert(record_meta)
                            self.vprint("{info} {filename} records written to {path} ".format(info=bcolors.INFO, filename=clean_csv.shape[0], path=file_name))
                            self.conn.commit()
                        else:
                            record_meta = (
                            scan_name, scan_id, norm_time, file_name, time.time(), clean_csv.shape[0], 'nessus', uuid,
                            1)
                            self.record_insert(record_meta)
                            self.vprint(file_name + ' has no host available... Updating database and skipping!')
                            self.conn.commit()
            #self.conn.commit()
            self.conn.close()
            "{success} Scan aggregation complete! Connection to database closed.".format(success=bcolors.SUCCESS)


        else:
            self.vprint('{fail} Failed to use scanner at {host}'.format(fail=bcolors.FAIL, host=self.nessus_hostname+':'+self.nessus_port))