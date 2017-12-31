import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import pytz
from datetime import datetime
import json
import sys
import time


class NessusAPI(object):
    SESSION = '/session'
    FOLDERS = '/folders'
    SCANS = '/scans'
    SCAN_ID = SCANS + '/{scan_id}'
    HOST_VULN = SCAN_ID + '/hosts/{host_id}'
    PLUGINS = HOST_VULN + '/plugins/{plugin_id}'
    EXPORT = SCAN_ID + '/export'
    EXPORT_TOKEN_DOWNLOAD = '/scans/exports/{token_id}/download'
    EXPORT_FILE_DOWNLOAD = EXPORT + '/{file_id}/download'
    EXPORT_STATUS = EXPORT + '/{file_id}/status'
    EXPORT_HISTORY = EXPORT + '?history_id={history_id}'

    def __init__(self, hostname=None, port=None, username=None, password=None, verbose=True):
        if username is None or password is None:
            raise Exception('ERROR: Missing username or password.')

        self.user = username
        self.password = password
        self.base = 'https://{hostname}:{port}'.format(hostname=hostname, port=port)
        self.verbose = verbose

        self.headers = {
            'Origin': self.base,
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.8',
            'User-Agent': 'VulnWhisperer for Nessus',
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Referer': self.base,
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'keep-alive',
            'X-Cookie': None
        }

        self.login()
        self.scan_ids = self.get_scan_ids()

    def vprint(self, msg):
        if self.verbose:
            print(msg)

    def login(self):
        resp = self.get_token()
        if resp.status_code is 200:
            self.headers['X-Cookie'] = 'token={token}'.format(token=resp.json()['token'])
        else:
            raise Exception('[FAIL] Could not login to Nessus')

    def request(self, url, data=None, headers=None, method='POST', download=False, json=False):
        if headers is None:
            headers = self.headers
        timeout = 0
        success = False

        url = self.base + url
        methods = {'GET': requests.get,
                   'POST': requests.post,
                   'DELETE': requests.delete}

        while (timeout <= 10) and (not success):
            data = methods[method](url, data=data, headers=self.headers, verify=False)
            if data.status_code == 401:
                try:
                    self.login()
                    timeout += 1
                    self.vprint('[INFO] Token refreshed')
                except Exception as e:
                    self.vprint('[FAIL] Could not refresh token\nReason: %s' % e)
            else:
                success = True

        if json:
            data = data.json()
        if download:
            return data.content
        return data

    def get_token(self):
        auth = '{"username":"%s", "password":"%s"}' % (self.user, self.password)
        token = self.request(self.SESSION, data=auth, json=False)
        return token

    def logout(self):
        self.request(self.SESSION, method='DELETE')

    def get_folders(self):
        folders = self.request(self.FOLDERS, method='GET', json=True)
        return folders

    def get_scans(self):
        scans = self.request(self.SCANS, method='GET', json=True)
        return scans

    def get_scan_ids(self):
        scans = self.get_scans()
        scan_ids = [scan_id['id'] for scan_id in scans['scans']]
        return scan_ids

    def count_scan(self, scans, folder_id):
        count = 0
        for scan in scans:
            if scan['folder_id'] == folder_id: count = count + 1
        return count

    def print_scans(self, data):
        for folder in data['folders']:
            print("\\{0} - ({1})\\".format(folder['name'], self.count_scan(data['scans'], folder['id'])))
            for scan in data['scans']:
                if scan['folder_id'] == folder['id']:
                    print(
                    "\t\"{0}\" - sid:{1} - uuid: {2}".format(scan['name'].encode('utf-8'), scan['id'], scan['uuid']))

    def get_scan_details(self, scan_id):
        data = self.request(self.SCAN_ID.format(scan_id=scan_id), method='GET', json=True)
        return data

    def get_scan_history(self, scan_id):
        data = self.request(self.SCAN_ID.format(scan_id=scan_id), method='GET', json=True)
        return data['history']

    def get_scan_hosts(self, scan_id):
        data = self.request(self.SCAN_ID.format(scan_id=scan_id), method='GET', json=True)
        return data['hosts']

    def get_host_vulnerabilities(self, scan_id, host_id):
        query = self.HOST_VULN.format(scan_id=scan_id, host_id=host_id)
        data = self.request(query, method='GET', json=True)
        return data

    def get_plugin_info(self, scan_id, host_id, plugin_id):
        query = self.PLUGINS.format(scan_id=scan_id, host_id=host_id, plugin_id=plugin_id)
        data = self.request(query, method='GET', json=True)
        return data

    def export_scan(self, scan_id, history_id):
        data = {'format': 'csv'}
        query = self.EXPORT_REPORT.format(scan_id=scan_id, history_id=history_id)
        req = self.request(query, data=data, method='POST')
        return req

    def download_scan(self, scan_id=None, history=None, export_format="", chapters="", dbpasswd=""):
        running = True
        counter = 0

        data = {'format': export_format}
        if not history:
            query = self.EXPORT.format(scan_id=scan_id)
        else:
            query = self.EXPORT_HISTORY.format(scan_id=scan_id, history_id=history)
            scan_id = str(scan_id)
        req = self.request(query, data=json.dumps(data), method='POST', json=True)
        try:
            file_id = req['file']
            token_id = req['token']
        except Exception as e:
            print("[ERROR] %s" % e)
        print('Download for file id ' + str(file_id) + '.')
        while running:
            time.sleep(2)
            counter += 2
            report_status = self.request(self.EXPORT_STATUS.format(scan_id=scan_id, file_id=file_id), method='GET',
                                         json=True)
            running = report_status['status'] != 'ready'
            sys.stdout.write(".")
            sys.stdout.flush()
            if counter % 60 == 0:
                print("")

        print("")
        content = self.request(self.EXPORT_TOKEN_DOWNLOAD.format(token_id=token_id), method='GET', download=True)
        return content

    @staticmethod
    def merge_dicts(self, *dict_args):
        """
        Given any number of dicts, shallow copy and merge into a new dict,
        precedence goes to key value pairs in latter dicts.
        """
        result = {}
        for dictionary in dict_args:
            result.update(dictionary)
        return result

    def get_utc_from_local(self, date_time, local_tz=None, epoch=True):
        date_time = datetime.fromtimestamp(date_time)
        if local_tz is None:
            local_tz = pytz.timezone('US/Central')
        else:
            local_tz = pytz.timezone(local_tz)
        # print date_time
        local_time = local_tz.normalize(local_tz.localize(date_time))
        local_time = local_time.astimezone(pytz.utc)
        if epoch:
            naive = local_time.replace(tzinfo=None)
            local_time = int((naive - datetime(1970, 1, 1)).total_seconds())
        return local_time

    def tz_conv(self, tz):
        time_map = {'Eastern Standard Time': 'US/Eastern',
                    'Central Standard Time': 'US/Central',
                    'Pacific Standard Time': 'US/Pacific',
                    'None': 'US/Central'}
        return time_map.get(tz, None)