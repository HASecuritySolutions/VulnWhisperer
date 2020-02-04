import json
import logging
import sys
import time
from datetime import datetime

import pytz
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


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

    def __init__(self, hostname=None, port=None, username=None, password=None, verbose=True, profile=None, access_key=None, secret_key=None):
        self.logger = logging.getLogger('NessusAPI')
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        if not all((username, password)) and not all((access_key, secret_key)):
            raise Exception('ERROR: Missing username, password or API keys.')

        self.profile = profile
        self.user = username
        self.password = password
        self.api_keys = False
        self.access_key = access_key
        self.secret_key = secret_key
        self.base = 'https://{hostname}:{port}'.format(hostname=hostname, port=port)
        self.verbose = verbose

        self.session = requests.Session()
        self.session.verify = False
        self.session.stream = True
        self.session.headers = {
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

        if all((self.access_key, self.secret_key)):
            self.logger.debug('Using {} API keys'.format(self.profile))
            self.api_keys = True
            self.session.headers['X-ApiKeys'] = 'accessKey={}; secretKey={}'.format(self.access_key, self.secret_key)
        else:
            self.login()

        self.scans = self.get_scans()
        self.scan_ids = self.get_scan_ids()

    def login(self):
        auth = '{"username":"%s", "password":"%s"}' % (self.user, self.password)
        resp = self.request(self.SESSION, data=auth, json_output=False)
        if resp.status_code == 200:
            self.session.headers['X-Cookie'] = 'token={token}'.format(token=resp.json()['token'])
        else:
            raise Exception('[FAIL] Could not login to Nessus')

    def request(self, url, data=None, headers=None, method='POST', download=False, json_output=False):
        timeout = 0
        success = False

        method = method.lower()
        url = self.base + url
        self.logger.debug('Requesting to url {}'.format(url))

        while (timeout <= 10) and (not success):
            response = getattr(self.session, method)(url, data=data)
            if response.status_code == 401:
                if url == self.base + self.SESSION:
                    break
                try:
                    timeout += 1
                    if self.api_keys:
                        continue
                    self.login()
                    self.logger.info('Token refreshed')
                except Exception as e:
                    self.logger.error('Could not refresh token\nReason: {}'.format(str(e)))
            else:
                success = True

        if json_output:
            return response.json()
        if download:
            self.logger.debug('Returning data.content')
            response_data = ''
            count = 0
            for chunk in response.iter_content(chunk_size=8192):
                count += 1
                if chunk:
                    response_data += chunk
            self.logger.debug('Processed {} chunks'.format(count))
            return response_data
        return response

    def get_scans(self):
        scans = self.request(self.SCANS, method='GET', json_output=True)
        return scans

    def get_scan_ids(self):
        scans = self.scans
        scan_ids = [scan_id['id'] for scan_id in scans['scans']] if scans['scans'] else []
        self.logger.debug('Found {} scan_ids'.format(len(scan_ids)))
        return scan_ids

    def get_scan_history(self, scan_id):
        data = self.request(self.SCAN_ID.format(scan_id=scan_id), method='GET', json_output=True)
        return data['history']

    def download_scan(self, scan_id=None, history=None, export_format=""):
        running = True
        counter = 0

        data = {'format': export_format}
        if not history:
            query = self.EXPORT.format(scan_id=scan_id)
        else:
            query = self.EXPORT_HISTORY.format(scan_id=scan_id, history_id=history)
            scan_id = str(scan_id)
        req = self.request(query, data=json.dumps(data), method='POST', json_output=True)
        try:
            file_id = req['file']
            if self.profile == 'nessus':
                token_id = req['token'] if 'token' in req else req['temp_token']
        except Exception as e:
            self.logger.error('{}'.format(str(e)))
        self.logger.info('Download for file id {}'.format(str(file_id)))
        while running:
            time.sleep(2)
            counter += 2
            report_status = self.request(self.EXPORT_STATUS.format(scan_id=scan_id, file_id=file_id), method='GET',
                                         json_output=True)
            running = report_status['status'] != 'ready'
            sys.stdout.write(".")
            sys.stdout.flush()
            # FIXME: why? can this be removed in favour of a counter?
            if counter % 60 == 0:
                self.logger.info("Completed: {}".format(counter))
        self.logger.info("Done: {}".format(counter))
        if self.profile == 'tenable' or self.api_keys:
            content = self.request(self.EXPORT_FILE_DOWNLOAD.format(scan_id=scan_id, file_id=file_id), method='GET', download=True)
        else:
            content = self.request(self.EXPORT_TOKEN_DOWNLOAD.format(token_id=token_id), method='GET', download=True)
        return content

    def get_utc_from_local(self, date_time, local_tz=None, epoch=True):
        date_time = datetime.fromtimestamp(date_time)
        if local_tz is None:
            local_tz = pytz.timezone('UTC')
        else:
            local_tz = pytz.timezone(local_tz)
        local_time = local_tz.normalize(local_tz.localize(date_time))
        local_time = local_time.astimezone(pytz.utc)
        if epoch:
            naive = local_time.replace(tzinfo=None)
            local_time = int((naive - datetime(1970, 1, 1)).total_seconds())
        self.logger.debug('Converted timestamp {} in datetime {}'.format(date_time, local_time))
        return local_time

    def tz_conv(self, tz):
        time_map = {'Eastern Standard Time': 'US/Eastern',
                    'Central Standard Time': 'US/Central',
                    'Pacific Standard Time': 'US/Pacific',
                    'None': 'US/Central'}
        return time_map.get(tz, None)
