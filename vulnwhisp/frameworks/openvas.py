#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Austin Taylor'

import datetime as dt
import io
import logging

import pandas as pd
import requests
from bs4 import BeautifulSoup


class OpenVAS_API(object):
    OMP = '/omp'

    def __init__(self,
                 hostname=None,
                 port=None,
                 username=None,
                 password=None,
                 report_format_id=None,
                 verbose=True):
        self.logger = logging.getLogger('OpenVAS_API')
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        if username is None or password is None:
            raise Exception('ERROR: Missing username or password.')

        self.username = username
        self.password = password
        self.base = 'https://{hostname}:{port}'.format(hostname=hostname, port=port)
        self.verbose = verbose
        self.processed_reports = 0
        self.report_format_id = report_format_id

        self.headers = {
            'Origin': self.base,
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.8',
            'User-Agent': 'VulnWhisperer for OpenVAS',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Cache-Control': 'max-age=0',
            'Referer': self.base,
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'keep-alive',
        }

        self.login()

        self.openvas_reports = self.get_reports()
        self.report_formats = self.get_report_formats()

    def login(self):
        resp = self.get_token()
        if resp.status_code is 200:
            xml_response = BeautifulSoup(resp.content, 'lxml')
            self.token = xml_response.find(attrs={'id': 'gsa-token'}).text

            self.cookies = resp.cookies.get_dict()
        else:
            raise Exception('[FAIL] Could not login to OpenVAS')

    def request(self, url, data=None, params=None, headers=None, cookies=None, method='POST', download=False,
                json=False):
        if headers is None:
            headers = self.headers
        if cookies is None:
            cookies = self.cookies

        timeout = 0
        success = False

        url = self.base + url
        methods = {'GET': requests.get,
                   'POST': requests.post,
                   'DELETE': requests.delete}

        while (timeout <= 10) and (not success):
            data = methods[method](url,
                                   data=data,
                                   headers=self.headers,
                                   params=params,
                                   cookies=cookies,
                                   verify=False)

            if data.status_code == 401:
                try:
                    self.login()
                    timeout += 1
                    self.logger.info(' Token refreshed')
                except Exception as e:
                    self.logger.error('Could not refresh token\nReason: {}'.format(str(e)))
            else:
                success = True

        if json:
            data = data.json()
        if download:
            return data.content
        return data

    def get_token(self):
        data = [
            ('cmd', 'login'),
            ('text', '/omp?r=1'),
            ('login', self.username),
            ('password', self.password),
        ]
        token = requests.post(self.base + self.OMP, data=data, verify=False)
        return token
    def get_report_formats(self):
        params = (
            ('cmd', 'get_report_formats'),
            ('token', self.token)
        )
        self.logger.info('Retrieving available report formats')
        data = self.request(url=self.OMP, method='GET', params=params)

        bs = BeautifulSoup(data.content, "lxml")
        table_body = bs.find('tbody')
        rows = table_body.find_all('tr')
        format_mapping = {}
        for row in rows:
            cols = row.find_all('td')
            for x in cols:
                for y in x.find_all('a'):
                    if y.get_text() != '':
                        format_mapping[y.get_text()] = \
                        [h.split('=')[1] for h in y['href'].split('&') if 'report_format_id' in h][0]
        return format_mapping

    def get_reports(self, complete=True):
        self.logger.info('Retreiving OpenVAS report data...')
        params = (('cmd', 'get_reports'),
                  ('token', self.token),
                  ('max_results', 1),
                  ('ignore_pagination', 1),
                  ('filter', 'apply_overrides=1 min_qod=70 autofp=0 first=1 rows=0 levels=hml sort-reverse=severity'),
                 )
        reports = self.request(self.OMP, params=params, method='GET')
        soup = BeautifulSoup(reports.text, 'lxml')
        data = []
        links = []
        table = soup.find('table', attrs={'class': 'gbntable'})
        table_body = table.find('tbody')

        rows = table_body.find_all('tr')
        for row in rows:
            cols = row.find_all('td')
            links.extend([a['href'] for a in row.find_all('a', href=True) if 'get_report' in str(a)])
            cols = [ele.text.strip() for ele in cols]
            data.append([ele for ele in cols if ele])
            report = pd.DataFrame(data, columns=['date', 'status', 'task', 'scan_severity', 'high', 'medium', 'low', 'log',
                                                 'false_pos'])

        if report.shape[0] != 0:
            report['links'] = links
            report['report_ids'] = report.links.str.extract('.*report_id=([a-z-0-9]*)', expand=False)
            report['epoch'] = (pd.to_datetime(report['date']) - dt.datetime(1970, 1, 1)).dt.total_seconds().astype(int)
        else:
            raise Exception("Could not retrieve OpenVAS Reports - Please check your settings and try again")

        report['links'] = links
        report['report_ids'] = report.links.str.extract('.*report_id=([a-z-0-9]*)', expand=False)
        report['epoch'] = (pd.to_datetime(report['date']) - dt.datetime(1970, 1, 1)).dt.total_seconds().astype(int)
        if complete:
            report = report[report.status == 'Done']
        severity_extraction = report.scan_severity.str.extract('([0-9.]*) \(([\w]+)\)', expand=False)
        severity_extraction.columns = ['scan_highest_severity', 'severity_rate']
        report_with_severity = pd.concat([report, severity_extraction], axis=1)
        return report_with_severity

    def process_report(self, report_id):

        params = (
            ('token', self.token),
            ('cmd', 'get_report'),
            ('report_id', report_id),
            ('filter', 'apply_overrides=0 min_qod=70 autofp=0 levels=hml first=1 rows=0 sort-reverse=severity'),
            ('ignore_pagination', '1'),
            ('report_format_id', '{report_format_id}'.format(report_format_id=self.report_formats['CSV Results'])),
            ('submit', 'Download'),
        )
        self.logger.info('Retrieving {}'.format(report_id))
        req = self.request(self.OMP, params=params, method='GET')
        report_df = pd.read_csv(io.BytesIO(req.text.encode('utf-8')))
        report_df['report_ids'] = report_id
        self.processed_reports += 1
        merged_df = pd.merge(report_df, self.openvas_reports, on='report_ids').reset_index().drop('index', axis=1)
        return merged_df
