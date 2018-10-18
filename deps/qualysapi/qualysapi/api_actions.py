from __future__ import absolute_import
from lxml import objectify
import qualysapi.api_objects
from qualysapi.api_objects import *


class QGActions(object):
    def getHost(self, host):
        call = '/api/2.0/fo/asset/host/'
        parameters = {'action': 'list', 'ips': host, 'details': 'All'}
        hostData = objectify.fromstring(self.request(call, parameters)).RESPONSE
        try:
            hostData = hostData.HOST_LIST.HOST
            return Host(hostData.DNS, hostData.ID, hostData.IP, hostData.LAST_VULN_SCAN_DATETIME, hostData.NETBIOS, hostData.OS, hostData.TRACKING_METHOD)
        except AttributeError:
            return Host("", "", host, "never", "", "", "")

    def getHostRange(self, start, end):
        call = '/api/2.0/fo/asset/host/'
        parameters = {'action': 'list', 'ips': start + '-' + end}
        hostData = objectify.fromstring(self.request(call, parameters))
        hostArray = []
        for host in hostData.RESPONSE.HOST_LIST.HOST:
            hostArray.append(Host(host.DNS, host.ID, host.IP, host.LAST_VULN_SCAN_DATETIME, host.NETBIOS, host.OS, host.TRACKING_METHOD))

        return hostArray

    def listAssetGroups(self, groupName=''):
        call = 'asset_group_list.php'
        if groupName == '':
            agData = objectify.fromstring(self.request(call))
        else:
            agData = objectify.fromstring(self.request(call, 'title=' + groupName)).RESPONSE

        groupsArray = []
        scanipsArray = []
        scandnsArray = []
        scannersArray = []
        for group in agData.ASSET_GROUP:
            try:
                for scanip in group.SCANIPS:
                    scanipsArray.append(scanip.IP)
            except AttributeError:
                scanipsArray = []  # No IPs defined to scan.

            try:
                for scanner in group.SCANNER_APPLIANCES.SCANNER_APPLIANCE:
                    scannersArray.append(scanner.SCANNER_APPLIANCE_NAME)
            except AttributeError:
                scannersArray = []  # No scanner appliances defined for this group.

            try:
                for dnsName in group.SCANDNS:
                    scandnsArray.append(dnsName.DNS)
            except AttributeError:
                scandnsArray = []  # No DNS names assigned to group.

            groupsArray.append(AssetGroup(group.BUSINESS_IMPACT, group.ID, group.LAST_UPDATE, scanipsArray, scandnsArray, scannersArray, group.TITLE))

        return groupsArray

    def listReportTemplates(self):
        call = 'report_template_list.php'
        rtData = objectify.fromstring(self.request(call))
        templatesArray = []

        for template in rtData.REPORT_TEMPLATE:
            templatesArray.append(ReportTemplate(template.GLOBAL, template.ID, template.LAST_UPDATE, template.TEMPLATE_TYPE, template.TITLE, template.TYPE, template.USER))

        return templatesArray

    def listReports(self, id=0):
        call = '/api/2.0/fo/report'

        if id == 0:
            parameters = {'action': 'list'}

            repData = objectify.fromstring(self.request(call, parameters)).RESPONSE
            reportsArray = []

            for report in repData.REPORT_LIST.REPORT:
                reportsArray.append(Report(report.EXPIRATION_DATETIME, report.ID, report.LAUNCH_DATETIME, report.OUTPUT_FORMAT, report.SIZE, report.STATUS, report.TYPE, report.USER_LOGIN))

            return reportsArray

        else:
            parameters = {'action': 'list', 'id': id}
            repData = objectify.fromstring(self.request(call, parameters)).RESPONSE.REPORT_LIST.REPORT
            return Report(repData.EXPIRATION_DATETIME, repData.ID, repData.LAUNCH_DATETIME, repData.OUTPUT_FORMAT, repData.SIZE, repData.STATUS, repData.TYPE, repData.USER_LOGIN)

    def notScannedSince(self, days):
        call = '/api/2.0/fo/asset/host/'
        parameters = {'action': 'list', 'details': 'All'}
        hostData = objectify.fromstring(self.request(call, parameters))
        hostArray = []
        today = datetime.date.today()
        for host in hostData.RESPONSE.HOST_LIST.HOST:
            last_scan = str(host.LAST_VULN_SCAN_DATETIME).split('T')[0]
            last_scan = datetime.date(int(last_scan.split('-')[0]), int(last_scan.split('-')[1]), int(last_scan.split('-')[2]))
            if (today - last_scan).days >= days:
                hostArray.append(Host(host.DNS, host.ID, host.IP, host.LAST_VULN_SCAN_DATETIME, host.NETBIOS, host.OS, host.TRACKING_METHOD))

        return hostArray

    def addIP(self, ips, vmpc):
        # 'ips' parameter accepts comma-separated list of IP addresses.
        # 'vmpc' parameter accepts 'vm', 'pc', or 'both'. (Vulnerability Managment, Policy Compliance, or both)
        call = '/api/2.0/fo/asset/ip/'
        enablevm = 1
        enablepc = 0
        if vmpc == 'pc':
            enablevm = 0
            enablepc = 1
        elif vmpc == 'both':
            enablevm = 1
            enablepc = 1

        parameters = {'action': 'add', 'ips': ips, 'enable_vm': enablevm, 'enable_pc': enablepc}
        self.request(call, parameters)

    def listScans(self, launched_after="", state="", target="", type="", user_login=""):
        # 'launched_after' parameter accepts a date in the format: YYYY-MM-DD
        # 'state' parameter accepts "Running", "Paused", "Canceled", "Finished", "Error", "Queued", and "Loading".
        # 'title' parameter accepts a string
        # 'type' parameter accepts "On-Demand", and "Scheduled".
        # 'user_login' parameter accepts a user name (string)
        call = '/api/2.0/fo/scan/'
        parameters = {'action': 'list', 'show_ags': 1, 'show_op': 1, 'show_status': 1}
        if launched_after != "":
            parameters['launched_after_datetime'] = launched_after

        if state != "":
            parameters['state'] = state

        if target != "":
            parameters['target'] = target

        if type != "":
            parameters['type'] = type

        if user_login != "":
            parameters['user_login'] = user_login

        scanlist = objectify.fromstring(self.request(call, parameters))
        scanArray = []
        for scan in scanlist.RESPONSE.SCAN_LIST.SCAN:
            try:
                agList = []
                for ag in scan.ASSET_GROUP_TITLE_LIST.ASSET_GROUP_TITLE:
                    agList.append(ag)
            except AttributeError:
                agList = []

            scanArray.append(Scan(agList, scan.DURATION, scan.LAUNCH_DATETIME, scan.OPTION_PROFILE.TITLE, scan.PROCESSED, scan.REF, scan.STATUS, scan.TARGET, scan.TITLE, scan.TYPE, scan.USER_LOGIN))

        return scanArray

    def launchScan(self, title, option_title, iscanner_name, asset_groups="", ip=""):
        # TODO: Add ability to scan by tag.
        call = '/api/2.0/fo/scan/'
        parameters = {'action': 'launch', 'scan_title': title, 'option_title': option_title, 'iscanner_name': iscanner_name, 'ip': ip, 'asset_groups': asset_groups}
        if ip == "":
            parameters.pop("ip")

        if asset_groups == "":
            parameters.pop("asset_groups")

        scan_ref = objectify.fromstring(self.request(call, parameters)).RESPONSE.ITEM_LIST.ITEM[1].VALUE

        call = '/api/2.0/fo/scan/'
        parameters = {'action': 'list', 'scan_ref': scan_ref, 'show_status': 1, 'show_ags': 1, 'show_op': 1}

        scan = objectify.fromstring(self.request(call, parameters)).RESPONSE.SCAN_LIST.SCAN
        try:
            agList = []
            for ag in scan.ASSET_GROUP_TITLE_LIST.ASSET_GROUP_TITLE:
                agList.append(ag)
        except AttributeError:
            agList = []

        return Scan(agList, scan.DURATION, scan.LAUNCH_DATETIME, scan.OPTION_PROFILE.TITLE, scan.PROCESSED, scan.REF, scan.STATUS, scan.TARGET, scan.TITLE, scan.TYPE, scan.USER_LOGIN)
