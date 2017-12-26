from __future__ import absolute_import
__author__ = 'pbaxi'

from collections import defaultdict

api_methods = defaultdict(set)
api_methods['1'] = set([
    'about.php',
    'action_log_report.php',
    'asset_data_report.php',
    'asset_domain.php',
    'asset_domain_list.php',
    'asset_group_delete.php',
    'asset_group_list.php',
    'asset_ip_list.php',
    'asset_range_info.php',
    'asset_search.php',
    'get_host_info.php',
    'ignore_vuln.php',
    'iscanner_list.php',
    'knowledgebase_download.php',
    'map-2.php',
    'map.php',
    'map_report.php',
    'map_report_list.php',
    'password_change.php',
    'scan.php',
    'scan_cancel.php',
    'scan_options.php',
    'scan_report.php',
    'scan_report_delete.php',
    'scan_report_list.php',
    'scan_running_list.php',
    'scan_target_history.php',
    'scheduled_scans.php',
    'ticket_delete.php',
    'ticket_edit.php',
    'ticket_list.php',
    'ticket_list_deleted.php',
    'time_zone_code.php',
    'user.php',
    'user_list.php',
])
# API v1 POST methods.
api_methods['1 post'] = set([
    'action_log_report.php',
    'asset_group.php',
    'asset_ip.php',
    'ignore_vuln.php',
    'knowledgebase_download.php',
    'map-2.php',
    'map.php',
    'password_change.php',
    'scan.php',
    'scan_report.php',
    'scan_target_history.php',
    'scheduled_scans.php',
    'ticket_delete.php',
    'ticket_edit.php',
    'ticket_list.php',
    'ticket_list_deleted.php',
    'user.php',
    'user_list.php',
])
# API v2 methods (they're all POST).
api_methods['2'] = set([
    'api/2.0/fo/appliance/',
    'api/2.0/fo/asset/excluded_ip/',
    'api/2.0/fo/asset/excluded_ip/history/',
    'api/2.0/fo/asset/host/',
    'api/2.0/fo/asset/host/cyberscope/',
    'api/2.0/fo/asset/host/cyberscope/fdcc/policy/',
    'api/2.0/fo/asset/host/cyberscope/fdcc/scan/',
    'api/2.0/fo/asset/host/vm/detection/',
    'api/2.0/fo/asset/ip/',
    'api/2.0/fo/asset/ip/v4_v6/',
    'api/2.0/fo/asset/vhost/',
    'api/2.0/fo/auth/',
    # 'api/2.0/fo/auth/{type}/', # Added below.
    'api/2.0/fo/compliance/',
    'api/2.0/fo/compliance/control',
    'api/2.0/fo/compliance/fdcc/policy',
    'api/2.0/fo/compliance/policy/',
    'api/2.0/fo/compliance/posture/info/',
    'api/2.0/fo/compliance/scap/arf/',
    'api/2.0/fo/knowledge_base/vuln/',
    'api/2.0/fo/report/',
    'api/2.0/fo/report/scorecard/',
    'api/2.0/fo/scan/',
    'api/2.0/fo/scan/compliance/',
    'api/2.0/fo/session/',
    'api/2.0/fo/setup/restricted_ips/',
])
for auth_type in set([
    'ibm_db2',
    'ms_sql',
    'oracle',
    'oracle_listener',
    'snmp',
    'unix',
    'windows',
]):
    api_methods['2'].add('api/2.0/fo/auth/%s/' % auth_type)
# WAS GET methods when no POST data.
api_methods['was no data get'] = set([
    'count/was/report',
    'count/was/wasscan',
    'count/was/wasscanschedule',
    'count/was/webapp',
    'download/was/report/',
    'download/was/wasscan/',
])
# WAS GET methods.
api_methods['was get'] = set([
    'download/was/report/',
    'download/was/wasscan/',
    'get/was/report/',
    'get/was/wasscan/',
    'get/was/wasscanschedule/',
    'get/was/webapp/',
    'status/was/report/',
    'status/was/wasscan/',
])
# Asset Management GET methods.
api_methods['am get'] = set([
    'count/am/asset',
    'count/am/hostasset',
    'count/am/tag',
    'get/am/asset/',
    'get/am/hostasset/',
    'get/am/tag/',
])
# Asset Management v2 GET methods.
api_methods['am2 get'] = set([
    'get/am/asset/',
    'get/am/hostasset/',
    'get/am/tag/',
    'get/am/hostinstancevuln/',
    'get/am/assetdataconnector/',
    'get/am/awsassetdataconnector/',
    'get/am/awsauthrecord/',
])
# Keep track of methods with ending slashes to autocorrect user when they forgot slash.
api_methods_with_trailing_slash = defaultdict(set)
for method_group in set(['1', '2', 'was', 'am', 'am2']):
    for method in api_methods[method_group]:
        if method[-1] == '/':
            # Add applicable method with api_version preceding it.
            # Example:
            # WAS API has 'get/was/webapp/'.
            # method_group = 'was get'
            # method_group.split()[0] = 'was'
            # Take off slash to match user provided method.
            # api_methods_with_trailing_slash['was'] contains 'get/was/webapp'
            api_methods_with_trailing_slash[method_group.split()[0]].add(method[:-1])
