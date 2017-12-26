# File for 3rd party contributions.

from __future__ import absolute_import
from __future__ import print_function
import six
from six.moves import range

__author__ = 'Parag Baxi <parag.baxi@gmail.com>'
__license__ = 'Apache License 2.0'

import logging
import time
import types
import unicodedata
from collections import defaultdict

from lxml import etree, objectify


# Set module level logger.
logger = logging.getLogger(__name__)


def generate_vm_report(self, report_details, startup_delay=60, polling_delay=30, max_checks=10):
    ''' Spool and download QualysGuard VM report.

    startup_delay: Time in seconds to wait before initially checking.
    polling_delay: Time in seconds to wait between checks.
    max_checks: Maximum number of times to check for report spooling completion.

    '''
    # Merge parameters.
    report_details['action'] = 'launch'
    logger.debug(report_details)
    xml_output = qualysapi_instance.request(2, 'report', report_details)
    report_id = etree.XML(xml_output).find('.//VALUE').text
    logger.debug('report_id: %s' % (report_id))
    # Wait for report to finish spooling.
    # Maximum number of times to check for report.  About 10 minutes.
    MAX_CHECKS = 10
    logger.info('Report sent to spooler. Checking for report in %s seconds.' % (startup_delay))
    time.sleep(startup_delay)
    for n in range(0, max_checks):
        # Check to see if report is done.
        xml_output = qualysapi_instance.request(2, 'report', {'action': 'list', 'id': report_id})
        tag_status = etree.XML(xml_output).findtext(".//STATE")
        logger.debug('tag_status: %s' % (tag_status))
        tag_status = etree.XML(xml_output).findtext(".//STATE")
        logger.debug('tag_status: %s' % (tag_status))
        if tag_status is not None:
            # Report is showing up in the Report Center.
            if tag_status == 'Finished':
                # Report creation complete.
                break
        # Report not finished, wait.
        logger.info('Report still spooling. Trying again in %s seconds.' % (polling_delay))
        time.sleep(polling_delay)
    # We now have to fetch the report.  Use the report id.
    report_xml = qualysapi_instance.request(2, 'report', {'action': 'fetch', 'id': report_id})
    return report_xml


def qg_html_to_ascii(qg_html_text):
    """Convert and return QualysGuard's quasi HTML text to ASCII text."""
    text = qg_html_text
    # Handle tagged line breaks (<p>, <br>)
    text = re.sub(r'(?i)<br>[ ]*', '\n', text)
    text = re.sub(r'(?i)<p>[ ]*', '\n', text)
    # Remove consecutive line breaks
    text = re.sub(r"^\s+", "", text, flags=re.MULTILINE)
    # Remove empty lines at the end.
    text = re.sub('[\n]+$', '$', text)
    # Store anchor tags href attribute
    links = list(lxml.html.iterlinks(text))
    # Remove anchor tags
    html_element = lxml.html.fromstring(text)
    # Convert anchor tags to "link_text (link: link_url )".
    logging.debug('Converting anchor tags...')
    text = html_element.text_content().encode('ascii', 'ignore')
    # Convert each link.
    for l in links:
        # Find and replace each link.
        link_text = l[0].text_content().encode('ascii', 'ignore').strip()
        link_url = l[2].strip()
        # Replacing link_text
        if link_text != link_url:
            # Link text is different, most likely a description.
            text = string.replace(text, link_text, '%s (link: %s )' % (link_text, link_url))
        else:
            # Link text is the same as the href.  No need to duplicate link.
            text = string.replace(text, link_text, '%s' % (link_url))
    logging.debug('Done.')
    return text


def qg_parse_informational_qids(xml_report):
    """Return vulnerabilities of severity 1 and 2 levels due to a restriction of
       QualysGuard's inability to report them in the internal ticketing system.
    """
    # asset_group's vulnerability data map:
    #    {'qid_number': {
    #                    # CSV info
    #                    'hosts': [{'ip': '10.28.0.1', 'dns': 'hostname', 'netbios': 'blah', 'vuln_id': 'remediation_ticket_number'}, {'ip': '10.28.0.3', 'dns': 'hostname2', 'netbios': '', 'vuln_id': 'remediation_ticket_number'}, ...],
    #                    'solution': '',
    #                    'impact': '',
    #                    'threat': '',
    #                    'severity': '',
    #                   }
    #     'qid_number2': ...
    #     }
    # Add all vulnerabilities to list of dictionaries.
    # Use defaultdict in case a new QID is encountered.
    info_vulns = defaultdict(dict)
    # Parse vulnerabilities in xml string.
    tree = objectify.fromstring(xml_report)
    # Write IP, DNS, & Result into each QID CSV file.
    logging.debug('Parsing report...')
    # TODO:  Check against c_args.max to prevent creating CSV content for QIDs that we won't use.
    for host in tree.HOST_LIST.HOST:
        # Extract possible extra hostname information.
        try:
            netbios = unicodedata.normalize('NFKD', six.text_type(host.NETBIOS)).encode('ascii', 'ignore').strip()
        except AttributeError:
            netbios = ''
        try:
            dns = unicodedata.normalize('NFKD', six.text_type(host.DNS)).encode('ascii', 'ignore').strip()
        except AttributeError:
            dns = ''
        ip = unicodedata.normalize('NFKD', six.text_type(host.IP)).encode('ascii', 'ignore').strip()
        # Extract vulnerabilities host is affected by.
        for vuln in host.VULN_INFO_LIST.VULN_INFO:
            try:
                result = unicodedata.normalize('NFKD', six.text_type(vuln.RESULT)).encode('ascii', 'ignore').strip()
            except AttributeError:
                result = ''
            qid = unicodedata.normalize('NFKD', six.text_type(vuln.QID)).encode('ascii', 'ignore').strip()
            # Attempt to add host to QID's list of affected hosts.
            try:
                info_vulns[qid]['hosts'].append({'ip': '%s' % (ip),
                                                 'dns': '%s' % (dns),
                                                 'netbios': '%s' % (netbios),
                                                 'vuln_id': '',
                                                 # Informational QIDs do not have vuln_id numbers.  This is a flag to write the CSV file.
                                                 'result': '%s' % (result), })
            except KeyError:
                # New QID.
                logging.debug('New QID found: %s' % (qid))
                info_vulns[qid]['hosts'] = []
                info_vulns[qid]['hosts'].append({'ip': '%s' % (ip),
                                                 'dns': '%s' % (dns),
                                                 'netbios': '%s' % (netbios),
                                                 'vuln_id': '',
                                                 # Informational QIDs do not have vuln_id numbers.  This is a flag to write the CSV file.
                                                 'result': '%s' % (result), })
    # All vulnerabilities added.
    # Add all vulnerabilty information.
    for vuln_details in tree.GLOSSARY.VULN_DETAILS_LIST.VULN_DETAILS:
        qid = unicodedata.normalize('NFKD', six.text_type(vuln_details.QID)).encode('ascii', 'ignore').strip()
        info_vulns[qid]['title'] = unicodedata.normalize('NFKD', six.text_type(vuln_details.TITLE)).encode('ascii',
                                                                                                           'ignore').strip()
        info_vulns[qid]['severity'] = unicodedata.normalize('NFKD', six.text_type(vuln_details.SEVERITY)).encode('ascii',
                                                                                                                 'ignore').strip()
        info_vulns[qid]['solution'] = qg_html_to_ascii(
            unicodedata.normalize('NFKD', six.text_type(vuln_details.SOLUTION)).encode('ascii', 'ignore').strip())
        info_vulns[qid]['threat'] = qg_html_to_ascii(
            unicodedata.normalize('NFKD', six.text_type(vuln_details.THREAT)).encode('ascii', 'ignore').strip())
        info_vulns[qid]['impact'] = qg_html_to_ascii(
            unicodedata.normalize('NFKD', six.text_type(vuln_details.IMPACT)).encode('ascii', 'ignore').strip())
    # Ready to report informational vulnerabilities.
    return info_vulns


# TODO: Implement required function qg_remediation_tickets(asset_group, status, qids)
# TODO: Remove static 'report_template' value.  Parameterize and document required report template.
def qg_ticket_list(asset_group, severity, qids=None):
    """Return dictionary of each vulnerability reported against asset_group of severity."""
    global asset_group_details
    # All vulnerabilities imported to list of dictionaries.
    vulns = qg_remediation_tickets(asset_group, 'OPEN', qids)  # vulns now holds all open remediation tickets.
    if not vulns:
        # No tickets to report.
        return False
    #
    # Sort the vulnerabilities in order of prevalence -- number of hosts affected.
    vulns = OrderedDict(sorted(list(vulns.items()), key=lambda t: len(t[1]['hosts'])))
    logging.debug('vulns sorted = %s' % (vulns))
    #
    # Remove QIDs that have duplicate patches.
    #
    # Read in patch report.
    # TODO:  Allow for lookup of report_template.
    # Report template is Patch report "Sev 5 confirmed patchable".
    logging.debug('Retrieving patch report from QualysGuard.')
    print('Retrieving patch report from QualysGuard.')
    report_template = '1063695'
    # Call QualysGuard for patch report.
    csv_output = qg_command(2, 'report', {'action': 'launch', 'output_format': 'csv',
                                          'asset_group_ids': asset_group_details['qg_asset_group_id'],
                                          'template_id': report_template,
                                          'report_title': 'QGIR Patch %s' % (asset_group)})
    logging.debug('csv_output =')
    logging.debug(csv_output)
    logging.debug('Improving remediation efficiency by removing unneeded, redundant patches.')
    print('Improving remediation efficiency by removing unneeded, redundant patches.')
    # Find the line for Patches by Host data.
    logging.debug('Header found at %s.' % (csv_output.find('Patch QID, IP, DNS, NetBIOS, OS, Vulnerability Count')))

    starting_pos = csv_output.find('Patch QID, IP, DNS, NetBIOS, OS, Vulnerability Count') + 52
    logging.debug('starting_pos = %s' % str(starting_pos))
    # Data resides between line ending in 'Vulnerability Count' and a blank line.
    patches_by_host = csv_output[starting_pos:csv_output[starting_pos:].find(
        'Host Vulnerabilities Fixed by Patch') + starting_pos - 3]
    logging.debug('patches_by_host =')
    logging.debug(patches_by_host)
    # Read in string patches_by_host csv to a dictionary.
    f = patches_by_host.split(os.linesep)
    reader = csv.DictReader(f, ['Patch QID', 'IP', 'DNS', 'NetBIOS', 'OS', 'Vulnerability Count'], delimiter=',')
    # Mark Patch QIDs that fix multiple vulnerabilities with associated IP addresses.
    redundant_qids = defaultdict(list)
    for row in reader:
        if int(row['Vulnerability Count']) > 1:
            # Add to list of redundant QIDs.
            redundant_qids[row['Patch QID']].append(row['IP'])
            logging.debug('%s, %s, %s, %s' % (
                row['Patch QID'],
                row['IP'],
                int(row['Vulnerability Count']),
                redundant_qids[row['Patch QID']]))
    # Log for debugging.
    logging.debug('len(redundant_qids) = %s, redundant_qids =' % (len(redundant_qids)))
    for patch_qid in list(redundant_qids.keys()):
        logging.debug('%s, %s' % (str(patch_qid), str(redundant_qids[patch_qid])))
    # Extract redundant QIDs with associated IP addresses.
    # Find the line for Patches by Host data.
    starting_pos = csv_output.find('Patch QID, IP, QID, Severity, Type, Title, Instance, Last Detected') + 66
    # Data resides between line ending in 'Vulnerability Count' and end of string.
    host_vulnerabilities_fixed_by_patch = csv_output[starting_pos:]
    # Read in string host_vulnerabilities_fixed_by_patch csv to a dictionary.
    f = host_vulnerabilities_fixed_by_patch.split(os.linesep)
    reader = csv.DictReader(f, ['Patch QID', 'IP', 'QID', 'Severity', 'Type', 'Title', 'Instance', 'Last Detected'],
                            delimiter=',')
    # Remove IP addresses associated with redundant QIDs.
    qids_to_remove = defaultdict(list)
    for row in reader:
        # If the row's IP address's Patch QID was found to have multiple vulnerabilities...
        if len(redundant_qids[row['Patch QID']]) > 0 and redundant_qids[row['Patch QID']].count(row['IP']) > 0:
            # Add the QID column to the list of dictionaries {QID: [IP address, IP address, ...], QID2: [IP address], ...}
            qids_to_remove[row['QID']].append(row['IP'])
    # Log for debugging.
    logging.debug('len(qids_to_remove) = %s, qids_to_remove =' % (len(qids_to_remove)))
    for a_qid in list(qids_to_remove.keys()):
        logging.debug('%s, %s' % (str(a_qid), str(qids_to_remove[a_qid])))
    #
    # Diff vulns against qids_to_remove and against open incidents.
    #
    vulns_length = len(vulns)
    # Iterate over list of keys rather than original dictionary as some keys may be deleted changing the size of the dictionary.
    for a_qid in list(vulns.keys()):
        # Debug log original qid's hosts.
        logging.debug('Before diffing vulns[%s] =' % (a_qid))
        logging.debug(vulns[a_qid]['hosts'])
        # Pop each host.
        # The [:] returns a "slice" of x, which happens to contain all its elements, and is thus effectively a copy of x.
        for host in vulns[a_qid]['hosts'][:]:
            # If the QID for the host is a dupe or if a there is an open Reaction incident.
            if qids_to_remove[a_qid].count(host['ip']) > 0 or reaction_open_issue(host['vuln_id']):
                # Remove the host from the QID's list of target hosts.
                logging.debug('Removing remediation ticket %s.' % (host['vuln_id']))
                vulns[a_qid]['hosts'].remove(host)
            else:
                # Do not remove this vuln
                logging.debug('Will report remediation %s.' % (host['vuln_id']))
        # Debug log diff'd qid's hosts.
        logging.debug('After diffing vulns[%s]=' % (a_qid))
        logging.debug(vulns[a_qid]['hosts'])
        # If there are no more hosts left to patch for the qid.
        if len(vulns[a_qid]['hosts']) == 0:
            # Remove the QID.
            logging.debug('Deleting vulns[%s].' % (a_qid))
            del vulns[a_qid]
    # Diff completed
    if not vulns_length == len(vulns):
        print('A count of %s vulnerabilities have been consolidated to %s vulnerabilities, a reduction of %s%%.' % (
            int(vulns_length),
            int(len(vulns)),
            int(round((int(vulns_length) - int(len(vulns))) / float(vulns_length) * 100))))
    # Return vulns to report.
    logging.debug('vulns =')
    logging.debug(vulns)
    return vulns
