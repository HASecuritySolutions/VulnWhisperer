import json
import os
from datetime import datetime, date, timedelta

from jira import JIRA
import requests
import logging
from bottle import template
import re

class JiraAPI(object):
    def __init__(self, hostname=None, username=None, password=None, path="", debug=False, clean_obsolete=True, max_time_window=12, decommission_time_window=3):
        self.logger = logging.getLogger('JiraAPI')
        if debug:
            self.logger.setLevel(logging.DEBUG)

        if "https://" not in hostname:
            hostname = "https://{}".format(hostname)
        self.username = username
        self.password = password
        self.jira = JIRA(options={'server': hostname}, basic_auth=(self.username, self.password))
        self.logger.info("Created vjira service for {}".format(hostname))
        self.all_tickets = []
        self.excluded_tickets = []
        self.JIRA_REOPEN_ISSUE = "Reopen Issue"
        self.JIRA_CLOSE_ISSUE = "Close Issue"
        self.JIRA_RESOLUTION_OBSOLETE = "Obsolete"
        self.JIRA_RESOLUTION_FIXED = "Fixed"
        self.template_path = 'vulnwhisp/reporting/resources/ticket.tpl'
        self.max_ips_ticket = 30
        self.attachment_filename = "vulnerable_assets.txt"
        self.max_time_tracking = max_time_window #in months
        if path:
            self.download_tickets(path)
        else:
            self.logger.warn("No local path specified, skipping Jira ticket download.")
        self.max_decommission_time = decommission_time_window #in months
        # [HIGIENE] close tickets older than 12 months as obsolete (max_time_window defined)
        if clean_obsolete:
            self.close_obsolete_tickets()
        # deletes the tag "server_decommission" from those tickets closed <=3 months ago
        self.decommission_cleanup()
        
        self.jira_still_vulnerable_comment = '''This ticket has been reopened due to the vulnerability not having been fixed (if multiple assets are affected, all need to be fixed; if the server is down, lastest known vulnerability might be the one reported).
        - In the case of the team accepting the risk and wanting to close the ticket, please add the label "*risk_accepted*" to the ticket before closing it.
        - If server has been decommissioned, please add the label "*server_decommission*" to the ticket before closing it.
        - If when checking the vulnerability it looks like a false positive, _+please elaborate in a comment+_ and add the label "*false_positive*" before closing it; we will review it and report it to the vendor.
        
        If you have further doubts, please contact the Security Team.'''

    def create_ticket(self, title, desc, project="IS", components=[], tags=[], attachment_contents = []):
        labels = ['vulnerability_management']
        for tag in tags:
            labels.append(str(tag))

        self.logger.info("Creating ticket for project {} title: {}".format(project, title[:20]))
        self.logger.debug("project {} has a component requirement: {}".format(project, components))
        project_obj = self.jira.project(project)
        components_ticket = []
        for component in components:
            exists = False
            for c in project_obj.components:
                if component == c.name:
                    self.logger.debug("resolved component name {} to id {}".format(c.name, c.id))
                    components_ticket.append({ "id": c.id })
                    exists=True
            if not exists:
                self.logger.error("Error creating Ticket: component {} not found".format(component))
                return 0
        
        try:
            new_issue = self.jira.create_issue(project=project,
                                               summary=title,
                                               description=desc,
                                               issuetype={'name': 'Bug'},
                                               labels=labels,
                                               components=components_ticket)
            
            self.logger.info("Ticket {} created successfully".format(new_issue))
            
            if attachment_contents:
                self.add_content_as_attachment(new_issue, attachment_contents)
        
        except Exception as e:
            self.logger.error("Failed to create ticket on Jira Project '{}'. Error: {}".format(project, e))
            new_issue = False
        
        return new_issue
    
    #Basic JIRA Metrics
    def metrics_open_tickets(self, project=None):
        jql = "labels= vulnerability_management and resolution = Unresolved" 
        if project:
            jql += " and (project='{}')".format(project)
        self.logger.debug('Executing: {}'.format(jql)) 
        return len(self.jira.search_issues(jql, maxResults=0))

    def metrics_closed_tickets(self, project=None):
        jql = "labels= vulnerability_management and NOT resolution = Unresolved AND created >=startOfMonth(-{})".format(self.max_time_tracking) 
        if project:
            jql += " and (project='{}')".format(project)
        return len(self.jira.search_issues(jql, maxResults=0))

    def sync(self, vulnerabilities, project, components=[]):
        #JIRA structure of each vulnerability: [source, scan_name, title, diagnosis, consequence, solution, ips, risk, references]
        self.logger.info("JIRA Sync started")

        for vuln in vulnerabilities:
            # JIRA doesn't allow labels with spaces, so making sure that the scan_name doesn't have spaces
            # if it has, they will be replaced by "_"
            if " " in  vuln['scan_name']:
                vuln['scan_name'] = "_".join(vuln['scan_name'].split(" "))
            
            # we exclude from the vulnerabilities to report those assets that already exist with *risk_accepted*/*server_decommission*
            vuln = self.exclude_accepted_assets(vuln)
            
            # make sure after exclusion of risk_accepted assets there are still assets
            if vuln['ips']:
                exists = False
                to_update = False
                ticketid = ""
                ticket_assets = []
                exists, to_update, ticketid, ticket_assets = self.check_vuln_already_exists(vuln)

                if exists:
                    # If ticket "resolved" -> reopen, as vulnerability is still existent
                    self.reopen_ticket(ticketid=ticketid, comment=self.jira_still_vulnerable_comment)
                    self.add_label(ticketid, vuln['risk'])
                    continue
                elif to_update:
                    self.ticket_update_assets(vuln, ticketid, ticket_assets)
                    self.add_label(ticketid, vuln['risk'])
                    continue
                attachment_contents = []
                # if assets >30, add as attachment
                # create local text file with assets, attach it to ticket
                if len(vuln['ips']) > self.max_ips_ticket:
                    attachment_contents = vuln['ips']
                    vuln['ips'] = ["Affected hosts ({assets}) exceed Jira's allowed character limit, added as an attachment.".format(assets = len(attachment_contents))]
                try:
                    tpl = template(self.template_path, vuln)
                except Exception as e:
                    self.logger.error('Exception templating: {}'.format(str(e)))
                    return 0
                self.create_ticket(title=vuln['title'], desc=tpl, project=project, components=components, tags=[vuln['source'], vuln['scan_name'], 'vulnerability', vuln['risk']], attachment_contents = attachment_contents)
            else:
                self.logger.info("Ignoring vulnerability as all assets are already reported in a risk_accepted ticket")
        
        self.close_fixed_tickets(vulnerabilities)
        # we reinitialize so the next sync redoes the query with their specific variables
        self.all_tickets = []
        self.excluded_tickets = []
        return True
    
    def exclude_accepted_assets(self, vuln):
        # we want to check JIRA tickets with risk_accepted/server_decommission or false_positive labels sharing the same source
        # will exclude tickets older than 12 months, old tickets will get closed for higiene and recreated if still vulnerable
        labels = [vuln['source'], vuln['scan_name'], 'vulnerability_management', 'vulnerability'] 
        
        if not self.excluded_tickets:
            jql = "{} AND labels in (risk_accepted,server_decommission, false_positive) AND NOT labels=advisory AND created >=startOfMonth(-{})".format(" AND ".join(["labels={}".format(label) for label in labels]), self.max_time_tracking)
            self.excluded_tickets = self.jira.search_issues(jql, maxResults=0)

        title = vuln['title']
        #WARNING: function IGNORES DUPLICATES, after finding a "duplicate" will just return it exists
        #it wont iterate over the rest of tickets looking for other possible duplicates/similar issues
        self.logger.info("Comparing vulnerability to risk_accepted tickets")
        assets_to_exclude = []
        tickets_excluded_assets = []
        for index in range(len(self.excluded_tickets)):
            checking_ticketid, checking_title, checking_assets = self.ticket_get_unique_fields(self.excluded_tickets[index])
            if title.encode('ascii') == checking_title.encode('ascii'):
                if checking_assets:
                    #checking_assets is a list, we add to our full list for later delete all assets
                    assets_to_exclude+=checking_assets
                    tickets_excluded_assets.append(checking_ticketid)
       
        if assets_to_exclude:
            assets_to_remove = []
            self.logger.warn("Vulnerable Assets seen on an already existing risk_accepted Jira ticket: {}".format(', '.join(tickets_excluded_assets)))
            self.logger.debug("Original assets: {}".format(vuln['ips']))
            #assets in vulnerability have the structure "ip - hostname - port", so we need to match by partial 
            for exclusion in assets_to_exclude:
                # for efficiency, we walk the backwards the array of ips from the scanners, as we will be popping out the matches 
                # and we don't want it to affect the rest of the processing (otherwise, it would miss the asset right after the removed one)
                for index in range(len(vuln['ips']))[::-1]:
                    if exclusion == vuln['ips'][index].split(" - ")[0]:
                        self.logger.debug("Deleting asset {} from vulnerability {}, seen in risk_accepted.".format(vuln['ips'][index], title))
                        vuln['ips'].pop(index)
            self.logger.debug("Modified assets: {}".format(vuln['ips']))

        return vuln

    def check_vuln_already_exists(self, vuln):
        '''
        This function compares a vulnerability with a collection of tickets.
        Returns [exists (bool), is equal (bool), ticketid (str), assets (array)]
        '''
        # we need to return if the vulnerability has already been reported and the ID of the ticket for further processing
        #function returns array [duplicated(bool), update(bool), ticketid, ticket_assets]
        title = vuln['title']
        labels = [vuln['source'], vuln['scan_name'], 'vulnerability_management', 'vulnerability'] 
        #list(set()) to remove duplicates
        assets = list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", ",".join(vuln['ips']))))
        
        if not self.all_tickets:
            self.logger.info("Retrieving all JIRA tickets with the following tags {}".format(labels))
            # we want to check all JIRA tickets, to include tickets moved to other queues
            # will exclude tickets older than 12 months, old tickets will get closed for higiene and recreated if still vulnerable
            jql = "{} AND NOT labels=advisory AND created >=startOfMonth(-{})".format(" AND ".join(["labels={}".format(label) for label in labels]), self.max_time_tracking)
            
            self.all_tickets = self.jira.search_issues(jql, maxResults=0)
        
        #WARNING: function IGNORES DUPLICATES, after finding a "duplicate" will just return it exists
        #it wont iterate over the rest of tickets looking for other possible duplicates/similar issues
        self.logger.info("Comparing Vulnerabilities to created tickets")
        for index in range(len(self.all_tickets)):
            checking_ticketid, checking_title, checking_assets = self.ticket_get_unique_fields(self.all_tickets[index])
            # added "not risk_accepted", as if it is risk_accepted, we will create a new ticket excluding the accepted assets
            if title.encode('ascii') == checking_title.encode('ascii') and not self.is_risk_accepted(self.jira.issue(checking_ticketid)): 
                difference = list(set(assets).symmetric_difference(checking_assets))
                #to check intersection - set(assets) & set(checking_assets)
                if difference: 
                    self.logger.info("Asset mismatch, ticket to update. Ticket ID: {}".format(checking_ticketid))
                    return False, True, checking_ticketid, checking_assets #this will automatically validate
                else:
                    self.logger.info("Confirmed duplicated. TickedID: {}".format(checking_ticketid))
                    return True, False, checking_ticketid, [] #this will automatically validate
        return False, False, "", []

    def ticket_get_unique_fields(self, ticket):
        title = ticket.raw.get('fields', {}).get('summary').encode("ascii").strip()
        ticketid = ticket.key.encode("ascii")

        assets = self.get_assets_from_description(ticket)
        if not assets:
            #check if attachment, if so, get assets from attachment
            assets = self.get_assets_from_attachment(ticket)
                
        return ticketid, title, assets

    def get_assets_from_description(self, ticket, _raw = False):
        # Get the assets as a string "host - protocol/port - hostname" separated by "\n"
        # structure the text to have the same structure as the assets from the attachment
        affected_assets = ""
        try:
            affected_assets = ticket.raw.get('fields', {}).get('description').encode("ascii").split("{panel:title=Affected Assets}")[1].split("{panel}")[0].replace('\n','').replace(' * ','\n').replace('\n', '', 1)
        except Exception as e:
            self.logger.error("Unable to process the Ticket's 'Affected Assets'. Ticket ID: {}. Reason: {}".format(ticket, e))

        if affected_assets:
            if _raw:
                # from line 406 check if the text in the panel corresponds to having added an attachment
                if "added as an attachment" in affected_assets:
                    return False
                return affected_assets

            try:
                # if _raw is not true, we return only the IPs of the affected assets
                return list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", affected_assets)))
            except Exception as e:
                self.logger.error("Ticket IPs regex failed. Ticket ID: {}. Reason: {}".format(ticket, e))
        return False

    def get_assets_from_attachment(self, ticket, _raw = False):
        # Get the assets as a string "host - protocol/port - hostname" separated by "\n"
        affected_assets = []
        try:
            fields = self.jira.issue(ticket.key).raw.get('fields', {})
            attachments = fields.get('attachment', {})
            affected_assets = ""
            #we will make sure we get the latest version of the file
            latest = ''
            attachment_id = ''
            if attachments:
                for item in attachments:
                    if item.get('filename') == self.attachment_filename:
                        if not latest:
                            latest = item.get('created')
                            attachment_id = item.get('id') 
                        else:
                            if latest < item.get('created'):
                                latest = item.get('created')         
                                attachment_id = item.get('id') 
            affected_assets = self.jira.attachment(attachment_id).get()

        except Exception as e:
            self.logger.error("Failed to get assets from ticket attachment. Ticket ID: {}. Reason: {}".format(ticket, e))

        if affected_assets:
            if _raw:
                return affected_assets

            try:
                # if _raw is not true, we return only the IPs of the affected assets
                affected_assets = list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", affected_assets)))
                return affected_assets
            except Exception as e:
                self.logger.error("Ticket IPs Attachment regex failed. Ticket ID: {}. Reason: {}".format(ticket, e))

        return False

    def parse_asset_to_json(self, asset):
        hostname, protocol, port = "", "", ""
        asset_info = asset.split(" - ")
        ip = asset_info[0]
        proto_port = asset_info[1]
        # in case there is some case where hostname is not reported at all
        if len(asset_info) == 3:
            hostname = asset_info[2]
        if proto_port != "N/A/N/A":
            protocol, port = proto_port.split("/")
            port = int(float(port))

        asset_dict = {
            "host": ip,
            "protocol": protocol,
            "port": port,
            "hostname": hostname
        }

        return asset_dict

    def clean_old_attachments(self, ticket):
        fields = ticket.raw.get('fields')
        attachments = fields.get('attachment')
        if attachments:
            for item in attachments:
                if item.get('filename') == self.attachment_filename:
                    self.jira.delete_attachment(item.get('id'))

    def add_content_as_attachment(self, issue, contents):
        try:
            #Create the file locally with the data
            attachment_file = open(self.attachment_filename, "w")
            attachment_file.write("\n".join(contents))
            attachment_file.close()
            #Push the created file to the ticket
            attachment_file = open(self.attachment_filename, "rb")
            self.jira.add_attachment(issue, attachment_file, self.attachment_filename)
            attachment_file.close()
            #remove the temp file
            os.remove(self.attachment_filename)
            self.logger.info("Added attachment successfully.")
        except:
            self.logger.error("Error while attaching file to ticket.")
            return False

        return True

    def get_ticket_reported_assets(self, ticket):
        #[METRICS] return a list with all the affected assets for that vulnerability (including already resolved ones) 
        return list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",str(self.jira.issue(ticket).raw))))

    def get_resolution_time(self, ticket):
        #get time a ticket took to be resolved
        ticket_obj = self.jira.issue(ticket)
        if self.is_ticket_resolved(ticket_obj):
            ticket_data = ticket_obj.raw.get('fields')
            #dates follow format '2018-11-06T10:36:13.849+0100'
            created = [int(x) for x in ticket_data['created'].split('.')[0].replace('T', '-').replace(':','-').split('-')]
            resolved =[int(x) for x in ticket_data['resolutiondate'].split('.')[0].replace('T', '-').replace(':','-').split('-')]
            
            start = datetime(created[0],created[1],created[2],created[3],created[4],created[5])
            end = datetime(resolved[0],resolved[1],resolved[2],resolved[3],resolved[4],resolved[5])
            return (end-start).days
        else:
            self.logger.error("Ticket {ticket} is not resolved, can't calculate resolution time".format(ticket=ticket))

        return False

    def ticket_update_assets(self, vuln, ticketid, ticket_assets):
        # correct description will always be in the vulnerability to report, only needed to update description to new one
        self.logger.info("Ticket {} exists, UPDATE requested".format(ticketid))
        
        #for now, if a vulnerability has been accepted ('accepted_risk'), ticket is completely ignored and not updated (no new assets)

        #TODO when vulnerability accepted, create a new ticket with only the non-accepted vulnerable assets
        #this would require go through the downloaded tickets, check duplicates/accepted ones, and if so,
        #check on their assets to exclude them from the new ticket
        risk_accepted = False
        ticket_obj = self.jira.issue(ticketid)
        if self.is_ticket_resolved(ticket_obj):
            if self.is_risk_accepted(ticket_obj):
                return 0
            self.reopen_ticket(ticketid=ticketid, comment=self.jira_still_vulnerable_comment)
        
        #First will do the comparison of assets
        ticket_obj.update()
        assets = list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", ",".join(vuln['ips']))))
        difference = list(set(assets).symmetric_difference(ticket_assets))
        
        comment = ''
        added = ''
        removed = ''
        #put a comment with the assets that have been added/removed
        for asset in difference:
            if asset in assets:
                if not added:
                    added = '\nThe following assets *have been newly detected*:\n'
                added += '* {}\n'.format(asset)
            elif asset in ticket_assets:
                if not removed:
                    removed= '\nThe following assets *have been resolved*:\n'
                removed += '* {}\n'.format(asset)

        comment = added + removed
        
        #then will check if assets are too many that need to be added as an attachment
        attachment_contents = []
        if len(vuln['ips']) > self.max_ips_ticket:
            attachment_contents = vuln['ips']
            vuln['ips'] = ["Affected hosts ({assets}) exceed Jira's allowed character limit, added as an attachment.".format(assets = len(attachment_contents))]
        
        #fill the ticket description template
        try:
            tpl = template(self.template_path, vuln)
        except Exception as e:
            self.logger.error('Exception updating assets: {}'.format(str(e)))
            return 0

        #proceed checking if it requires adding as an attachment
        try:
            #update attachment with hosts and delete the old versions
            if attachment_contents:
                self.clean_old_attachments(ticket_obj)
                self.add_content_as_attachment(ticket_obj, attachment_contents)
                
            ticket_obj.update(description=tpl, comment=comment, fields={"labels":ticket_obj.fields.labels})
            self.logger.info("Ticket {} updated successfully".format(ticketid))
            self.add_label(ticketid, 'updated')
        except Exception as e:
            self.logger.error("Error while trying up update ticket {ticketid}.\nReason: {e}".format(ticketid = ticketid, e=e))
        return 0

    def add_label(self, ticketid, label):
        ticket_obj = self.jira.issue(ticketid)
        
        if label not in [x.encode('utf8') for x in ticket_obj.fields.labels]:
            ticket_obj.fields.labels.append(label)
        
            try:
                ticket_obj.update(fields={"labels":ticket_obj.fields.labels})
                self.logger.info("Added label {label} to ticket {ticket}".format(label=label, ticket=ticketid))
            except:
                self.logger.error("Error while trying to add label {label} to ticket {ticket}".format(label=label, ticket=ticketid))
        
        return 0

    def remove_label(self, ticketid, label):
        ticket_obj = self.jira.issue(ticketid)
        
        if label in [x.encode('utf8') for x in ticket_obj.fields.labels]:
            ticket_obj.fields.labels.remove(label)
        
            try:
                ticket_obj.update(fields={"labels":ticket_obj.fields.labels})
                self.logger.info("Removed label {label} from ticket {ticket}".format(label=label, ticket=ticketid))
            except:
                self.logger.error("Error while trying to remove label {label} to ticket {ticket}".format(label=label, ticket=ticketid))
        else:
            self.logger.error("Error: label {label} not in ticket {ticket}".format(label=label, ticket=ticketid))
        
        return 0

    def close_fixed_tickets(self, vulnerabilities):
        '''
        Close tickets which vulnerabilities have been resolved and are still open.
        Higiene clean up affects to all tickets created by the module, filters by label 'vulnerability_management'
        '''
        found_vulns = []
        for vuln in vulnerabilities:
            found_vulns.append(vuln['title'])

        comment = '''This ticket is being closed as it appears that the vulnerability no longer exists.
        If the vulnerability reappears, a new ticket will be opened.'''

        for ticket in self.all_tickets:
            if ticket.raw['fields']['summary'].strip() in found_vulns:
                self.logger.info("Ticket {} is still vulnerable".format(ticket))
                continue
            self.logger.info("Ticket {} is no longer vulnerable".format(ticket))
            self.close_ticket(ticket, self.JIRA_RESOLUTION_FIXED, comment) 
        return 0


    def is_ticket_reopenable(self, ticket_obj):
        transitions = self.jira.transitions(ticket_obj)
        for transition in transitions:
            if transition.get('name') == self.JIRA_REOPEN_ISSUE:
                self.logger.debug("Ticket is reopenable")
                return True
        self.logger.error("Ticket {} can't be opened. Check Jira transitions.".format(ticket_obj))
        return False

    def is_ticket_closeable(self, ticket_obj):
        transitions = self.jira.transitions(ticket_obj)
        for transition in transitions:
            if transition.get('name') == self.JIRA_CLOSE_ISSUE:
                return True
        self.logger.error("Ticket {} can't closed. Check Jira transitions.".format(ticket_obj))
        return False

    def is_ticket_resolved(self, ticket_obj):
        #Checks if a ticket is resolved or not
        if ticket_obj is not None:
            if ticket_obj.raw['fields'].get('resolution') is not None:
                if ticket_obj.raw['fields'].get('resolution').get('name') != 'Unresolved':
                    self.logger.debug("Checked ticket {} is already closed".format(ticket_obj))
                    self.logger.info("Ticket {} is closed".format(ticket_obj))
                    return True
        self.logger.debug("Checked ticket {} is already open".format(ticket_obj))
        return False


    def is_risk_accepted(self, ticket_obj):
        if ticket_obj is not None:
            if ticket_obj.raw['fields'].get('labels') is not None:
                labels = ticket_obj.raw['fields'].get('labels')
                if "risk_accepted" in labels:
                    self.logger.warn("Ticket {} accepted risk, will be ignored".format(ticket_obj))
                    return True
                elif "server_decommission" in labels:
                    self.logger.warn("Ticket {} server decommissioned, will be ignored".format(ticket_obj))
                    return True
                elif "false_positive" in labels:
                    self.logger.warn("Ticket {} flagged false positive, will be ignored".format(ticket_obj))
                    return True
        self.logger.info("Ticket {} risk has not been accepted".format(ticket_obj))
        return False

    def reopen_ticket(self, ticketid, ignore_labels=False, comment=""):
        self.logger.debug("Ticket {} exists, REOPEN requested".format(ticketid))
        # this will reopen a ticket by ticketid
        ticket_obj = self.jira.issue(ticketid)
        
        if self.is_ticket_resolved(ticket_obj):
            if (not self.is_risk_accepted(ticket_obj) or ignore_labels):
                try:
                    if self.is_ticket_reopenable(ticket_obj):
                        error = self.jira.transition_issue(issue=ticketid, transition=self.JIRA_REOPEN_ISSUE, comment = comment)
                        self.logger.info("Ticket {} reopened successfully".format(ticketid))
                        if not ignore_labels:
                            self.add_label(ticketid, 'reopened')
                        return 1
                except Exception as e:
                    # continue with ticket data so that a new ticket is created in place of the "lost" one
                    self.logger.error("error reopening ticket {}: {}".format(ticketid, e))
                    return 0
        return 0

    def close_ticket(self, ticketid, resolution, comment):
        # this will close a ticket by ticketid
        self.logger.debug("Ticket {} exists, CLOSE requested".format(ticketid))
        ticket_obj = self.jira.issue(ticketid)
        if not self.is_ticket_resolved(ticket_obj):
            try:
                if self.is_ticket_closeable(ticket_obj):
                    #need to add the label before closing the ticket
                    self.add_label(ticketid, 'closed')
                    error = self.jira.transition_issue(issue=ticketid, transition=self.JIRA_CLOSE_ISSUE, comment = comment, resolution = {"name": resolution })
                    self.logger.info("Ticket {} closed successfully".format(ticketid))
                    return 1
            except Exception as e:
                # continue with ticket data so that a new ticket is created in place of the "lost" one
                self.logger.error("error closing ticket {}: {}".format(ticketid, e))
                return 0
                
        return 0

    def close_obsolete_tickets(self):
        # Close tickets older than 12 months, vulnerabilities not solved will get created a new ticket 
        self.logger.info("Closing obsolete tickets older than {} months".format(self.max_time_tracking))
        jql = "labels=vulnerability_management AND NOT labels=advisory AND created <startOfMonth(-{}) and resolution=Unresolved".format(self.max_time_tracking)
        tickets_to_close = self.jira.search_issues(jql, maxResults=0)
        
        comment = '''This ticket is being closed for hygiene, as it is more than {} months old.
        If the vulnerability still exists, a new ticket will be opened.'''.format(self.max_time_tracking)
        
        for ticket in tickets_to_close:
                self.close_ticket(ticket, self.JIRA_RESOLUTION_OBSOLETE, comment)
        
        return 0

    def project_exists(self, project):
        try:
            self.jira.project(project)
            return True
        except:
            return False
        return False

    def download_tickets(self, path):
        '''
        saves all tickets locally, local snapshot of vulnerability_management ticktes
        '''
        #check if file already exists
        check_date = str(date.today())
        fname = '{}jira_{}.json'.format(path, check_date) 
        if os.path.isfile(fname):
            self.logger.info("File {} already exists, skipping ticket download".format(fname))
            return True
        try:
            self.logger.info("Saving locally tickets from the last {} months".format(self.max_time_tracking))
            jql = "labels=vulnerability_management AND NOT labels=advisory AND created >=startOfMonth(-{})".format(self.max_time_tracking)
            tickets_data = self.jira.search_issues(jql, maxResults=0)

            #TODO process tickets, creating a new field called "_metadata" with all the affected assets well structured
            # for future processing in ELK/Splunk; this includes downloading attachments with assets and processing them

            processed_tickets = []

            for ticket in tickets_data:
                assets = self.get_assets_from_description(ticket, _raw=True)
                if not assets:
                    # check if attachment, if so, get assets from attachment
                    assets = self.get_assets_from_attachment(ticket, _raw=True)
                # process the affected assets to save them as json structure on a new field from the JSON
                _metadata = {"affected_hosts": []}
                if assets:
                    if "\n" in assets:
                        for asset in assets.split("\n"):
                            assets_json = self.parse_asset_to_json(asset)
                            _metadata["affected_hosts"].append(assets_json)
                    else:
                        assets_json = self.parse_asset_to_json(assets)
                        _metadata["affected_hosts"].append(assets_json)


                temp_ticket = ticket.raw.get('fields')
                temp_ticket['_metadata'] = _metadata

                processed_tickets.append(temp_ticket)
            
            #end of line needed, as writelines() doesn't add it automatically, otherwise one big line
            to_save = [json.dumps(ticket.raw.get('fields'))+"\n" for ticket in tickets_data]
            with open(fname, 'w') as outfile:
                outfile.writelines(to_save)
                self.logger.info("Tickets saved succesfully.")
            
            return True

        except Exception as e:
            self.logger.error("Tickets could not be saved locally: {}.".format(e))

        return False 

    def decommission_cleanup(self):
        '''
        deletes the server_decomission tag from those tickets that have been 
        closed already for more than x months (default is 3 months) in order to clean solved issues
        for statistics purposes
        '''
        self.logger.info("Deleting 'server_decommission' tag from tickets closed more than {} months ago".format(self.max_decommission_time))

        jql = "labels=vulnerability_management AND labels=server_decommission and resolutiondate <=startOfMonth(-{})".format(self.max_decommission_time)
        decommissioned_tickets = self.jira.search_issues(jql, maxResults=0)
        
        comment = '''This ticket is having deleted the *server_decommission* tag, as it is more than {} months old and is expected to already have been decommissioned.
        If that is not the case and the vulnerability still exists, the vulnerability will be opened again.'''.format(self.max_decommission_time)
        
        for ticket in decommissioned_tickets:
            #we open first the ticket, as we want to make sure the process is not blocked due to 
            #an unexisting jira workflow or unallowed edit from closed tickets
            self.reopen_ticket(ticketid=ticket, ignore_labels=True)
            self.remove_label(ticket, 'server_decommission')
            self.close_ticket(ticket, self.JIRA_RESOLUTION_FIXED, comment)
        
        return 0
