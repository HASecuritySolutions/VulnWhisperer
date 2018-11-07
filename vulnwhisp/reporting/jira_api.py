import json
import os
from datetime import datetime, date, timedelta

from jira import JIRA
import requests
import logging
from bottle import template
import re

class JiraAPI(object):
    def __init__(self, hostname=None, username=None, password=None, path="", debug=False, clean_obsolete=True, max_time_window=12):
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
        self.JIRA_REOPEN_ISSUE = "Reopen Issue"
        self.JIRA_CLOSE_ISSUE = "Close Issue"
        self.max_time_tracking = max_time_window #in months
        #<JIRA Resolution: name=u'Obsolete', id=u'11'>
        self.JIRA_RESOLUTION_OBSOLETE = "Obsolete"
        self.JIRA_RESOLUTION_FIXED = "Fixed"
        self.clean_obsolete = clean_obsolete
        self.template_path = 'vulnwhisp/reporting/resources/ticket.tpl'
        if path:
            self.download_tickets(path)
        else:
            self.logger.warning("No local path specified, skipping Jira ticket download.")

    def create_ticket(self, title, desc, project="IS", components=[], tags=[]):
        labels = ['vulnerability_management']
        for tag in tags:
            labels.append(str(tag))

        self.logger.info("creating ticket for project {} title[20] {}".format(project, title[:20]))
        self.logger.info("project {} has a component requirement: {}".format(project, self.PROJECT_COMPONENT_TABLE[project]))
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
                    
        new_issue = self.jira.create_issue(project=project,
                                           summary=title,
                                           description=desc,
                                           issuetype={'name': 'Bug'},
                                           labels=labels,
                                           components=components_ticket)

        self.logger.info("Ticket {} created successfully".format(new_issue))
        return new_issue
    
    #Basic JIRA Metrics
    def metrics_open_tickets(self, project=None):
        jql = "labels= vulnerability_management and resolution = Unresolved" 
        if project:
            jql += " and (project='{}')".format(project)
        self.logger.debug('Executing: {}'.format(jql)) 
        return len(self.jira.search_issues(jql, maxResults=0))

    def metrics_closed_tickets(self, project=None):
        jql = "labels= vulnerability_management and NOT resolution = Unresolved" 
        if project:
            jql += " and (project='{}')".format(project)
        return len(self.jira.search_issues(jql, maxResults=0))

    def sync(self, vulnerabilities, project, components=[]):
        #JIRA structure of each vulnerability: [source, scan_name, title, diagnosis, consequence, solution, ips, risk, references]
        self.logger.info("JIRA Sync started")

        # [HIGIENE] close tickets older than 12 months as obsolete
        # Higiene clean up affects to all tickets created by the module, filters by label 'vulnerability_management'
        if self.clean_obsolete:
            self.close_obsolete_tickets()

        for vuln in vulnerabilities:
            # JIRA doesn't allow labels with spaces, so making sure that the scan_name doesn't have spaces
            # if it has, they will be replaced by "_"
            if " " in  vuln['scan_name']:
                vuln['scan_name'] = "_".join(vuln['scan_name'].split(" "))
            
            exists = False
            to_update = False
            ticketid = ""
            ticket_assets = []
            exists, to_update, ticketid, ticket_assets = self.check_vuln_already_exists(vuln)

            if exists:
                # If ticket "resolved" -> reopen, as vulnerability is still existent
                self.reopen_ticket(ticketid)
                self.add_label(ticketid, vuln['risk'])
                continue
            elif to_update:
                self.ticket_update_assets(vuln, ticketid, ticket_assets)
                self.add_label(ticketid, vuln['risk'])
                continue

            try:
                tpl = template(self.template_path, vuln)
            except Exception as e:
                self.logger.error('Exception templating: {}'.format(str(e)))
                return 0
            self.create_ticket(title=vuln['title'], desc=tpl, project=project, components=components, tags=[vuln['source'], vuln['scan_name'], 'vulnerability', vuln['risk']])
        
        self.close_fixed_tickets(vulnerabilities)
        # we reinitialize so the next sync redoes the query with their specific variables
        self.all_tickets = []
        return True

    def check_vuln_already_exists(self, vuln):
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
        for index in range(len(self.all_tickets)-1):
            checking_ticketid, checking_title, checking_assets = self.ticket_get_unique_fields(self.all_tickets[index])
            if title == checking_title: 
                difference = list(set(assets).symmetric_difference(checking_assets))
                #to check intersection - set(assets) & set(checking_assets)
                if difference: 
                    self.logger.info("Asset mismatch, ticket to update. TickedID: {}".format(checking_ticketid))
                    return False, True, checking_ticketid, checking_assets #this will automatically validate
                else:
                    self.logger.info("Confirmed duplicated. TickedID: {}".format(checking_ticketid))
                    return True, False, checking_ticketid, [] #this will automatically validate
        return False, False, "", []

    def ticket_get_unique_fields(self, ticket):
        title = ticket.raw.get('fields', {}).get('summary').encode("ascii").strip()
        ticketid = ticket.key.encode("ascii")
        try:
            affected_assets_section = ticket.raw.get('fields', {}).get('description').encode("ascii").split("{panel:title=Affected Assets}")[1].split("{panel}")[0]
            assets = list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", affected_assets_section)))
        except:
            self.logger.error("Ticket IPs regex failed. Ticket ID: {}".format(ticketid))
            assets = []
        
        return ticketid, title, assets

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
        
        if self.is_ticket_resolved(self.jira.issue(ticketid)):
            self.reopen_ticket(ticketid)
        try:
            tpl = template(self.template_path, vuln)
        except Exception as e:
            self.logger.error('Exception updating assets: {}'.format(str(e)))
            return 0

        ticket_obj = self.jira.issue(ticketid)
        ticket_obj.update()
        assets = list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", ",".join(vuln['ips']))))
        difference = list(set(assets).symmetric_difference(ticket_assets))
        
        comment = ''
        #put a comment with the assets that have been added/removed
        for asset in difference:
            if asset in assets:
                comment += "Asset {} have been added to the ticket as vulnerability *has been newly detected*.\n".format(asset)
            elif asset in ticket_assets:
                comment += "Asset {} have been removed from the ticket as vulnerability *has been resolved*.\n".format(asset)
       
        try:
            ticket_obj.update(description=tpl, comment=comment, fields={"labels":ticket_obj.fields.labels})
            self.logger.info("Ticket {} updated successfully".format(ticketid))
            self.add_label(ticketid, 'updated')
        except:
            self.logger.error("Error while trying up update ticket {}".format(ticketid))
        return 0

    def add_label(self, ticketid, label):
        ticket_obj = self.jira.issue(ticketid)
        
        if label not in ticket_obj.fields.labels:
                ticket_obj.fields.labels.append(label)
        
        try:
            ticket_obj.update(fields={"labels":ticket_obj.fields.labels})
            self.logger.info("Added label {label} to ticket {ticket}".format(label=label, ticket=ticketid))
        except:
            self.logger.error("Error while trying to add label {label} to ticket {ticket}".format(label=label, ticket=ticketid))
        return 0

    def close_fixed_tickets(self, vulnerabilities):
        # close tickets which vulnerabilities have been resolved and are still open
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
        self.logger.warn("Ticket can't be opened. Check Jira transitions.")
        return False

    def is_ticket_closeable(self, ticket_obj):
        transitions = self.jira.transitions(ticket_obj)
        for transition in transitions:
            if transition.get('name') == self.JIRA_CLOSE_ISSUE:
                return True
        self.logger.warn("Ticket can't closed. Check Jira transitions.")
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
                elif "server_decomission" in labels:
                    self.logger.warn("Ticket {} server decomissioned, will be ignored".format(ticket_obj))
                    return True
        self.logger.info("Ticket {} risk has not been accepted".format(ticket_obj))
        return False

    def reopen_ticket(self, ticketid):
        self.logger.debug("Ticket {} exists, REOPEN requested".format(ticketid))
        # this will reopen a ticket by ticketid
        ticket_obj = self.jira.issue(ticketid)
        
        if self.is_ticket_resolved(ticket_obj):
            if not self.is_risk_accepted(ticket_obj):
                try:
                    if self.is_ticket_reopenable(ticket_obj):
                        comment = '''This ticket has been reopened due to the vulnerability not having been fixed (if multiple assets are affected, all need to be fixed; if the server is down, lastest known vulnerability might be the one reported).
                        In the case of the team accepting the risk and wanting to close the ticket, please add the label "*risk_accepted*" to the ticket before closing it.
                        If server has been decomissioned, please add the label "*server_decomission*" to the ticket before closing it.
                        If you have further doubts, please contact the Security Team.'''
                        error = self.jira.transition_issue(issue=ticketid, transition=self.JIRA_REOPEN_ISSUE, comment = comment)
                        self.logger.info("Ticket {} reopened successfully".format(ticketid))
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
                    error = self.jira.transition_issue(issue=ticketid, transition=self.JIRA_CLOSE_ISSUE, comment = comment, resolution = {"name": resolution })
                    self.logger.info("Ticket {} closed successfully".format(ticketid))
                    self.add_label(ticketid, 'closed')
                    return 1
            except Exception as e:
                # continue with ticket data so that a new ticket is created in place of the "lost" one
                self.logger.error("error closing ticket {}: {}".format(ticketid, e))
                return 0
                
        return 0

    def close_obsolete_tickets(self):
        # Close tickets older than 12 months, vulnerabilities not solved will get created a new ticket 
        self.logger.info("Closing obsolete tickets older than {} months".format(self.max_time_tracking))
        jql = "labels=vulnerability_management AND created <startOfMonth(-{}) and resolution=Unresolved".format(self.max_time_tracking)
        tickets_to_close = self.jira.search_issues(jql, maxResults=0)
        
        comment = '''This ticket is being closed for hygiene, as it is more than 12 months old.
        If the vulnerability still exists, a new ticket will be opened.'''
        
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
        #saves all tickets locally, local snapshot of vulnerability_management ticktes
        #check if file already exists
        check_date = str(date.today())
        fname = '{}jira_{}.json'.format(path, check_date) 
        if os.path.isfile(fname):
            self.logger.info("File {} already exists, skipping ticket download".format(fname))
            return True
        try:
            self.logger.info("Saving locally tickets from the last {} months".format(self.max_time_tracking))
            jql = "labels=vulnerability_management AND created >=startOfMonth(-{})".format(self.max_time_tracking)
            tickets_data = self.jira.search_issues(jql, maxResults=0)
            
            #end of line needed, as writelines() doesn't add it automatically, otherwise one big line
            to_save = [json.dumps(ticket.raw.get('fields'))+"\n" for ticket in tickets_data]
            with open(fname, 'w') as outfile:
                outfile.writelines(to_save)
                self.logger.info("Tickets saved succesfully.")
            
            return True

        except Exception as e:
            self.logger.error("Tickets could not be saved locally: {}.".format(e))
        
        return False 
