import os
import sys

# Support for python3
if (sys.version_info > (3, 0)):
    import configparser as cp
else:
    import ConfigParser as cp


class vwConfig(object):

    def __init__(self, config_in=None):
        self.config_in = config_in
        self.config = cp.RawConfigParser()
        self.config.read(self.config_in)

    def get(self, section, option):
        return self.config.get(section, option)

    def getbool(self, section, option):
        return self.config.getboolean(section, option)

    def get_enabled(self):
	enabled = []
	check = ["true", "True", "1"]
	for section in self.config.sections():
            try:
                if self.get(section, "enabled") in check:
                    enabled.append(section)	
            except:
                print "[INFO] Section {} has no option 'enabled'".format(section)
	return enabled

    def exists_jira_profiles(self, profiles):
        # get list of profiles source_scanner.scan_name
        for profile in profiles:
            if not self.config.has_section(self.normalize_section(profile)):
                print "[INFO] JIRA Scan Profile missing"
                return False
        return True


    def update_jira_profiles(self, profiles):
        # create JIRA profiles in the ini config file 

        for profile in profiles:
            #IMPORTANT profile scans/results will be normalized to lower and "_" instead of spaces for ini file section
            section_name = self.normalize_section(profile)
            try:
                self.get(section_name, "source")
                print "Skipping creating of section '{}'; already exists".format(section_name)
            except:
                print "Creating config section for '{}'".format(section_name)
                self.config.add_section(section_name)
                self.config.set(section_name,'source',profile.split('.')[0])
                # in case any scan name contains '.' character
                self.config.set(section_name,'scan_name','.'.join(profile.split('.')[1:]))
                self.config.set(section_name,'jira_project', "")
                self.config.set(section_name,'; if multiple components, separate by ","')
                self.config.set(section_name,'components', "")
                self.config.set(section_name,'; minimum criticality to report (low, medium, high or critical)')
                self.config.set(section_name,'min_critical_to_report', 'high')
        
        # writing changes back to file
        with open(self.config_in, 'w') as configfile:
            self.config.write(configfile)
        
        return

    def normalize_section(self, profile):
        profile = "jira.{}".format(profile.lower().replace(" ","_"))
        return profile
