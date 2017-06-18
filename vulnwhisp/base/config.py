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