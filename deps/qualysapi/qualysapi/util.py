""" A set of utility functions for QualysConnect module. """
from __future__ import absolute_import
import logging

import qualysapi.config as qcconf
import qualysapi.connector as qcconn
import qualysapi.settings as qcs

__author__ = "Parag Baxi <parag.baxi@gmail.com> & Colin Bell <colin.bell@uwaterloo.ca>"
__copyright__ = "Copyright 2011-2013, Parag Baxi & University of Waterloo"
__license__ = 'Apache License 2.0'

# Set module level logger.
logger = logging.getLogger(__name__)


def connect(config_file=qcs.default_filename, section='info', remember_me=False, remember_me_always=False):
    """ Return a QGAPIConnect object for v1 API pulling settings from config
    file.
    """
    # Retrieve login credentials.
    conf = qcconf.QualysConnectConfig(filename=config_file, section=section, remember_me=remember_me,
                                      remember_me_always=remember_me_always)
    connect = qcconn.QGConnector(conf.get_auth(),
                                 conf.get_hostname(),
                                 conf.proxies,
                                 conf.max_retries)
    logger.info("Finished building connector.")
    return connect
