''' Module to hold global settings reused throughout qualysapi. '''

from __future__ import absolute_import
__author__ = "Colin Bell <colin.bell@uwaterloo.ca>"
__copyright__ = "Copyright 2011-2013, University of Waterloo"
__license__ = "BSD-new"

import os

global defaults
global default_filename


if os.name == 'nt':
    default_filename = "config.ini"
else:
    default_filename = ".qcrc"

defaults = {'hostname': 'qualysapi.qualys.com',
            'max_retries': '3'}
