#!/usr/bin/python
# iotop: Display I/O usage of processes in a top like UI
# Copyright (c) 2007, 2008 Guillaume Chazarain <guichaz@gmail.com>
# GPL version 2 or later
# See iotop --help for some help

import sys

from iotop.ui import main

try:
    main()
except KeyboardInterrupt:
    pass
sys.exit(0)
