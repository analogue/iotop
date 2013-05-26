#!/usr/bin/env python

from distutils.core import setup
from distutils.command import install as distutils_install
from iotop.version import VERSION

# Dirty hack to make setup.py install the iotop script to sbin/ instead of bin/
# while still honoring the choice of installing into local/ or not.
if hasattr(distutils_install, 'INSTALL_SCHEMES'):
    for d in distutils_install.INSTALL_SCHEMES.itervalues():
        if d.get('scripts', '').endswith('/bin'):
            d['scripts'] = d['scripts'][:-len('/bin')] + '/sbin'

setup(name='iotop',
      version=VERSION,
      description='Per process I/O bandwidth monitor',
      long_description=
'''Iotop is a Python program with a top like UI used to show of behalf of which
process is the I/O going on.''',
      author='Guillaume Chazarain',
      author_email='guichaz@gmail.com',
      url='http://guichaz.free.fr/iotop',
      scripts=['sbin/iotop'],
      data_files=[('share/man/man8', ['iotop.8'])],
      packages=['iotop'],
      license='GPL'
)
