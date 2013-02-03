#!/bin/bash

# http://bugs.python.org/issue644744

python setup.py install -O1 --root="$RPM_BUILD_ROOT" --record=INSTALLED_FILES
# 'brp-compress' gzips the man pages without distutils knowing... fix this
sed -i -e 's@man/man\([[:digit:]]\)/\(.\+\.[[:digit:]]\)$@man/man\1/\2.gz@g' INSTALLED_FILES
# actually, it doesn't on all distributions so just compress unconditionally
# before brp-compress is run
find "$RPM_BUILD_ROOT" -type f -name iotop.8 -exec gzip '{}' \;

# move from bin/ to sbin/
sed -i -e 's@/bin/iotop@/sbin/iotop@g' INSTALLED_FILES
cd "$(find "$RPM_BUILD_ROOT" -type d -name bin)/.."
mv bin sbin
cd -
