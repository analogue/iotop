#!/bin/bash

set -x
set -e # Exit on error

PACKAGE=$(basename "$PWD")
mkdir dist
TEMPDIR="$(mktemp -d)"
VERSION=$(python -c "from $PACKAGE.version import VERSION; print VERSION")
echo "$PACKAGE-$VERSION: $TEMPDIR"
mkdir "$TEMPDIR/$PACKAGE-$VERSION"
git archive HEAD | (cd "$TEMPDIR/$PACKAGE-$VERSION" && tar vx)
git2cl > "$TEMPDIR/$PACKAGE-$VERSION/ChangeLog"
DIR="$PWD"
cd "$TEMPDIR/$PACKAGE-$VERSION"
./setup.py sdist --formats gztar,bztar
mv "dist/$PACKAGE-$VERSION.tar."{gz,bz2} "$DIR/dist"
./setup.py bdist_rpm
mv "dist/$PACKAGE-$VERSION-1."{noarch,src}.rpm "$DIR/dist"
rm -fr "$TEMPDIR"
(cd "$DIR/dist" && echo * | xargs -n1 gpg -ab)
