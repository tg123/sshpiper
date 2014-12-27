#!/bin/bash
set -e

BASEDIR=$(dirname $(readlink -f $0))

DIST_BIN=${1:-$GOPATH/bin/sshpiperd}
DIST_BIN=`readlink -f $DIST_BIN`

if [ ! -x $DIST_BIN ];then
    echo "can not find sshpiper bin"
    exit
fi

echo "packing bin:$DIST_BIN"

VERSION=`$DIST_BIN --version | grep -Po "ver: .*? " | sed "s/ver: *//g" | sed "s/ *$//g"` 
VERSION=${VERSION#v} ## remove v

echo "building .deb for ver: $VERSION"

DIST_DIR=`mktemp -d`


## copy from docker
cat > $DIST_DIR/postinst <<'EOF'
#!/bin/sh
set -e
set -u

update-rc.d sshpiperd defaults > /dev/null || true
if [ -n "$2" ]; then
    _dh_action=restart
else
    _dh_action=start
fi
service sshpiperd $_dh_action 2>/dev/null || true
#DEBHELPER#
EOF

cat > $DIST_DIR/prerm <<'EOF'
#!/bin/sh
set -e
set -u
service sshpiperd stop 2>/dev/null || true
#DEBHELPER#
EOF

chmod +x $DIST_DIR/postinst $DIST_DIR/prerm


mkdir -p $DIST_DIR/root/var/sshpiper
mkdir -p $DIST_DIR/root/etc/
mkdir -p $DIST_DIR/root/usr/local/bin

cp $DIST_BIN $DIST_DIR/root/usr/local/bin
cp $BASEDIR/sshpiperd.conf $DIST_DIR/root/etc


NAME=sshpiperd
MAINTAINER=tgic
CATEGORY=net
DESCRIPTION="Username based SSH Reverse Proxy"
LICENSE="The MIT License (MIT)"
HOMEPAGE="https://github.com/tg123/sshpiper"

echo $BASEDIR

fpm -f -s dir -t deb -n "$NAME" -v "$VERSION" \
    --deb-init $BASEDIR/init.d/sshpiperd \
    --deb-priority optional \
    --after-install $DIST_DIR/postinst \
    --before-remove $DIST_DIR/prerm \
    --prefix / \
    --maintainer "$MAINTAINER" \
    --description "$DESCRIPTION" \
    --category "$CATEGORY" \
    --depends libpam0g \
    --provides sshpiperd \
    --url "$HOMEPAGE" \
    --license "$LICENSE" \
    --config-files /etc/sshpiperd.conf \
    -C $DIST_DIR/root .

rm -rf $DIST_DIR
