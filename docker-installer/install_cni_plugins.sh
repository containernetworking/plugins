#!/bin/sh

set -e

if [ $# -ne 2 ]; then
  echo "USAGE: $0 source-dir dest-dir"
  exit 1
fi

SRC=$1
DST=$2

install_cni_plugin() {
	NAME=$1
	MD5=$( md5sum $SRC/$NAME | awk '{ print $1 }' )
	if [ -e $DST/$NAME ]; then
		if [ ! -e $DST/$NAME.by_cni_installer_image ]; then
			# The file already exists but there's no marker that
			# it was installed by this installer -> keep untouched
			echo "* '$NAME' ignored (exists but not installed by me)"
			return
		fi
		OTHER_MD5=$( md5sum $DST/$NAME | awk '{ print $1 }' )
		INSTALLED_MD5=$( cat $DST/$NAME.by_cni_installer_image )

		if [ "$OTHER_MD5" != "$INSTALLED_MD5" ]; then
			# The file was previously installed by this installer
			# but later changed -> keep untouched
			echo "* '$NAME' ignored (previously installed by me but changed by someone else)"
			return
		fi

		if [ "$OTHER_MD5" == "$MD5" ]; then
			# The file was previously installed by this installer
			# and is up-to-date
			echo "* '$NAME' is up-to-date"
			return
		fi

		# The file was previously installed by this installer
		# but needs an update
		cp -a $SRC/$NAME $DST/$NAME
		echo $MD5 > $DST/$NAME.by_cni_installer_image
		echo "* '$NAME' updated"

	else
		cp -a $SRC/$NAME $DST/$NAME
		echo $MD5 > $DST/$NAME.by_cni_installer_image
		echo "* '$NAME' installed"
	fi
}

echo "Installing CNI plug-ins to $DST"
echo

for FILE in $( find $SRC -maxdepth 1  -type f ); do
	NAME=$( basename $FILE )
	install_cni_plugin $NAME
done
