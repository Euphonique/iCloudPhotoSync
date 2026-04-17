#!/bin/bash
source /pkgscripts-ng/include/pkg_util.sh

package="iCloudPhotoSync"
version="1.0.0-0053"
os_min_ver="7.1-42218"
displayname="iCloud Photo Sync"
description="Sync photos from iCloud to your Synology NAS"
maintainer="Pascal Pagel"
maintainer_url="https://github.com/Euphonique"
arch="noarch"
dsmuidir="ui"
dsmappname="SYNO.SDS.iCloudPhotoSync"
dsmapplaunchname="SYNO.SDS.iCloudPhotoSync.Instance"
silent_install="yes"
silent_upgrade="yes"
silent_uninstall="yes"
thirdparty="yes"
startable="yes"

pkg_dump_info
