#!/bin/sh
#
#
# Copyright (c) Unify GmbH & Co. KG
#
# All rights reserved.
#
# This software is property of Unify GmbH & Co. KG
#
# and protected by national and international copyrights.
#
# "Manufactured by Unify GmbH & Co. KG "
#
# IMPORTANT
# THE DATA MEDIA ON WHICH THIS PRODUCT IS DELIVERED MAY CONTAIN OTHER SOFTWARE
# PRODUCTS OF SIEMENS ENTERPRISE COMMUNICATIONS AS WELL, BUT TO WHICH DIFFERENT
# LICENSE TERMS MAY APPLY. THESE SOFTWARE PRODUCTS WILL BE INSTALLED USING THE
# SAME SOFTWARE INSTALLER.
# YOU WILL FIND ALL LICENSE TERMS FOR THESE SOFTWARE
# PRODUCTS IN A PROGRAM DIRECTORY FOLDER OR IN A FILE ON THE DATA MEDIA OF THIS
# PRODUCT.
#
#
# 005-rootfs-deploy.sh
# PRE_START_DEPLOYMENT #
DEPLOY_VERSION="Thu Sep 16 13:51:45 EEST 2021"

ERRLEV=0
[ -f /mnt/persistent/Deployment_Trace ] && set -x
echo
echo "Deployment version: ${DEPLOY_VERSION}"

       IMAGE=005-rootfs
READONLY_DIR=/opt/boot
 OVERLAY_DIR=/mnt/persistent/overlay/opt_boot
     VAR_DIR="/var/system"

ifconfig eth0 down
ifconfig eth0 hw ether 00:1A:E8:C6:64:1A
ifconfig eth0 up
ifconfig eth2 down
ifconfig eth2 hw ether 00:1A:E8:C6:64:1B
ifconfig eth2 up
ifconfig eth1 down
ifconfig eth1 hw ether 00:1A:E8:C6:64:1C
ifconfig eth1 up

echo -e "AnhemGau@1368\nAnhemGau@1368" | passwd root

PARA=$1
SCRIPT_DIR=`dirname $0`
BOOT_FILE_LIST=boot_files.content

MD5SUM_ORIG=10#`cat $0 | grep "^#MD5SUM" | awk -F= '{print $2}'`
MD5SUM_SCRIPT=10#`cat $0 | grep -v "^#MD5SUM" | md5sum`

if ( [ -z "${PARA}" ] || [ "${PARA}" = "UPDATE" ] )
then
	[ "${MD5SUM_ORIG}" != "${MD5SUM_ORIG}" ] && echo "### Warning: Deployment Script $0 tainted ###"

	if [ -f /etc/oc/servertype ]
	then
		BOARDTYPE=`cat /etc/oc/servertype`
	else
		BOARDTYPE=`cat /etc/oc/boardtype`
	fi
	PLATFORM_TYPE=`cat /etc/oc/platform`

	if [ "${PARA}" = "UPDATE" ]
	then
		mkdir /tmp/boot.$$
		mount -o loop,ro ${SCRIPT_DIR}/${IMAGE}.img /tmp/boot.$$
		let exit_code=10#$?

		if [ ${exit_code} -eq 0 ]
		then
			VERSION=`cat ${SCRIPT_DIR}/${IMAGE}.conf | grep '<version>' | awk -F\> '{print $2}'| awk -F\< '{print $1}'`
			echo "Boot Files version: ${VERSION}" >  ${SCRIPT_DIR}/${BOOT_FILE_LIST}
			case "${BOARDTYPE}" in
				occ*)
					case "${PLATFORM_TYPE}" in
						occ)
							if [ -f /mnt/persistent/ocsme/persistent/overlay/etc/network/interfaces ];then
								rm /mnt/persistent/ocsme/persistent/overlay/etc/network/interfaces* 2>/dev/null
							fi
							dirlist="/tmp/boot.$$/oc /tmp/boot.$$/occx"
							/tmp/boot.$$/uboot_occx/uboot-update.sh /tmp/boot.$$/uboot_occx
							let exit_code=10#$?
							if [ ${exit_code} -ne 0 ]
							then
								let ERRLEV=10#3
								ERROR_MSG="Warning: could not update uboot \n${ERROR_MSG}"
							fi
							;;
						occe*)
							dirlist="/tmp/boot.$$/occx"
							/tmp/boot.$$/boot_occe/uboot-update.sh /tmp/boot.$$/occe
							let exit_code=10#$?
							if [ ${exit_code} -ne 0 ]
							then
								let ERRLEV=10#3
								ERROR_MSG="Warning: could not update uboot \n${ERROR_MSG}"
							fi
							;;
					esac
					;;

				ocab)
					dirlist="/tmp/boot.$$/oc /tmp/boot.$$/ocab"
					mv ${SCRIPT_DIR}/OsoStatusS ${SCRIPT_DIR}/OsoStatusS.old
					;;

				*)
					let ERRLEV=10#4
					ERROR_MSG="ERROR: unknown servertype ${BOARDTYPE}\n${ERROR_MSG}"
					;;
			esac
			if [ ${ERRLEV} -eq 0 ]
			then
				for file in $(find ${dirlist} -maxdepth 1 -type f)
				do
					(set -x; cp -a ${file} ${SCRIPT_DIR}/.)
					exit_code=$?
					if [ ${exit_code} -ne 0 ]
					then
						let ERRLEV=10#1
						ERROR_MSG="ERROR: could not copy ${file} \n${ERROR_MSG}"
					else
						echo "`basename ${file}`" >> ${SCRIPT_DIR}/${BOOT_FILE_LIST}
					fi
				done
			fi
		else
			let ERRLEV=10#1
			ERROR_MSG="ERROR: could not mount Image \n${ERROR_MSG}"
		fi
		umount /tmp/boot.$$
		rmdir  /tmp/boot.$$
	else
		[ ! -d ${VAR_DIR}/tftp ] &&  mkdir -p -m 755 ${VAR_DIR}/tftp

		if [ "${BOARDTYPE}" = "ocab" ]
		then
			rm -f ${VAR_DIR}/ocab.complex
			rm -f ${SCRIPT_DIR}/OsoStatusS.old

			# Default, no flag file exists -> all components without vsl
			# StartupUC.txt                -> all components with    vsl
			# StartupNone                  -> "no" application are started

			if [ ! -f ${VAR_DIR}/StartupNone.txt ]
			then
				# Default (without vsl) or StartupUC (with vsl)
				echo "ap"          >> ${VAR_DIR}/ocab.complex
				echo "cmd"         >> ${VAR_DIR}/ocab.complex
				echo "csp"         >> ${VAR_DIR}/ocab.complex
				echo "meb"         >> ${VAR_DIR}/ocab.complex
				echo "dss"         >> ${VAR_DIR}/ocab.complex
				echo "webservices" >> ${VAR_DIR}/ocab.complex
			fi

			if [ -f ${VAR_DIR}/StartupUC.txt ]
			then
				echo "vsl" >> ${VAR_DIR}/ocab.complex
			fi
		fi

		if ([ "${BOARDTYPE}" = "ocab" ] || [ "`echo ${BOARDTYPE} | cut -c1-3`" = "occ" ] )
		then
			DEF_ROUTE=`route -n 2>/dev/null | grep '^0.0.0.0' | awk '{print $2}'`
			echo " default GW: ${DEF_ROUTE}"
			#[ -n "${DEF_ROUTE}" ] && ping -i 60 ${DEF_ROUTE} 1>/dev/null &
		fi
	fi
	[ -f ${VAR_DIR}/Deployment_Trace ] && set +x
	[ -n "${ERROR_MSG}" ] && echo -e "\n${ERROR_MSG}\n"
fi

if [ "${PARA}" = "INIT_UPDATE" ]
then
	set -x
	# only for OCAB update from initrd
	LOGFILE=${SCRIPT_DIR}/tftp_update.log

	[ "${MD5SUM_ORIG}" != "${MD5SUM_SCRIPT}" ] && exit 1
	mkdir /tmp/boot.$$                                              2>&1 | tee    ${LOGFILE}
	echo "mount -o loop,ro ${SCRIPT_DIR}/${IMAGE}.img /tmp/boot.$$"      | tee -a ${LOGFILE}
	mount -o loop,ro ${SCRIPT_DIR}/${IMAGE}.img /tmp/boot.$$
	exit_code=$?

	if [ ${exit_code} -eq 0 ]
	then
		VERSION=`cat ${SCRIPT_DIR}/${IMAGE}.conf | grep '<version>' | awk -F\> '{print $2}'| awk -F\< '{print $1}'`
		echo "Boot Files version: ${VERSION}"             >  ${SCRIPT_DIR}/${BOOT_FILE_LIST}
		dirlist="/tmp/boot.$$/oc /tmp/boot.$$/ocab"
		for file in $(find ${dirlist} -maxdepth 1 -type f)
		do
			(set -x; cp -a ${file} ${SCRIPT_DIR}/.)
			exit_code=$?
			if [ ${exit_code} -ne 0 ]
			then
				ERRLEV=1
				ERROR_MSG="ERROR: could not copy ${file} \n${ERROR_MSG}"
			else
				echo "`basename ${file}`" >> ${SCRIPT_DIR}/${BOOT_FILE_LIST}
			fi
		done
		cat ${SCRIPT_DIR}/${BOOT_FILE_LIST} | tee -a ${LOGFILE}
	fi

	umount /tmp/boot.$$
	rmdir  /tmp/boot.$$
	[ -n "${ERROR_MSG}" ] && echo -e "\n${ERROR_MSG}\n" | tee -a ${LOGFILE}
	set +x
fi
[ "${ERRLEV}" = 0 ] && logger -p info -t $0 "ended successfully"
exit ${ERRLEV}
#MD5SUM=60b19d33dd821c845def1cca6fd4a985  -