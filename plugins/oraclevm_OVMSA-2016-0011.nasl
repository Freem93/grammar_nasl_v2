#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0011.
#

include("compat.inc");

if (description)
{
  script_id(88689);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_name(english:"OracleVM 3.3 : sos (OVMSA-2016-0011)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Add vendor, vendor URL info for Oracle Linux [orabug
    17656507] 

  - Direct traceroute to linux.oracle.com (John Haxby)
    [orabug 11713272] 

  - Check oraclelinux-release instead of redhat-release to
    get OS version (John Haxby) [bug 11681869] 

  - Remove RH ftp URL and support email 

  - add sos-oracle-enterprise.patch 

  - Add smartmon plugin (John Haxby) [orabug 17995005] 

  - [sosreport] Report correct final path with --build
    Related: bz1290953

  - [hpasm] Add timeout. Resolves: bz1291828

  - [sosreport] Prepare report in a private subdirectory
    Resolves: bz1290953

  - [ovirt] Collect engine tuneables and domain information.
    Resolves: bz1234226

  - [networking] nmcli status is obtained from the output
    Resolves: bz1206661

  - [cluster] Scrub password from crm_report data. Resolves:
    bz1206581

  - [networking] Use the correct options for nmcli.
    Resolves: bz1206661

  - [mysql] Collect log file by default. Resolves: bz1209442

  - [openshift] Scrub passwords from plugin config files.
    Resolves: bz1203330

  - [tuned] Collect additional configurations files and
    profiles. Resolves: bz1174186

  - [networking] Fix 'ip addr' collection. Resolves:
    bz1209455

  - [networking] test nmcli status before using output
    Resolves: bz1206661

  - [openshift] Scrub passwords from config files. Resolves:
    bz1203330

  - [cluster] Ensure cluster sets 'make' to False when
    calling get_cmd_output_path. Resolves: bz1190723

  - [openshift] Collect additional config files. Resolves:
    bz1166874

  - [activemq] Honour all_logs and get config on RHEL.
    Resolves: bz1165878

  - [policy/redhat] use /tmp as default temporary directory

  - [global] remove dependency on python-six Resolves:
    bz1144525

  - [cluster] Added package luci and fix lockdumps
    capturing. Resolves: bz1171186

  - [puppet] Adding new plugin for puppet Resolves:
    bz1172880

  - [block] parted will use sector units instead of human
    units. Resolves: bz1086537

  - [foreman] Added option to prevent generic resource
    collection with foreman plugin. Remove the plugin
    katello since data collection done by foreman-debug.
    Resolves: bz1135290

  - [global] update el6 to upstream 3.2 release Resolves:
    bz1144525

  - [global] sync 3.2-15.el6 with RHEL-7.1 Resolves:
    bz1144525

  - [mysql] test for boolean values in dbuser and dbpass

  - [mysql] improve handling of dbuser, dbpass and MYSQL_PWD

  - [plugin] limit path names to PC_NAME_MAX

  - [squid] collect files from /var/log/squid

  - [sosreport] log plugin exceptions to a file

  - [ctdb] fix collection of /etc/sysconfig/ctdb

  - [sosreport] fix silent exception handling

  - [sosreport] do not make logging calls after OSError

  - [sosreport] catch OSError exceptions in
    SoSReport.execute

  - [anaconda] make useradd password regex tolerant of
    whitespace

  - [mysql] fix handling of mysql.dbpass option

  - [navicli] catch exceptions if stdin is unreadable

  - [docs] update man page for new options

  - [sosreport] make all utf-8 handling user errors=ignore

  - [kpatch] do not attempt to collect data if kpatch is not
    installed

  - [archive] drop support for Zip archives

  - [sosreport] fix archive permissions regression

  - [tomcat] add support for tomcat7 and default log size
    limits

  - [mysql] obtain database password from the environment

  - [corosync] add postprocessing for corosync-objctl output

  - [ovirt_hosted_engine] fix exception when force-enabled

  - [yum] call rhsm-debug with --no-subscriptions

  - [powerpc] allow PowerPC plugin to run on ppc64le

  - [package] add Obsoletes for sos-plugins-openstack

  - [pam] add pam_tally2 and faillock support

  - [postgresql] obtain db password from the environment

  - [pcp] add Performance Co-Pilot plugin

  - [nfsserver] collect /etc/exports.d

  - [sosreport] handle --compression-type correctly

  - [anaconda] redact passwords in kickstart configurations

  - [haproxy] add new plugin

  - [keepalived] add new plugin

  - [lvm2] set locking_type=0 when calling lvm commands

  - [tuned] add new plugin

  - [cgroups] collect /etc/sysconfig/cgred

  - [plugins] ensure doc text is always displayed for
    plugins

  - [sosreport] fix the distribution version API call

  - [docker] add new plugin

  - [openstack_*] include broken-out openstack plugins

  - [mysql] support MariaDB

  - [openstack] do not collect /var/lib/nova

  - [grub2] collect grub.cfg on UEFI systems

  - [sosreport] handle out-of-space errors gracefully

  - [firewalld] new plugin

  - [networking] collect NetworkManager status

  - [kpatch] new plugin

  - [global] update to upstream 3.2 release

  - [ds] add collection of ds admin server configuration
    Resolves: bz994628

  - [ldap] ensure /etc/openldap/ content is collected
    Resolves: bz994628

  - [plugintools] preserve permissions on directories
    Resolves: bz1069786

  - [plugintools] Fix size limiting in addCopySpecLimit
    Resolves: bz1001600

  - [general] do not collect /var/log/sa Resolves: bz1001600

  - [grub] Fix grub.conf path for grub-1.x versions
    Resolves: bz1076388

  - [ds] Fix logging exception when plugin force-enabled
    Resolves: bz994628

  - [pgsql] backport PGPASSWORD changes from upstream
    Resolves: bz1125998

  - [plugin] backport command timeout support Resolves:
    bz1005703

  - Restrict ldap and ds plugin paths to avoid collecting
    secrets Resolves: bz994628

  - Add certutil output to ldap and ds plugins to summarize
    certs Resolves: bz994628

  - [powerpc] backport plugin from upstream Resolves:
    bz977190

  - [devicemapper] set locking_type=0 when calling lvm2
    commands Resolves: bz1102282

  - [nfsserver] collect 'exportfs -v' Resolves: bz985512

  - [openshift] improve password redaction Resolves:
    bz1039755

  - [openshift] don't collect all of /etc/openshift
    Resolves: bz1039755

  - [mongodb] backport new plugin from upstream

  - [activemq] backport new plugin from upstream

  - [openshift] sync plugin with upstream

  - [plugin] backport collectExtOutputs and addCopySpecs

  - Make OpenShift module collect domain information

  - Add 'gear' option to OpenShift module

  - Add OpenShift module Resolves: bz1039755

  - [plugin] backport addCopySpecLimit tailit parameter
    Resolves: bz1001600

  - [plugintools] preserve permissions on all path
    components Resolves: bz1069786

  - [tomcat] update for tomcat6 and add password filtering
    Resolves: bz1088070

  - [filesys] collect dumpe2fs -h output by default
    Resolves: bz1105629

  - [rpm] reduce number of calls to rpm Resolves: bz1019872

  - Verify fewer packages in rpm plug-in Resolves: bz1019872

  - [bootloader] elide bootloader password Resolves:
    bz1101311

  - [plugin] backport do_path_regex_sub Resolves: bz1101311

  - [networking] do not attempt to read use-gss-proxy
    Resolves: bz1079954

  - [mysql] limit log collection by default Resolves:
    bz1015783

  - [mysql] add optional database dump support Resolves:
    bz1032262

  - [docs] update man pages Resolves: bz1022226

  - [sosreport] log exceptions during Plugin.postproc
    Resolves: bz1020445

  - [distupgrade] elide passwords in kickstart user
    directives Resolves: bz1052344

  - [ipa] add ipa-replica-manage output Resolves: bz1012410

  - [bootloader] Include /etc/yaboot.conf Resolves:
    bz1001941

  - [cluster] collect /sys/fs/gfs2/*/withdraw Resolves:
    bz997174

  - [general] do not collect /var/log/sa Resolves: bz1001600

  - [networking] avoid Cisco cdp paths in /proc and /sys
    Resolves: bz1004936

  - [sar] Handle compressed binary data files better
    Resolves: bz1001600

  - [sar] Add file size limits Resolves: bz1001600

  - [sar] Enable XML data collection Resolves: bz1001600

  - [selinux] pass --input-logs when calling ausearch
    Resolves: bz1032706

  - [printing] fix cups log file size limiting Resolves:
    bz1061529

  - [auditd] fix log size limiting Resolves: bz1061529

  - [hardware] call hardware.py directly instead of invoking
    python Resolves: bz1041770

  - [hpasm] new plugin to collect HP ASM information
    Resolves: bz915115

  - [sos] improve handling of fatal IO errors Resolves:
    bz1085042

  - [bootloader] collect grub.conf for UEFI based systems
    Resolves: bz1076388

  - [ctdb] add plugin to collect Samba CTDB information
    Resolves: bz961041

  - [keepalived] new plugin Resolves: bz1107862

  - [sssd] scrub ldap_default_authtok in sssd plugin
    Resolves: bz1013366

  - [haproxy] new plugin Resolves: bz1107866

  - [gluster] add 'logsize' and 'all_logs' plugin options
    Resolves: bz1002619

  - Fix doRegexSub usage in distupgrade plugin Resolves:
    bz1052344

  - Redact user home directory paths in distupgrade plugin
    Resolves: bz1052344

  - Add distupgrade plugin Resolves: bz1052344

  - Pass a --from parameter when calling crm_report
    Resolves: bz1035774"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-February/000416.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b045540"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sos package.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:sos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"sos-3.2-28.0.1.el6_7.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sos");
}
