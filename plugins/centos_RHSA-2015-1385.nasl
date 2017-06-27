#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1385 and 
# CentOS Errata and Security Advisory 2015:1385 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85016);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/07/28 16:58:13 $");

  script_cve_id("CVE-2014-3565");
  script_bugtraq_id(69477);
  script_osvdb_id(110884);
  script_xref(name:"RHSA", value:"2015:1385");

  script_name(english:"CentOS 6 : net-snmp (CESA-2015:1385)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The net-snmp packages provide various libraries and tools for the
Simple Network Management Protocol (SNMP), including an SNMP library,
an extensible agent, tools for requesting or setting information from
SNMP agents, tools for generating and handling SNMP traps, a version
of the netstat command which uses SNMP, and a Tk/Perl Management
Information Base (MIB) browser.

A denial of service flaw was found in the way snmptrapd handled
certain SNMP traps when started with the '-OQ' option. If an attacker
sent an SNMP trap containing a variable with a NULL type where an
integer variable type was expected, it would cause snmptrapd to crash.
(CVE-2014-3565)

This update also fixes the following bugs :

* The HOST-RESOURCES-MIB::hrSystemProcesses object was not implemented
because parts of the HOST-RESOURCES-MIB module were rewritten in an
earlier version of net-snmp. Consequently,
HOST-RESOURCES-MIB::hrSystemProcesses did not provide information on
the number of currently loaded or running processes. With this update,
HOST-RESOURCES-MIB::hrSystemProcesses has been implemented, and the
net-snmp daemon reports as expected. (BZ#1134335)

* The Net-SNMP agent daemon, snmpd, reloaded the system ARP table
every 60 seconds. As a consequence, snmpd could cause a short CPU
usage spike on busy systems with a large APR table. With this update,
snmpd does not reload the full ARP table periodically, but monitors
the table changes using a netlink socket. (BZ#789500)

* Previously, snmpd used an invalid pointer to the current time when
periodically checking certain conditions specified by the 'monitor'
option in the /etc/snmpd/snmpd.conf file. Consequently, snmpd
terminated unexpectedly on start with a segmentation fault if a
certain entry with the 'monitor' option was used. Now, snmpd
initializes the correct pointer to the current time, and snmpd no
longer crashes on start. (BZ#1050970)

* Previously, snmpd expected 8-bit network interface indices when
processing HOST-RESOURCES-MIB::hrDeviceTable. If an interface index of
a local network interface was larger than 30,000 items, snmpd could
terminate unexpectedly due to accessing invalid memory. Now,
processing of all network sizes is enabled, and snmpd no longer
crashes in the described situation. (BZ#1195547)

* The snmpdtrapd service incorrectly checked for errors when
forwarding a trap with a RequestID value of 0, and logged 'Forward
failed' even though the trap was successfully forwarded. This update
fixes snmptrapd checks and the aforementioned message is now logged
only when appropriate. (BZ#1146948)

* Previously, snmpd ignored the value of the 'storageUseNFS' option in
the /etc/snmpd/snmpd.conf file. As a consequence, NFS drivers were
shown as 'Network Disks', even though 'storageUseNFS' was set to '2'
to report them as 'Fixed Disks' in HOST-RESOURCES-MIB::hrStorageTable.
With this update, snmpd takes the 'storageUseNFS' option value into
account, and 'Fixed Disks' NFS drives are reported correctly.
(BZ#1125793)

* Previously, the Net-SNMP python binding used an incorrect size (8
bytes instead of 4) for variables of IPADDRESS type. Consequently,
applications that were using Net-SNMP Python bindings could send
malformed SNMP messages. With this update, the bindings now use 4
bytes for variables with IPADRESS type, and only valid SNMP messages
are sent. (BZ#1100099)

* Previously, the snmpd service did not cut values in
HOST-RESOURCES-MIB::hrStorageTable to signed 32-bit integers, as
required by SNMP standards, and provided the values as unsigned
integers. As a consequence, the HOST-RESOURCES-MIB::hrStorageTable
implementation did not conform to RFC 2790. The values are now cut to
32-bit signed integers, and snmpd is therefore standard compliant.
(BZ#1104293)

Users of net-snmp are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-July/002025.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3da073e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-5.5-54.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-devel-5.5-54.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-libs-5.5-54.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-perl-5.5-54.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-python-5.5-54.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-utils-5.5-54.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
