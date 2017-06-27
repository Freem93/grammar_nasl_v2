#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0321 and 
# CentOS Errata and Security Advisory 2014:0321 respectively.
#

include("compat.inc");

if (description)
{
  script_id(73162);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/03/26 10:46:22 $");

  script_cve_id("CVE-2014-2284");
  script_bugtraq_id(65867);
  script_xref(name:"RHSA", value:"2014:0321");

  script_name(english:"CentOS 6 : net-snmp (CESA-2014:0321)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The net-snmp packages provide various libraries and tools for the
Simple Network Management Protocol (SNMP), including an SNMP library,
an extensible agent, tools for requesting or setting information from
SNMP agents, tools for generating and handling SNMP traps, a version
of the netstat command which uses SNMP, and a Tk/Perl Management
Information Base (MIB) browser.

A buffer overflow flaw was found in the way the decode_icmp_msg()
function in the ICMP-MIB implementation processed Internet Control
Message Protocol (ICMP) message statistics reported in the
/proc/net/snmp file. A remote attacker could send a message for each
ICMP message type, which could potentially cause the snmpd service to
crash when processing the /proc/net/snmp file. (CVE-2014-2284)

This update also fixes the following bug :

* The snmpd service parses the /proc/diskstats file to track disk
usage statistics for UCD-DISKIO-MIB::diskIOTable. On systems with a
large number of block devices, /proc/diskstats may be large in size
and parsing it can take a non-trivial amount of CPU time. With this
update, Net-SNMP introduces a new option, 'diskio', in the
/etc/snmp/snmpd.conf file, which can be used to explicitly specify
devices that should be monitored. Only these whitelisted devices are
then reported in UCD-DISKIO-MIB::diskIOTable, thus speeding up snmpd
on systems with numerous block devices. (BZ#990674)

All net-snmp users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the snmpd service will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-March/020224.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5ae4943"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"net-snmp-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-devel-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-libs-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-perl-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-python-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-utils-5.5-49.el6_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
