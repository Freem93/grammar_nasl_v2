#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0876 and 
# CentOS Errata and Security Advisory 2012:0876 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59927);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/03/07 21:05:18 $");

  script_cve_id("CVE-2012-2141");
  script_bugtraq_id(53255);
  script_osvdb_id(81636);
  script_xref(name:"RHSA", value:"2012:0876");

  script_name(english:"CentOS 6 : net-snmp (CESA-2012:0876)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix one security issue and multiple
bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The net-snmp packages provide various libraries and tools for the
Simple Network Management Protocol (SNMP), including an SNMP library,
an extensible agent, tools for requesting or setting information from
SNMP agents, tools for generating and handling SNMP traps, a version
of the netstat command which uses SNMP, and a Tk/Perl Management
Information Base (MIB) browser.

An array index error, leading to an out-of-bounds buffer read flaw,
was found in the way the net-snmp agent looked up entries in the
extension table. A remote attacker with read privileges to a
Management Information Base (MIB) subtree handled by the 'extend'
directive (in '/etc/snmp/snmpd.conf') could use this flaw to crash
snmpd via a crafted SNMP GET request. (CVE-2012-2141)

These updated net-snmp packages also include numerous bug fixes. Space
precludes documenting all of these changes in this advisory. Users are
directed to the Red Hat Enterprise Linux 6.3 Technical Notes for
information on the most significant of these changes.

All users of net-snmp are advised to upgrade to these updated
packages, which contain backported patches to resolve these issues.
After installing the update, the snmpd and snmptrapd daemons will be
restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018717.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9fa65db"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"net-snmp-5.5-41.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-devel-5.5-41.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-libs-5.5-41.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-perl-5.5-41.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-python-5.5-41.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-utils-5.5-41.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
