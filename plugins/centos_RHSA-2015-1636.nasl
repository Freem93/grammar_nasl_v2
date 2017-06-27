#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1636 and 
# CentOS Errata and Security Advisory 2015:1636 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85464);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/08/21 13:26:45 $");

  script_cve_id("CVE-2015-5621");
  script_osvdb_id(121026);
  script_xref(name:"RHSA", value:"2015:1636");

  script_name(english:"CentOS 6 / 7 : net-snmp (CESA-2015:1636)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix one security issue are now
available for Red Hat Enterprise Linux 6 and 7.

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

It was discovered that the snmp_pdu_parse() function could leave
incompletely parsed varBind variables in the list of variables. A
remote, unauthenticated attacker could use this flaw to crash snmpd
or, potentially, execute arbitrary code on the system with the
privileges of the user running snmpd. (CVE-2015-5621)

Red Hat would like to thank Qinghao Tang of QIHU 360 company, China
for reporting this issue.

All net-snmp users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-August/021335.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e795440"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-August/021338.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cbe7bd4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-agent-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/18");
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
if (rpm_check(release:"CentOS-6", reference:"net-snmp-5.5-54.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-devel-5.5-54.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-libs-5.5-54.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-perl-5.5-54.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-python-5.5-54.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"net-snmp-utils-5.5-54.el6_7.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-agent-libs-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-devel-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-gui-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-libs-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-perl-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-python-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-sysvinit-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-utils-5.7.2-20.el7_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
