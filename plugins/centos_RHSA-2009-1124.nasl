#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1124 and 
# CentOS Errata and Security Advisory 2009:1124 respectively.
#

include("compat.inc");

if (description)
{
  script_id(39523);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:43:06 $");

  script_cve_id("CVE-2009-1887");
  script_osvdb_id(56459);
  script_xref(name:"RHSA", value:"2009:1124");

  script_name(english:"CentOS 3 : net-snmp (CESA-2009:1124)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix a security issue are now available
for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Simple Network Management Protocol (SNMP) is a protocol used for
network management.

A divide-by-zero flaw was discovered in the snmpd daemon. A remote
attacker could issue a specially crafted GETBULK request that could
crash the snmpd daemon. (CVE-2009-1887)

Note: An attacker must have read access to the SNMP server in order to
exploit this flaw. In the default configuration, the community name
'public' grants read-only access. In production deployments, it is
recommended to change this default community name.

All net-snmp users should upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
update, the snmpd and snmptrapd daemons will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/015999.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2339a566"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/016000.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efcddda1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"net-snmp-5.0.9-2.30E.28")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"net-snmp-5.0.9-2.30E.28")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"net-snmp-devel-5.0.9-2.30E.28")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"net-snmp-devel-5.0.9-2.30E.28")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"net-snmp-libs-5.0.9-2.30E.28")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"net-snmp-libs-5.0.9-2.30E.28")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"net-snmp-perl-5.0.9-2.30E.28")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"net-snmp-perl-5.0.9-2.30E.28")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"net-snmp-utils-5.0.9-2.30E.28")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"net-snmp-utils-5.0.9-2.30E.28")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
