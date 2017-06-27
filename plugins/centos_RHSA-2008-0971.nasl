#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0971 and 
# CentOS Errata and Security Advisory 2008:0971 respectively.
#

include("compat.inc");

if (description)
{
  script_id(37176);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2008-4309");
  script_bugtraq_id(32020);
  script_xref(name:"RHSA", value:"2008:0971");

  script_name(english:"CentOS 3 / 4 / 5 : net-snmp (CESA-2008:0971)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix a security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Simple Network Management Protocol (SNMP) is a protocol used for
network management.

A denial-of-service flaw was found in the way Net-SNMP processes SNMP
GETBULK requests. A remote attacker who issued a specially crafted
request could cause the snmpd server to crash. (CVE-2008-4309)

Note: An attacker must have read access to the SNMP server in order to
exploit this flaw. In the default configuration, the community name
'public' grants read-only access. In production deployments, it is
recommended to change this default community name.

All users of net-snmp should upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015365.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edd7d5dd"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015366.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ec7fd58"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015367.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42782a4d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015368.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f96daf13"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015385.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ae25ada"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015386.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?46228385"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"net-snmp-5.0.9-2.30E.25")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-devel-5.0.9-2.30E.25")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-libs-5.0.9-2.30E.25")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-perl-5.0.9-2.30E.25")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-utils-5.0.9-2.30E.25")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-5.1.2-13.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-devel-5.1.2-13.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-libs-5.1.2-13.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-perl-5.1.2-13.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-utils-5.1.2-13.c4.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"net-snmp-5.3.1-24.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-devel-5.3.1-24.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-libs-5.3.1-24.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-perl-5.3.1-24.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-utils-5.3.1-24.el5_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
