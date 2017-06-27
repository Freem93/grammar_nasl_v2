#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1155 and 
# CentOS Errata and Security Advisory 2007:1155 respectively.
#

include("compat.inc");

if (description)
{
  script_id(29731);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-5925", "CVE-2007-5969");
  script_bugtraq_id(26353, 26765);
  script_osvdb_id(51171);
  script_xref(name:"RHSA", value:"2007:1155");

  script_name(english:"CentOS 4 / 5 : mysql (CESA-2007:1155)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld),
and many different client programs and libraries.

A flaw was found in a way MySQL handled symbolic links when database
tables were created with explicit 'DATA' and 'INDEX DIRECTORY'
options. An authenticated user could create a table that would
overwrite tables in other databases, causing destruction of data or
allowing the user to elevate privileges. (CVE-2007-5969)

A flaw was found in a way MySQL's InnoDB engine handled spatial
indexes. An authenticated user could create a table with spatial
indexes, which are not supported by the InnoDB engine, that would
cause the mysql daemon to crash when used. This issue only causes a
temporary denial of service, as the mysql daemon will be automatically
restarted after the crash. (CVE-2007-5925)

All mysql users are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014519.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fad74482"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014524.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04d4f510"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014525.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a99d1074"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014537.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e02c48a9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014538.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e30be283"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"mysql-4.1.20-3.RHEL4.1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"mysql-4.1.20-3.RHEL4.1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"mysql-4.1.20-3.RHEL4.1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"mysql-bench-4.1.20-3.RHEL4.1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"mysql-bench-4.1.20-3.RHEL4.1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"mysql-bench-4.1.20-3.RHEL4.1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"mysql-devel-4.1.20-3.RHEL4.1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"mysql-devel-4.1.20-3.RHEL4.1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"mysql-devel-4.1.20-3.RHEL4.1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"mysql-server-4.1.20-3.RHEL4.1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"mysql-server-4.1.20-3.RHEL4.1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"mysql-server-4.1.20-3.RHEL4.1.el4_6.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"mysql-5.0.22-2.2.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-bench-5.0.22-2.2.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-devel-5.0.22-2.2.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-server-5.0.22-2.2.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-test-5.0.22-2.2.el5_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
