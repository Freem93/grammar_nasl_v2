#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1484 and 
# CentOS Errata and Security Advisory 2009:1484 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43800);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2007-6600", "CVE-2009-0922", "CVE-2009-3230");
  script_bugtraq_id(34090, 36314);
  script_xref(name:"RHSA", value:"2009:1484");

  script_name(english:"CentOS 4 / 5 : postgresql (CESA-2009:1484)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix two security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced object-relational database management system
(DBMS).

It was discovered that the upstream patch for CVE-2007-6600 included
in the Red Hat Security Advisory RHSA-2008:0038 did not include
protection against misuse of the RESET ROLE and RESET SESSION
AUTHORIZATION commands. An authenticated user could use this flaw to
install malicious code that would later execute with superuser
privileges. (CVE-2009-3230)

A flaw was found in the way PostgreSQL handled encoding conversion. A
remote, authenticated user could trigger an encoding conversion
failure, possibly leading to a temporary denial of service. Note: To
exploit this issue, a locale and client encoding for which specific
messages fail to translate must be selected (the availability of these
is determined by an administrator-defined locale setting).
(CVE-2009-0922)

Note: For Red Hat Enterprise Linux 4, this update upgrades PostgreSQL
to version 7.4.26. For Red Hat Enterprise Linux 5, this update
upgrades PostgreSQL to version 8.1.18. Refer to the PostgreSQL Release
Notes for a list of changes :

http://www.postgresql.org/docs/7.4/static/release.html
http://www.postgresql.org/docs/8.1/static/release.html

All PostgreSQL users should upgrade to these updated packages, which
resolve these issues. If the postgresql service is running, it will be
automatically restarted after installing this update."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016183.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?300a48a5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016184.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca6dfcff"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016272.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b560f7b2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016274.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22400c07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-contrib-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-contrib-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-debuginfo-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-debuginfo-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-devel-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-devel-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-docs-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-docs-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-jdbc-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-jdbc-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-libs-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-libs-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-pl-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-pl-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-python-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-python-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-server-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-server-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-tcl-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-tcl-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-test-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-test-7.4.26-1.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"postgresql-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-contrib-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-devel-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-docs-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-libs-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-pl-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-python-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-server-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-tcl-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-test-8.1.18-2.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
