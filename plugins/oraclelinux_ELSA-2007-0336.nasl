#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0336 and 
# Oracle Linux Security Advisory ELSA-2007-0336 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67488);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:16:27 $");

  script_cve_id("CVE-2007-2138");
  script_osvdb_id(34903);
  script_xref(name:"RHSA", value:"2007:0336");

  script_name(english:"Oracle Linux 3 / 4 / 5 : postgresql (ELSA-2007-0336)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0336 :

Updated postgresql packages that fix several security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced Object-Relational database management system
(DBMS).

A flaw was found in the way PostgreSQL allows authenticated users to
execute security-definer functions. It was possible for an
unprivileged user to execute arbitrary code with the privileges of the
security-definer function. (CVE-2007-2138)

Users of PostgreSQL should upgrade to these updated packages
containing PostgreSQL version 8.1.9, 7.4.17, and 7.3.19 which corrects
this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000229.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-May/000126.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-May/000127.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rh-postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-contrib-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-contrib-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-devel-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-devel-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-docs-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-docs-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-jdbc-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-jdbc-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-libs-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-libs-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-pl-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-pl-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-python-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-python-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-server-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-server-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-tcl-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-tcl-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"rh-postgresql-test-7.3.19-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-test-7.3.19-1")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-contrib-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-contrib-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-devel-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-devel-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-docs-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-docs-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-jdbc-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-jdbc-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-libs-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-libs-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-pl-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-pl-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-python-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-python-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-server-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-server-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-tcl-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-tcl-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-test-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-test-7.4.17-1.RHEL4.1")) flag++;

if (rpm_check(release:"EL5", reference:"postgresql-8.1.9-1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-contrib-8.1.9-1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-devel-8.1.9-1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-docs-8.1.9-1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-libs-8.1.9-1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-pl-8.1.9-1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-python-8.1.9-1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-server-8.1.9-1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-tcl-8.1.9-1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-test-8.1.9-1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
