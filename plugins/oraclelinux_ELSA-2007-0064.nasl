#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0064 and 
# Oracle Linux Security Advisory ELSA-2007-0064 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67447);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 16:16:26 $");

  script_cve_id("CVE-2006-5540", "CVE-2007-0555");
  script_bugtraq_id(22387);
  script_osvdb_id(30018, 33087);
  script_xref(name:"RHSA", value:"2007:0064");

  script_name(english:"Oracle Linux 3 / 4 : postgresql (ELSA-2007-0064)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0064 :

Updated postgresql packages that fix two security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced Object-Relational database management system
(DBMS).

A flaw was found in the way the PostgreSQL server handles certain
SQL-language functions. An authenticated user could execute a sequence
of commands which could crash the PostgreSQL server or possibly read
from arbitrary memory locations. A user would need to have permissions
to drop and add database tables to be able to exploit this issue
(CVE-2007-0555).

A denial of service flaw was found affecting the PostgreSQL server
running on Red Hat Enterprise Linux 4 systems. An authenticated user
could execute a SQL command which could crash the PostgreSQL server.
(CVE-2006-5540)

Users of PostgreSQL should upgrade to these updated packages
containing PostgreSQL version 7.4.16 or 7.3.18, which correct these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-February/000047.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-March/000096.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/21");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-7.3.18-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-contrib-7.3.18-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-devel-7.3.18-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-docs-7.3.18-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-jdbc-7.3.18-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-libs-7.3.18-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-pl-7.3.18-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-python-7.3.18-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-server-7.3.18-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-tcl-7.3.18-1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"rh-postgresql-test-7.3.18-1")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-contrib-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-contrib-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-devel-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-devel-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-docs-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-docs-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-jdbc-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-jdbc-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-libs-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-libs-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-pl-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-pl-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-python-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-python-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-server-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-server-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-tcl-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-tcl-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-test-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-test-7.4.16-1.RHEL4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
