#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0038 and 
# Oracle Linux Security Advisory ELSA-2008-0038 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67638);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:49 $");

  script_cve_id("CVE-2007-3278", "CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");
  script_bugtraq_id(27163);
  script_osvdb_id(40899);
  script_xref(name:"RHSA", value:"2008:0038");

  script_name(english:"Oracle Linux 4 / 5 : postgresql (ELSA-2008-0038)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0038 :

Updated postgresql packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced Object-Relational database management system
(DBMS). The postgresql packages include the client programs and
libraries needed to access a PostgreSQL DBMS server.

Will Drewry discovered multiple flaws in PostgreSQL's regular
expression engine. An authenticated attacker could use these flaws to
cause a denial of service by causing the PostgreSQL server to crash,
enter an infinite loop, or use extensive CPU and memory resources
while processing queries containing specially crafted regular
expressions. Applications that accept regular expressions from
untrusted sources may expose this problem to unauthorized attackers.
(CVE-2007-4769, CVE-2007-4772, CVE-2007-6067)

A privilege escalation flaw was discovered in PostgreSQL. An
authenticated attacker could create an index function that would be
executed with administrator privileges during database maintenance
tasks, such as database vacuuming. (CVE-2007-6600)

A privilege escalation flaw was discovered in PostgreSQL's Database
Link library (dblink). An authenticated attacker could use dblink to
possibly escalate privileges on systems with 'trust' or 'ident'
authentication configured. Please note that dblink functionality is
not enabled by default, and can only by enabled by a database
administrator on systems with the postgresql-contrib package
installed. (CVE-2007-3278, CVE-2007-6601)

All postgresql users should upgrade to these updated packages, which
include PostgreSQL 7.4.19 and 8.1.11, and resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-January/000480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-January/000484.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189, 264, 287, 399);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-contrib-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-contrib-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-devel-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-devel-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-docs-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-docs-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-jdbc-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-jdbc-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-libs-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-libs-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-pl-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-pl-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-python-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-python-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-server-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-server-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-tcl-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-tcl-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"postgresql-test-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"postgresql-test-7.4.19-1.el4_6.1")) flag++;

if (rpm_check(release:"EL5", reference:"postgresql-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-contrib-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-devel-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-docs-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-libs-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-pl-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-python-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-server-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-tcl-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql-test-8.1.11-1.el5_1.1")) flag++;


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
