#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0164 and 
# Oracle Linux Security Advisory ELSA-2011-0164 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68184);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 16:53:48 $");

  script_cve_id("CVE-2010-3677", "CVE-2010-3678", "CVE-2010-3679", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3683", "CVE-2010-3833", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840");
  script_bugtraq_id(42596, 42598, 42599, 42625, 42633, 42638, 42646, 43676);
  script_xref(name:"RHSA", value:"2011:0164");

  script_name(english:"Oracle Linux 6 : mysql (ELSA-2011-0164)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0164 :

Updated mysql packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

The MySQL PolyFromWKB() function did not sanity check Well-Known
Binary (WKB) data, which could allow a remote, authenticated attacker
to crash mysqld. (CVE-2010-3840)

A flaw in the way MySQL processed certain JOIN queries could allow a
remote, authenticated attacker to cause excessive CPU use (up to
100%), if a stored procedure contained JOIN queries, and that
procedure was executed twice in sequence. (CVE-2010-3839)

A flaw in the way MySQL processed queries that provide a mixture of
numeric and longblob data types to the LEAST or GREATEST function,
could allow a remote, authenticated attacker to crash mysqld.
(CVE-2010-3838)

A flaw in the way MySQL processed PREPARE statements containing both
GROUP_CONCAT and the WITH ROLLUP modifier could allow a remote,
authenticated attacker to crash mysqld. (CVE-2010-3837)

MySQL did not properly pre-evaluate LIKE arguments in view prepare
mode, possibly allowing a remote, authenticated attacker to crash
mysqld. (CVE-2010-3836)

A flaw in the way MySQL processed statements that assign a value to a
user-defined variable and that also contain a logical value evaluation
could allow a remote, authenticated attacker to crash mysqld.
(CVE-2010-3835)

A flaw in the way MySQL evaluated the arguments of extreme-value
functions, such as LEAST and GREATEST, could allow a remote,
authenticated attacker to crash mysqld. (CVE-2010-3833)

A flaw in the way MySQL handled LOAD DATA INFILE requests allowed
MySQL to send OK packets even when there were errors. (CVE-2010-3683)

A flaw in the way MySQL processed EXPLAIN statements for some complex
SELECT queries could allow a remote, authenticated attacker to crash
mysqld. (CVE-2010-3682)

A flaw in the way MySQL processed certain alternating READ requests
provided by HANDLER statements could allow a remote, authenticated
attacker to crash mysqld. (CVE-2010-3681)

A flaw in the way MySQL processed CREATE TEMPORARY TABLE statements
that define NULL columns when using the InnoDB storage engine, could
allow a remote, authenticated attacker to crash mysqld.
(CVE-2010-3680)

A flaw in the way MySQL processed certain values provided to the
BINLOG statement caused MySQL to read unassigned memory. A remote,
authenticated attacker could possibly use this flaw to crash mysqld.
(CVE-2010-3679)

A flaw in the way MySQL processed SQL queries containing IN or CASE
statements, when a NULL argument was provided as one of the arguments
to the query, could allow a remote, authenticated attacker to crash
mysqld. (CVE-2010-3678)

A flaw in the way MySQL processed JOIN queries that attempt to
retrieve data from a unique SET column could allow a remote,
authenticated attacker to crash mysqld. (CVE-2010-3677)

Note: CVE-2010-3840, CVE-2010-3838, CVE-2010-3837, CVE-2010-3835,
CVE-2010-3833, CVE-2010-3682, CVE-2010-3681, CVE-2010-3680,
CVE-2010-3678, and CVE-2010-3677 only cause a temporary denial of
service, as mysqld was automatically restarted after each crash.

These updated packages upgrade MySQL to version 5.1.52. Refer to the
MySQL release notes for a full list of changes :

http://dev.mysql.com/doc/refman/5.1/en/news-5-1-52.html

All MySQL users should upgrade to these updated packages, which
correct these issues. After installing this update, the MySQL server
daemon (mysqld) will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001871.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"mysql-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-bench-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-devel-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-embedded-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-embedded-devel-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-libs-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-server-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"mysql-test-5.1.52-1.el6_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-devel / mysql-embedded / etc");
}
