#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60940);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2010-3677", "CVE-2010-3678", "CVE-2010-3679", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3683", "CVE-2010-3833", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840");

  script_name(english:"Scientific Linux Security Update : mysql on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The MySQL PolyFromWKB() function did not sanity check Well-Known
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

After installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-52.html"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=4794
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fdbe388"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"mysql-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-bench-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-devel-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-embedded-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-embedded-devel-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-libs-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-server-5.1.52-1.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-test-5.1.52-1.el6_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
