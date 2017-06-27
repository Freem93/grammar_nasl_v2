#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60884);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-3677", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3833", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840");

  script_name(english:"Scientific Linux Security Update : mysql on SL5.x i386/x86_64");
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
"It was found that the MySQL PolyFromWKB() function did not sanity
check Well-Known Binary (WKB) data. A remote, authenticated attacker
could use specially crafted WKB data to crash mysqld. This issue only
caused a temporary denial of service, as mysqld was automatically
restarted after the crash. (CVE-2010-3840)

A flaw was found in the way MySQL processed certain JOIN queries. If a
stored procedure contained JOIN queries, and that procedure was
executed twice in sequence, it could cause an infinite loop, leading
to excessive CPU use (up to 100%). A remote, authenticated attacker
could use this flaw to cause a denial of service. (CVE-2010-3839)

A flaw was found in the way MySQL processed queries that provide a
mixture of numeric and longblob data types to the LEAST or GREATEST
function. A remote, authenticated attacker could use this flaw to
crash mysqld. This issue only caused a temporary denial of service, as
mysqld was automatically restarted after the crash. (CVE-2010-3838)

A flaw was found in the way MySQL processed PREPARE statements
containing both GROUP_CONCAT and the WITH ROLLUP modifier. A remote,
authenticated attacker could use this flaw to crash mysqld. This issue
only caused a temporary denial of service, as mysqld was automatically
restarted after the crash. (CVE-2010-3837)

It was found that MySQL did not properly pre-evaluate LIKE arguments
in view prepare mode. A remote, authenticated attacker could possibly
use this flaw to crash mysqld. (CVE-2010-3836)

A flaw was found in the way MySQL processed statements that assign a
value to a user-defined variable and that also contain a logical value
evaluation. A remote, authenticated attacker could use this flaw to
crash mysqld. This issue only caused a temporary denial of service, as
mysqld was automatically restarted after the crash. (CVE-2010-3835)

A flaw was found in the way MySQL evaluated the arguments of
extreme-value functions, such as LEAST and GREATEST. A remote,
authenticated attacker could use this flaw to crash mysqld. This issue
only caused a temporary denial of service, as mysqld was automatically
restarted after the crash. (CVE-2010-3833)

A flaw was found in the way MySQL processed EXPLAIN statements for
some complex SELECT queries. A remote, authenticated attacker could
use this flaw to crash mysqld. This issue only caused a temporary
denial of service, as mysqld was automatically restarted after the
crash. (CVE-2010-3682)

A flaw was found in the way MySQL processed certain alternating READ
requests provided by HANDLER statements. A remote, authenticated
attacker could use this flaw to provide such requests, causing mysqld
to crash. This issue only caused a temporary denial of service, as
mysqld was automatically restarted after the crash. (CVE-2010-3681)

A flaw was found in the way MySQL processed CREATE TEMPORARY TABLE
statements that define NULL columns when using the InnoDB storage
engine. A remote, authenticated attacker could use this flaw to crash
mysqld. This issue only caused a temporary denial of service, as
mysqld was automatically restarted after the crash. (CVE-2010-3680)

A flaw was found in the way MySQL processed JOIN queries that attempt
to retrieve data from a unique SET column. A remote, authenticated
attacker could use this flaw to crash mysqld. This issue only caused a
temporary denial of service, as mysqld was automatically restarted
after the crash. (CVE-2010-3677)

After installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1011&L=scientific-linux-errata&T=0&P=194
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed57bbbe"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"mysql-5.0.77-4.el5_5.4")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-bench-5.0.77-4.el5_5.4")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-devel-5.0.77-4.el5_5.4")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-server-5.0.77-4.el5_5.4")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-test-5.0.77-4.el5_5.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
