#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60655);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2008-2079", "CVE-2008-3963", "CVE-2008-4456", "CVE-2009-2446");

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
"CVE-2008-2079 mysql: privilege escalation via DATA/INDEX DIRECTORY
directives

CVE-2008-3963 MySQL: Using an empty binary value leads to server crash

CVE-2008-4456 mysql: mysql command line client XSS flaw

CVE-2008-3963 MySQL: Using an empty binary value leads to server crash

CVE-2009-2446 MySQL: Format string vulnerability by manipulation with
database instances (crash)

MySQL did not correctly check directories used as arguments for the
DATA DIRECTORY and INDEX DIRECTORY directives. Using this flaw, an
authenticated attacker could elevate their access privileges to tables
created by other database users. Note: This attack does not work on
existing tables. An attacker can only elevate their access to another
user's tables as the tables are created. As well, the names of these
created tables need to be predicted correctly for this attack to
succeed. (CVE-2008-2079)

A flaw was found in the way MySQL handles an empty bit-string literal.
A remote, authenticated attacker could crash the MySQL server daemon
(mysqld) if they used an empty bit-string literal in a SQL statement.
This issue only caused a temporary denial of service, as the MySQL
daemon was automatically restarted after the crash. (CVE-2008-3963)

An insufficient HTML entities quoting flaw was found in the mysql
command line client's HTML output mode. If an attacker was able to
inject arbitrary HTML tags into data stored in a MySQL database, which
was later retrieved using the mysql command line client and its HTML
output mode, they could perform a cross-site scripting (XSS) attack
against victims viewing the HTML output in a web browser.
(CVE-2008-4456)

Multiple format string flaws were found in the way the MySQL server
logs user commands when creating and deleting databases. A remote,
authenticated attacker with permissions to CREATE and DROP databases
could use these flaws to formulate a specifically-crafted SQL command
that would cause a temporary denial of service (open connections to
mysqld are terminated). (CVE-2009-2446)

Note: To exploit the CVE-2009-2446 flaws, the general query log (the
mysqld '--log' command line option or the 'log' option in
'/etc/my.cnf') must be enabled. This logging is not enabled by
default.

After installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0909&L=scientific-linux-errata&T=0&P=1324
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c14422c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cwe_id(79, 134, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"mysql-5.0.77-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-bench-5.0.77-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-connector-odbc-3.51.26r1127-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-devel-5.0.77-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-server-5.0.77-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-test-5.0.77-3.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
