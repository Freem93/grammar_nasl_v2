#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60451);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2006-3469", "CVE-2006-4031", "CVE-2007-2691", "CVE-2008-2079");

  script_name(english:"Scientific Linux Security Update : mysql on SL4.x i386/x86_64");
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
"MySQL did not correctly check directories used as arguments for the
DATA DIRECTORY and INDEX DIRECTORY directives. Using this flaw, an
authenticated attacker could elevate their access privileges to tables
created by other database users. Note: this attack does not work on
existing tables. An attacker can only elevate their access to another
user's tables as the tables are created. As well, the names of these
created tables need to be predicted correctly for this attack to
succeed. (CVE-2008-2079)

MySQL did not require the 'DROP' privilege for 'RENAME TABLE'
statements. An authenticated user could use this flaw to rename
arbitrary tables. (CVE-2007-2691)

MySQL allowed an authenticated user to access a table through a
previously created MERGE table, even after the user's privileges were
revoked from the original table, which might violate intended security
policy. This is addressed by allowing the MERGE storage engine to be
disabled, which can be done by running mysqld with the '--skip-merge'
option. (CVE-2006-4031)

A flaw in MySQL allowed an authenticated user to cause the MySQL
daemon to crash via crafted SQL queries. This only caused a temporary
denial of service, as the MySQL daemon is automatically restarted
after the crash. (CVE-2006-3469)

As well, these updated packages fix the following bugs :

  - in the previous mysql packages, if a column name was
    referenced more than once in an 'ORDER BY' section of a
    query, a segmentation fault occurred.

  - when MySQL failed to start, the init script returned a
    successful (0) exit code. When using the Red Hat Cluster
    Suite, this may have caused cluster services to report a
    successful start, even when MySQL failed to start. In
    these updated packages, the init script returns the
    correct exit codes, which resolves this issue.

  - it was possible to use the mysqld_safe command to
    specify invalid port numbers (higher than 65536),
    causing invalid ports to be created, and, in some cases,
    a 'port number definition: unsigned short' error. In
    these updated packages, when an invalid port number is
    specified, the default port number is used.

  - when setting 'myisam_repair_threads > 1', any repair set
    the index cardinality to '1', regardless of the table
    size.

  - the MySQL init script no longer runs 'chmod -R' on the
    entire database directory tree during every startup.

  - when running 'mysqldump' with the MySQL 4.0
    compatibility mode option, '--compatible=mysql40',
    mysqldump created dumps that omitted the
    'auto_increment' field.

As well, the MySQL init script now uses more reliable methods for
determining parameters, such as the data directory location.

Note: these updated packages upgrade MySQL to version 4.1.22. For a
full list of bug fixes and enhancements, refer to the MySQL release
notes: http://dev.mysql.com/doc/refman/4.1/en/news-4-1-22.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/4.1/en/news-4-1-22.html"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0807&L=scientific-linux-errata&T=0&P=2861
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f4cdd75"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/24");
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
if (rpm_check(release:"SL4", reference:"mysql-4.1.22-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"mysql-bench-4.1.22-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"mysql-devel-4.1.22-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"mysql-server-4.1.22-2.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
