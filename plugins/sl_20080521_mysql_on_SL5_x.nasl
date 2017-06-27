#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60406);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2006-0903", "CVE-2006-4031", "CVE-2006-4227", "CVE-2006-7232", "CVE-2007-1420", "CVE-2007-2583", "CVE-2007-2691", "CVE-2007-2692", "CVE-2007-3781", "CVE-2007-3782");

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
"MySQL did not require privileges such as 'SELECT' for the source table
in a 'CREATE TABLE LIKE' statement. An authenticated user could obtain
sensitive information, such as the table structure. (CVE-2007-3781)

A flaw was discovered in MySQL that allowed an authenticated user to
gain update privileges for a table in another database, via a view
that refers to the external table. (CVE-2007-3782)

MySQL did not require the 'DROP' privilege for 'RENAME TABLE'
statements. An authenticated user could use this flaw to rename
arbitrary tables. (CVE-2007-2691)

A flaw was discovered in the mysql_change_db function when returning
from SQL SECURITY INVOKER stored routines. An authenticated user could
use this flaw to gain database privileges. (CVE-2007-2692)

MySQL allowed an authenticated user to bypass logging mechanisms via
SQL queries that contain the NULL character, which were not properly
handled by the mysql_real_query function. (CVE-2006-0903)

MySQL allowed an authenticated user to access a table through a
previously created MERGE table, even after the user's privileges were
revoked from the original table, which might violate intended security
policy. This is addressed by allowing the MERGE storage engine to be
disabled, which can be done by running mysqld with the '--skip-merge'
option. (CVE-2006-4031)

MySQL evaluated arguments in the wrong security context, which allowed
an authenticated user to gain privileges through a routine that had
been made available using 'GRANT EXECUTE'. (CVE-2006-4227)

Multiple flaws in MySQL allowed an authenticated user to cause the
MySQL daemon to crash via crafted SQL queries. This only caused a
temporary denial of service, as the MySQL daemon is automatically
restarted after the crash. (CVE-2006-7232, CVE-2007-1420,
CVE-2007-2583)

As well, these updated packages fix the following bugs :

  - a separate counter was used for 'insert delayed'
    statements, which caused rows to be discarded. In these
    updated packages, 'insert delayed' statements no longer
    use a separate counter, which resolves this issue.

  - due to a bug in the Native POSIX Thread Library, in
    certain situations, 'flush tables' caused a deadlock on
    tables that had a read lock. The mysqld daemon had to be
    killed forcefully. Now, 'COND_refresh' has been replaced
    with 'COND_global_read_lock', which resolves this issue.

  - mysqld crashed if a query for an unsigned column type
    contained a negative value for a 'WHERE [column] NOT IN'
    subquery.

  - in master and slave server situations, specifying 'on
    duplicate key update' for 'insert' statements did not
    update slave servers.

  - in the mysql client, empty strings were displayed as
    'NULL'. For example, running 'insert into [table-name]
    values (' ');' resulted in a 'NULL' entry being
    displayed when querying the table using 'select * from
    [table-name];'.

  - a bug in the optimizer code resulted in certain queries
    executing much slower than expected.

  - on 64-bit PowerPC architectures, MySQL did not calculate
    the thread stack size correctly, which could have caused
    MySQL to crash when overly-complex queries were used.

Note: these updated packages upgrade MySQL to version 5.0.45. For a
full list of bug fixes and enhancements, refer to the MySQL release
notes: http://dev.mysql.com/doc/refman/5.0/en/releasenotes-cs-5-0.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.0/en/releasenotes-cs-5-0.html"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0805&L=scientific-linux-errata&T=0&P=2055
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0dc35d6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cwe_id(20, 89, 189, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
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
if (rpm_check(release:"SL5", reference:"mysql-5.0.45-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-bench-5.0.45-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-devel-5.0.45-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-server-5.0.45-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-test-5.0.45-7.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
