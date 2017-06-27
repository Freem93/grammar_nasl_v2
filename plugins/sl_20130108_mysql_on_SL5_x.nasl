#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(63599);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/17 14:07:22 $");

  script_cve_id("CVE-2009-4030", "CVE-2012-4452");

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
"It was found that the fix for the CVE-2009-4030 issue, a flaw in the
way MySQL checked the paths used as arguments for the DATA DIRECTORY
and INDEX DIRECTORY directives when the 'datadir' option was
configured with a relative path, was incorrectly removed when the
mysql packages in Scientific Linux 5 were updated to version 5.0.95
via SLSA-2012:0127. An authenticated attacker could use this flaw to
bypass the restriction preventing the use of subdirectories of the
MySQL data directory being used as DATA DIRECTORY and INDEX DIRECTORY
paths. This update re-applies the fix for CVE-2009-4030.
(CVE-2012-4452)

Note: If the use of the DATA DIRECTORY and INDEX DIRECTORY directives
were disabled as described in SLSA-2010:0109 (by adding
'symbolic-links=0' to the '[mysqld]' section of the 'my.cnf'
configuration file), users were not vulnerable to this issue.

This update also fixes the following bugs :

  - Prior to this update, the log file path in the logrotate
    script did not behave as expected. As a consequence, the
    logrotate function failed to rotate the
    '/var/log/mysqld.log' file. This update modifies the
    logrotate script to allow rotating the mysqld.log file.

  - Prior to this update, the mysqld daemon could fail when
    using the EXPLAIN flag in prepared statement mode. This
    update modifies the underlying code to handle the
    EXPLAIN flag as expected.

  - Prior to this update, the mysqld init script could
    wrongly report that mysql server startup failed when the
    server was actually started. This update modifies the
    init script to report the status of the mysqld server as
    expected.

  - Prior to this update, the '--enable-profiling' option
    was by default disabled. This update enables the
    profiling feature.

After installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=1337
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03523f3c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"mysql-5.0.95-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-bench-5.0.95-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-debuginfo-5.0.95-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-devel-5.0.95-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-server-5.0.95-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-test-5.0.95-3.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
