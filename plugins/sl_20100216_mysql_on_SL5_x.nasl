#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60736);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2008-2079", "CVE-2008-4098", "CVE-2009-4019", "CVE-2009-4028", "CVE-2009-4030");

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
"CVE-2009-4019 mysql: DoS (crash) when comparing GIS items from
subquery and when handling subqueires in WHERE and assigning a SELECT
result to a @variable

CVE-2009-4028 mysql: client SSL certificate verification flaw

CVE-2009-4030 mysql: Incomplete fix for CVE-2008-2079 / CVE-2008-4098

It was discovered that the MySQL client ignored certain SSL
certificate verification errors when connecting to servers. A
man-in-the-middle attacker could use this flaw to trick MySQL clients
into connecting to a spoofed MySQL server. (CVE-2009-4028)

Note: This fix may uncover previously hidden SSL configuration issues,
such as incorrect CA certificates being used by clients or expired
server certificates. This update should be carefully tested in
deployments where SSL connections are used.

A flaw was found in the way MySQL handled SELECT statements with
subqueries in the WHERE clause, that assigned results to a user
variable. A remote, authenticated attacker could use this flaw to
crash the MySQL server daemon (mysqld). This issue only caused a
temporary denial of service, as the MySQL daemon was automatically
restarted after the crash. (CVE-2009-4019)

When the 'datadir' option was configured with a relative path, MySQL
did not properly check paths used as arguments for the DATA DIRECTORY
and INDEX DIRECTORY directives. An authenticated attacker could use
this flaw to bypass the restriction preventing the use of
subdirectories of the MySQL data directory being used as DATA
DIRECTORY and INDEX DIRECTORY paths. (CVE-2009-4030)

Note: Due to the security risks and previous security issues related
to the use of the DATA DIRECTORY and INDEX DIRECTORY directives, users
not depending on this feature should consider disabling it by adding
'symbolic-links=0' to the '[mysqld]' section of the 'my.cnf'
configuration file. In this update, an example of such a configuration
was added to the default 'my.cnf' file.

After installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1002&L=scientific-linux-errata&T=0&P=1164
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7a3955a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 59, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/16");
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
if (rpm_check(release:"SL5", reference:"mysql-5.0.77-4.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-bench-5.0.77-4.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-devel-5.0.77-4.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-server-5.0.77-4.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-test-5.0.77-4.el5_4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
