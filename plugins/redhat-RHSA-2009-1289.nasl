#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1289. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63890);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2008-2079", "CVE-2008-3963", "CVE-2008-4097", "CVE-2008-4098", "CVE-2008-4456", "CVE-2009-2446");
  script_bugtraq_id(29106, 31081, 31486, 35609);
  script_xref(name:"RHSA", value:"2009:1289");

  script_name(english:"RHEL 5 : mysql (RHSA-2009:1289)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix various security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

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

This update also fixes multiple bugs. Details regarding these bugs can
be found in the Red Hat Enterprise Linux 5.4 Technical Notes. You can
find a link to the Technical Notes in the References section of this
errata.

Note: These updated packages upgrade MySQL to version 5.0.77 to
incorporate numerous upstream bug fixes. Details of these changes are
found in the following MySQL Release Notes:
http://dev.mysql.com/doc/refman/5.0/en/news-5-0-77.html

All MySQL users are advised to upgrade to these updated packages,
which resolve these issues. After installing this update, the MySQL
server daemon (mysqld) will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-3963.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4456.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5.4/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1289.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 79, 134, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1289";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", reference:"mysql-5.0.77-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-bench-5.0.77-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-bench-5.0.77-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-bench-5.0.77-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"mysql-devel-5.0.77-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-server-5.0.77-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-server-5.0.77-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-server-5.0.77-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-test-5.0.77-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-test-5.0.77-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-test-5.0.77-3.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-devel / mysql-server / mysql-test");
  }
}
