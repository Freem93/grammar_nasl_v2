#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0110. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44635);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/04 15:51:46 $");

  script_cve_id("CVE-2008-2079", "CVE-2008-4097", "CVE-2008-4098", "CVE-2008-4456", "CVE-2009-2446", "CVE-2009-4030");
  script_bugtraq_id(29106, 31486, 35609, 37075);
  script_xref(name:"RHSA", value:"2010:0110");

  script_name(english:"RHEL 4 : mysql (RHSA-2010:0110)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

Multiple flaws were discovered in the way MySQL handled symbolic links
to tables created using the DATA DIRECTORY and INDEX DIRECTORY
directives in CREATE TABLE statements. An attacker with CREATE and
DROP table privileges and shell access to the database server could
use these flaws to escalate their database privileges, or gain access
to tables created by other database users. (CVE-2008-4098,
CVE-2009-4030)

Note: Due to the security risks and previous security issues related
to the use of the DATA DIRECTORY and INDEX DIRECTORY directives, users
not depending on this feature should consider disabling it by adding
'symbolic-links=0' to the '[mysqld]' section of the 'my.cnf'
configuration file. In this update, an example of such a configuration
was added to the default 'my.cnf' file.

An insufficient HTML entities quoting flaw was found in the mysql
command line client's HTML output mode. If an attacker was able to
inject arbitrary HTML tags into data stored in a MySQL database, which
was later retrieved using the mysql command line client and its HTML
output mode, they could perform a cross-site scripting (XSS) attack
against victims viewing the HTML output in a web browser.
(CVE-2008-4456)

Multiple format string flaws were found in the way the MySQL server
logged user commands when creating and deleting databases. A remote,
authenticated attacker with permissions to CREATE and DROP databases
could use these flaws to formulate a specially crafted SQL command
that would cause a temporary denial of service (open connections to
mysqld are terminated). (CVE-2009-2446)

Note: To exploit the CVE-2009-2446 flaws, the general query log (the
mysqld '--log' command line option or the 'log' option in 'my.cnf')
must be enabled. This logging is not enabled by default.

All MySQL users are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. After
installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4098.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2009-4030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/4.1/en/symbolic-links-to-tables.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0110.html"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0110";
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
  if (rpm_check(release:"RHEL4", reference:"mysql-4.1.22-2.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"mysql-bench-4.1.22-2.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"mysql-devel-4.1.22-2.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"mysql-server-4.1.22-2.el4_8.3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-devel / mysql-server");
  }
}
