#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1289 and 
# CentOS Errata and Security Advisory 2009:1289 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43782);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2008-2079", "CVE-2008-3963", "CVE-2008-4097", "CVE-2008-4098", "CVE-2008-4456", "CVE-2009-2446");
  script_bugtraq_id(29106, 31081, 31486, 35609);
  script_xref(name:"RHSA", value:"2009:1289");

  script_name(english:"CentOS 5 : mysql (CESA-2009:1289)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016143.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41d5097d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016144.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c91589e7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 79, 134, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"mysql-5.0.77-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-bench-5.0.77-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-devel-5.0.77-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-server-5.0.77-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-test-5.0.77-3.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
