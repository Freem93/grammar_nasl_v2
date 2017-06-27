#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0364. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32425);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2006-0903", "CVE-2006-4031", "CVE-2006-4227", "CVE-2006-7232", "CVE-2007-1420", "CVE-2007-2583", "CVE-2007-2691", "CVE-2007-2692", "CVE-2007-3781", "CVE-2007-3782");
  script_bugtraq_id(19279, 19559, 23911, 24011, 24016, 25017);
  script_osvdb_id(27703);
  script_xref(name:"RHSA", value:"2008:0364");

  script_name(english:"RHEL 5 : mysql (RHSA-2008:0364)");
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

This update has been rated as having low security impact by the Red
Hat Security Response Team.

MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld),
and many different client programs and libraries.

MySQL did not require privileges such as 'SELECT' for the source table
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

* a separate counter was used for 'insert delayed' statements, which
caused rows to be discarded. In these updated packages, 'insert
delayed' statements no longer use a separate counter, which resolves
this issue.

* due to a bug in the Native POSIX Thread Library, in certain
situations, 'flush tables' caused a deadlock on tables that had a read
lock. The mysqld daemon had to be killed forcefully. Now,
'COND_refresh' has been replaced with 'COND_global_read_lock', which
resolves this issue.

* mysqld crashed if a query for an unsigned column type contained a
negative value for a 'WHERE [column] NOT IN' subquery.

* in master and slave server situations, specifying 'on duplicate key
update' for 'insert' statements did not update slave servers.

* in the mysql client, empty strings were displayed as 'NULL'. For
example, running 'insert into [table-name] values (' ');' resulted in
a 'NULL' entry being displayed when querying the table using 'select *
from [table-name];'.

* a bug in the optimizer code resulted in certain queries executing
much slower than expected.

* on 64-bit PowerPC architectures, MySQL did not calculate the thread
stack size correctly, which could have caused MySQL to crash when
overly-complex queries were used.

Note: these updated packages upgrade MySQL to version 5.0.45. For a
full list of bug fixes and enhancements, refer to the MySQL release
notes: http://dev.mysql.com/doc/refman/5.0/en/releasenotes-cs-5-0.html

All mysql users are advised to upgrade to these updated packages,
which resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-0903.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-4031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-4227.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-7232.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-1420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2583.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2691.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2692.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3781.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3782.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0364.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 89, 189, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2008:0364";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL5", reference:"mysql-5.0.45-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-bench-5.0.45-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-bench-5.0.45-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-bench-5.0.45-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"mysql-devel-5.0.45-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-server-5.0.45-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-server-5.0.45-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-server-5.0.45-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-test-5.0.45-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-test-5.0.45-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-test-5.0.45-7.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
