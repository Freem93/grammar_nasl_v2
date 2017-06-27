#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0768. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33585);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2006-3469", "CVE-2006-4031", "CVE-2007-2691", "CVE-2008-2079");
  script_bugtraq_id(19279, 24016, 29106);
  script_osvdb_id(27703);
  script_xref(name:"RHSA", value:"2008:0768");

  script_name(english:"RHEL 4 : mysql (RHSA-2008:0768)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix various security issues, several bugs,
and add an enhancement are now available for Red Hat Enterprise Linux
4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld),
and many different client programs and libraries.

MySQL did not correctly check directories used as arguments for the
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

* in the previous mysql packages, if a column name was referenced more
than once in an 'ORDER BY' section of a query, a segmentation fault
occurred.

* when MySQL failed to start, the init script returned a successful
(0) exit code. When using the Red Hat Cluster Suite, this may have
caused cluster services to report a successful start, even when MySQL
failed to start. In these updated packages, the init script returns
the correct exit codes, which resolves this issue.

* it was possible to use the mysqld_safe command to specify invalid
port numbers (higher than 65536), causing invalid ports to be created,
and, in some cases, a 'port number definition: unsigned short' error.
In these updated packages, when an invalid port number is specified,
the default port number is used.

* when setting 'myisam_repair_threads > 1', any repair set the index
cardinality to '1', regardless of the table size.

* the MySQL init script no longer runs 'chmod -R' on the entire
database directory tree during every startup.

* when running 'mysqldump' with the MySQL 4.0 compatibility mode
option, '--compatible=mysql40', mysqldump created dumps that omitted
the 'auto_increment' field.

As well, the MySQL init script now uses more reliable methods for
determining parameters, such as the data directory location.

Note: these updated packages upgrade MySQL to version 4.1.22. For a
full list of bug fixes and enhancements, refer to the MySQL release
notes: http://dev.mysql.com/doc/refman/4.1/en/news-4-1-22.html

All mysql users are advised to upgrade to these updated packages,
which resolve these issues and add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-3469.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-4031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2691.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0768.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/25");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0768";
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
  if (rpm_check(release:"RHEL4", reference:"mysql-4.1.22-2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mysql-bench-4.1.22-2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mysql-devel-4.1.22-2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mysql-server-4.1.22-2.el4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-devel / mysql-server");
  }
}
