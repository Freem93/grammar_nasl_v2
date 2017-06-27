#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0121. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63404);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2009-4030", "CVE-2012-4452");
  script_osvdb_id(60665);
  script_xref(name:"RHSA", value:"2013:0121");

  script_name(english:"RHEL 5 : mysql (RHSA-2013:0121)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

It was found that the fix for the CVE-2009-4030 issue, a flaw in the
way MySQL checked the paths used as arguments for the DATA DIRECTORY
and INDEX DIRECTORY directives when the 'datadir' option was
configured with a relative path, was incorrectly removed when the
mysql packages in Red Hat Enterprise Linux 5 were updated to version
5.0.95 via RHSA-2012:0127. An authenticated attacker could use this
flaw to bypass the restriction preventing the use of subdirectories of
the MySQL data directory being used as DATA DIRECTORY and INDEX
DIRECTORY paths. This update re-applies the fix for CVE-2009-4030.
(CVE-2012-4452)

Note: If the use of the DATA DIRECTORY and INDEX DIRECTORY directives
were disabled as described in RHSA-2010:0109 (by adding
'symbolic-links=0' to the '[mysqld]' section of the 'my.cnf'
configuration file), users were not vulnerable to this issue.

This issue was discovered by Karel Volny of the Red Hat Quality
Engineering team.

This update also fixes the following bugs :

* Prior to this update, the log file path in the logrotate script did
not behave as expected. As a consequence, the logrotate function
failed to rotate the '/var/log/mysqld.log' file. This update modifies
the logrotate script to allow rotating the mysqld.log file.
(BZ#647223)

* Prior to this update, the mysqld daemon could fail when using the
EXPLAIN flag in prepared statement mode. This update modifies the
underlying code to handle the EXPLAIN flag as expected. (BZ#654000)

* Prior to this update, the mysqld init script could wrongly report
that mysql server startup failed when the server was actually started.
This update modifies the init script to report the status of the
mysqld server as expected. (BZ#703476)

* Prior to this update, the '--enable-profiling' option was by default
disabled. This update enables the profiling feature. (BZ#806365)

All MySQL users are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. After
installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4452.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHSA-2012-0127.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHSA-2010-0109.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0121.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/08");
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
  rhsa = "RHSA-2013:0121";
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
  if (rpm_check(release:"RHEL5", reference:"mysql-5.0.95-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-bench-5.0.95-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-bench-5.0.95-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-bench-5.0.95-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"mysql-debuginfo-5.0.95-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"mysql-devel-5.0.95-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-server-5.0.95-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-server-5.0.95-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-server-5.0.95-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mysql-test-5.0.95-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mysql-test-5.0.95-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mysql-test-5.0.95-3.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-debuginfo / mysql-devel / mysql-server / etc");
  }
}
