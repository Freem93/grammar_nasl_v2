#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:433. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18408);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:55:18 $");

  script_cve_id("CVE-2005-1409", "CVE-2005-1410");
  script_osvdb_id(16323, 16324);
  script_xref(name:"RHSA", value:"2005:433");

  script_name(english:"RHEL 3 / 4 : postgresql (RHSA-2005:433)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix several security vulnerabilities
and risks of data loss are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced Object-Relational database management system
(DBMS) that supports almost all SQL constructs (including
transactions, subselects and user-defined types and functions).

The PostgreSQL community discovered two distinct errors in initial
system catalog entries that could allow authorized database users to
crash the database and possibly escalate their privileges. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
names CVE-2005-1409 and CVE-2005-1410 to these issues.

Although installing this update will protect new (freshly initdb'd)
database installations from these errors, administrators MUST TAKE
MANUAL ACTION to repair the errors in pre-existing databases. The
appropriate procedures are explained at
http://www.postgresql.org/docs/8.0/static/release-7-4-8.html for Red
Hat Enterprise Linux 4 users, or
http://www.postgresql.org/docs/8.0/static/release-7-3-10.html for Red
Hat Enterprise Linux 3 users.

This update corrects several problems that might occur while trying to
upgrade a Red Hat Enterprise Linux 3 installation (containing
rh-postgresql packages) to Red Hat Enterprise Linux 4 (containing
postgresql packages). These updated packages correctly supersede the
rh-postgresql packages.

The original release of Red Hat Enterprise Linux 4 failed to
initialize the database correctly if started for the first time with
SELinux in enforcement mode. This update corrects that problem.

If you already have a nonfunctional database in place, shut down the
postgresql service if running, install this update, then do 'sudo rm
-rf /var/lib/pgsql/data' before restarting the postgresql service.

This update also solves the problem that the PostgreSQL server might
fail to restart after a system reboot, due to a stale lockfile.

This update also corrects a problem with wrong error messages in
libpq, the postgresql client library. The library would formerly
report kernel error messages incorrectly when the locale setting was
not C.

This update also includes fixes for several other errors, including
two race conditions that could result in apparent data inconsistency
or actual data loss.

All users of PostgreSQL are advised to upgrade to these updated
packages and to apply the recommended manual corrections to existing
databases."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1409.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1410.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-433.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:433";
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
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-7.3.10-1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-contrib-7.3.10-1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-devel-7.3.10-1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-docs-7.3.10-1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-jdbc-7.3.10-1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-libs-7.3.10-1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-pl-7.3.10-1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-python-7.3.10-1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-server-7.3.10-1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-tcl-7.3.10-1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-test-7.3.10-1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-7.4.8-1.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-contrib-7.4.8-1.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-devel-7.4.8-1.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-docs-7.4.8-1.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-jdbc-7.4.8-1.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-libs-7.4.8-1.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-pl-7.4.8-1.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-python-7.4.8-1.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-server-7.4.8-1.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-tcl-7.4.8-1.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-test-7.4.8-1.RHEL4.1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
  }
}
