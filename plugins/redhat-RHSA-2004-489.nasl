#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:489. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16016);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 17:55:16 $");

  script_cve_id("CVE-2004-0977");
  script_osvdb_id(10941);
  script_xref(name:"RHSA", value:"2004:489");

  script_name(english:"RHEL 3 : rh-postgresql (RHSA-2004:489)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rh-postgresql packages that fix various bugs are now
available.

PostgreSQL is an advanced Object-Relational database management system
(DBMS) that supports almost all SQL constructs (including
transactions, subselects, and user-defined types and functions).

Trustix has identified improper temporary file usage in the
make_oidjoins_check script. It is possible that an attacker could
overwrite arbitrary file contents as the user running the
make_oidjoins_check script. This script has been removed from the RPM
file since it has no use to ordinary users. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2004-0977 to this issue.

Additionally, the following non-security issues have been addressed :

  - Fixed a low probability risk for loss of recently
    committed transactions.

  - Fixed a low probability risk for loss of older data due
    to failure to update transaction status.

  - A lock file problem that sometimes prevented automatic
    restart after a system crash has been fixed.

All users of rh-postgresql should upgrade to these updated packages,
which resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0977.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-489.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:489";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-7.3.8-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-contrib-7.3.8-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-devel-7.3.8-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-docs-7.3.8-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-jdbc-7.3.8-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-libs-7.3.8-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-pl-7.3.8-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-python-7.3.8-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-server-7.3.8-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-tcl-7.3.8-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-test-7.3.8-2")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rh-postgresql / rh-postgresql-contrib / rh-postgresql-devel / etc");
  }
}
