#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1484. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42064);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2007-6600", "CVE-2009-0922", "CVE-2009-3230");
  script_bugtraq_id(34090, 36314);
  script_xref(name:"RHSA", value:"2009:1484");

  script_name(english:"RHEL 4 / 5 : postgresql (RHSA-2009:1484)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix two security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced object-relational database management system
(DBMS).

It was discovered that the upstream patch for CVE-2007-6600 included
in the Red Hat Security Advisory RHSA-2008:0038 did not include
protection against misuse of the RESET ROLE and RESET SESSION
AUTHORIZATION commands. An authenticated user could use this flaw to
install malicious code that would later execute with superuser
privileges. (CVE-2009-3230)

A flaw was found in the way PostgreSQL handled encoding conversion. A
remote, authenticated user could trigger an encoding conversion
failure, possibly leading to a temporary denial of service. Note: To
exploit this issue, a locale and client encoding for which specific
messages fail to translate must be selected (the availability of these
is determined by an administrator-defined locale setting).
(CVE-2009-0922)

Note: For Red Hat Enterprise Linux 4, this update upgrades PostgreSQL
to version 7.4.26. For Red Hat Enterprise Linux 5, this update
upgrades PostgreSQL to version 8.1.18. Refer to the PostgreSQL Release
Notes for a list of changes :

http://www.postgresql.org/docs/7.4/static/release.html
http://www.postgresql.org/docs/8.1/static/release.html

All PostgreSQL users should upgrade to these updated packages, which
resolve these issues. If the postgresql service is running, it will be
automatically restarted after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0922.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3230.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1484.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264, 399);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1484";
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
  if (rpm_check(release:"RHEL4", reference:"postgresql-7.4.26-1.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-contrib-7.4.26-1.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-devel-7.4.26-1.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-docs-7.4.26-1.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-jdbc-7.4.26-1.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-libs-7.4.26-1.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-pl-7.4.26-1.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-python-7.4.26-1.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-server-7.4.26-1.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-tcl-7.4.26-1.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-test-7.4.26-1.el4_8.1")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-contrib-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-contrib-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-contrib-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"postgresql-devel-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-docs-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-docs-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-docs-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"postgresql-libs-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-pl-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-pl-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-pl-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-python-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-python-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-python-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-server-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-server-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-server-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-tcl-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-tcl-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-tcl-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-test-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-test-8.1.18-2.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-test-8.1.18-2.el5_4.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
  }
}
