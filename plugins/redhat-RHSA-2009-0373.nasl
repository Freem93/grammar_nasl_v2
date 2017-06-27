#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0373. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36032);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/01/03 17:27:01 $");

  script_cve_id("CVE-2009-0784");
  script_xref(name:"RHSA", value:"2009:0373");

  script_name(english:"RHEL 4 / 5 : systemtap (RHSA-2009:0373)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated systemtap packages that fix a security issue are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

SystemTap is an instrumentation infrastructure for systems running
version 2.6 of the Linux kernel. SystemTap scripts can collect system
operations data, greatly simplifying information gathering. Collected
data can then assist in performance measuring, functional testing, and
performance and function problem diagnosis.

A race condition was discovered in SystemTap that could allow users in
the stapusr group to elevate privileges to that of members of the
stapdev group (and hence root), bypassing directory confinement
restrictions and allowing them to insert arbitrary SystemTap kernel
modules. (CVE-2009-0784)

Note: This issue was only exploitable if another SystemTap kernel
module was placed in the 'systemtap/' module directory for the
currently running kernel.

Red Hat would like to thank Erik Sjolund for reporting this issue.

SystemTap users should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0784.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-0373.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/27");
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
  rhsa = "RHSA-2009:0373";
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
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"systemtap-0.6.2-2.el4_7")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"systemtap-0.6.2-2.el4_7")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"systemtap-runtime-0.6.2-2.el4_7")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"systemtap-runtime-0.6.2-2.el4_7")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"systemtap-testsuite-0.6.2-2.el4_7")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"systemtap-testsuite-0.6.2-2.el4_7")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"systemtap-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"systemtap-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"systemtap-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"systemtap-client-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"systemtap-client-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"systemtap-client-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"systemtap-runtime-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"systemtap-runtime-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"systemtap-runtime-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"systemtap-server-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"systemtap-server-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"systemtap-server-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"systemtap-testsuite-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"systemtap-testsuite-0.7.2-3.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"systemtap-testsuite-0.7.2-3.el5_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemtap / systemtap-client / systemtap-runtime / systemtap-server / etc");
  }
}
