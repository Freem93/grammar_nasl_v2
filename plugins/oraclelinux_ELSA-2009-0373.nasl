#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:0373 and 
# Oracle Linux Security Advisory ELSA-2009-0373 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67830);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/26 16:04:31 $");

  script_cve_id("CVE-2009-0784");
  script_xref(name:"RHSA", value:"2009:0373");

  script_name(english:"Oracle Linux 4 / 5 : systemtap (ELSA-2009-0373)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:0373 :

Updated systemtap packages that fix a security issue are now available
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
    value:"https://oss.oracle.com/pipermail/el-errata/2009-March/000934.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-March/000935.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemtap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemtap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemtap-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemtap-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemtap-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemtap-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"systemtap-0.6.2-2.0.1.el4_7")) flag++;
if (rpm_check(release:"EL4", reference:"systemtap-runtime-0.6.2-2.0.1.el4_7")) flag++;
if (rpm_check(release:"EL4", reference:"systemtap-testsuite-0.6.2-2.0.1.el4_7")) flag++;

if (rpm_check(release:"EL5", reference:"systemtap-0.7.2-3.0.1.el5_3")) flag++;
if (rpm_check(release:"EL5", reference:"systemtap-client-0.7.2-3.0.1.el5_3")) flag++;
if (rpm_check(release:"EL5", reference:"systemtap-runtime-0.7.2-3.0.1.el5_3")) flag++;
if (rpm_check(release:"EL5", reference:"systemtap-server-0.7.2-3.0.1.el5_3")) flag++;
if (rpm_check(release:"EL5", reference:"systemtap-testsuite-0.7.2-3.0.1.el5_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemtap / systemtap-client / systemtap-runtime / systemtap-server / etc");
}
