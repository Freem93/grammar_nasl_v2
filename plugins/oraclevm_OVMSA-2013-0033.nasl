#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2013-0033.
#

include("compat.inc");

if (description)
{
  script_id(79504);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2013-1917", "CVE-2013-1919", "CVE-2013-1920");
  script_bugtraq_id(58880, 59291, 59292);

  script_name(english:"OracleVM 2.2 : xen (OVMSA-2013-0033)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - fix error in first version of the XSA-44 patch (Chuck
    Anderson) [orabug 16632878, 16694867] (CVE-2013-1917)

  - clear EFLAGS.NT in SYSENTER entry path (Andrew Cooper)
    [orabug 16632878] (CVE-2013-1917)

  - fix various issues with handling guest IRQs (Jan
    Beulich) [orabug 16635741] (CVE-2013-1919)

  - defer event channel bucket pointer store until after XSM
    checks [orabug 16635980] (CVE-2013-1920)

  - tools: xend: tolerate empty state/*.xml (Konrad Wilk,
    Joe Jin) [orabug 14683665]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2013-April/000143.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ec4d36e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-pvhvm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "2\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.2", reference:"xen-3.4.0-0.1.47.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-64-3.4.0-0.1.47.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-debugger-3.4.0-0.1.47.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-devel-3.4.0-0.1.47.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-pvhvm-devel-3.4.0-0.1.47.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-tools-3.4.0-0.1.47.el5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-64 / xen-debugger / xen-devel / xen-pvhvm-devel / etc");
}
