#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0012.
#

include("compat.inc");

if (description)
{
  script_id(88737);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2015-2752", "CVE-2015-2756", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106");
  script_bugtraq_id(72577, 73448, 74947, 74948, 74949, 74950);
  script_osvdb_id(120061, 120062, 122855, 122856, 122857, 122858);

  script_name(english:"OracleVM 2.2 : xen (OVMSA-2016-0012)");
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

  - XSA-125: Limit XEN_DOMCTL_memory_mapping hypercall to
    only process up to 64 GFNs (or less) (Jan Beulich)
    [20732412] (CVE-2015-2752)

  - XSA-126: xen: limit guest control of PCI command
    register (Jan Beulich) [20739399] (CVE-2015-2756)

  - XSA-128: xen: properly gate host writes of modified PCI
    CFG contents (Jan Beulich) [21157440] (CVE-2015-4103)

  - XSA-129: xen: don't allow guest to control MSI mask
    register (Jan Beulich) [21158692] (CVE-2015-4104)

  - XSA-130: xen/MSI-X: disable logging by default (Jan
    Beulich) [21159408] (CVE-2015-4105)

  - XSA-131: [PATCH 1/8] xen/MSI: don't open-code
    pass-through of enable bit modifications (Jan Beulich)
    [21164529] (CVE-2015-4106)

  - XSA-131: [PATCH 2/8] xen/pt: consolidate PM capability
    emu_mask [21164529] (CVE-2015-4106)

  - XSA-131: [PATCH 3/8] xen/pt: correctly handle PM status
    bit [21164529] (CVE-2015-4106)

  - XSA-131: [PATCH 4/8] xen/pt: split out calculation of
    throughable mask in PCI config space handling [21164529]
    (CVE-2015-4106)

  - XSA-131: [PATCH 5/8] xen/pt: mark all PCIe capability
    bits read-only [21164529] (CVE-2015-4106)

  - XSA-131: [PATCH 6/8] xen/pt: mark reserved bits in PCI
    config space fields [21164529] (CVE-2015-4106)

  - XSA-131: [PATCH 7/8] xen/pt: add a few PCI config space
    field descriptions [21164529] (CVE-2015-4106)

  - XSA-131: [PATCH 8/8] xen/pt: unknown PCI config space
    fields should be read-only [21164529] (CVE-2015-4106)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-February/000417.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b4a9eaa"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"OVS2.2", reference:"xen-3.4.0-0.2.25.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-64-3.4.0-0.2.25.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-debugger-3.4.0-0.2.25.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-devel-3.4.0-0.2.25.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-pvhvm-devel-3.4.0-0.2.25.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-tools-3.4.0-0.2.25.el5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-64 / xen-debugger / xen-devel / xen-pvhvm-devel / etc");
}
