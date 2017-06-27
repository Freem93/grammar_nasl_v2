#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2013-0004.
#

include("compat.inc");

if (description)
{
  script_id(79496);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2012-5634");
  script_bugtraq_id(57223);

  script_name(english:"OracleVM 3.2 : xen (OVMSA-2013-0004)");
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

  - Xen Security Advisory CVE-2012-5634 / XSA-33 (v3) VT-d
    interrupt remapping source validation flaw

    The patch supplied for Xen 4.1 (xsa33-4.1.patch)
    contained a build error. A corrected patch is attached.
    The fix is also now available in as changeset
    23441:2a91623a5807

    When passing a device which is behind a legacy PCI
    Bridge through to a guest Xen incorrectly configures the
    VT-d hardware. This could allow incorrect interrupts to
    be injected to other guests which also have passthrough
    devices. In a typical Xen system many devices are owned
    by domain 0 or driver domains, leaving them vulnerable
    to such an attack. Such a DoS is likely to have an
    impact on other guests running in the system.

    A malicious domain, given access to a device which is
    behind a legacy PCI bridge, can mount a denial of
    service attack affecting the whole system.

    Xen version 4.0 onwards is vulnerable. Only systems
    using Intel VT-d for PCI passthrough are vulnerable. Any
    domain which is given access to a PCI device that is
    behind a legacy PCI bridge can take advantage of this
    vulnerability. Domains which are given access to PCIe
    devices only are not able to take advantage of this
    vulnerability.

    This issue can be avoided by not assigning PCI devices
    which are behind a legacy PCI bridge to untrusted
    guests."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2013-January/000122.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b895879d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/18");
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
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"xen-4.1.3-25.el5.1")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-devel-4.1.3-25.el5.1")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-tools-4.1.3-25.el5.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-tools");
}
