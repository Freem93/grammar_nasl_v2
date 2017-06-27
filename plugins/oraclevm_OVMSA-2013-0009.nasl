#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2013-0009.
#

include("compat.inc");

if (description)
{
  script_id(79498);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2013-0153", "CVE-2013-0215");
  script_bugtraq_id(57742, 57745);

  script_name(english:"OracleVM 3.1 : xen (OVMSA-2013-0009)");
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

  - oxenstored incorrect handling of certain Xenbus ring
    states Xen Security Advisory 38 (CVE-2013-0215) Patch
    xsa38.patch The oxenstored daemon (the ocaml version of
    the xenstore daemon) does not correctly handle unusual
    or malicious contents in the xenstore ring. A malicious
    guest can exploit this to cause oxenstored to read past
    the end of the ring (and very likely crash) or to
    allocate large amounts of RAM. Signed-off-by Chuck
    Anderson (CVE-2013-0215)

  - ACPI: acpi_table_parse should return handler's error
    code Currently, the error code returned by
    acpi_table_parse's handler is ignored. This patch will
    propagate handler's return value to acpi_table_parse's
    caller. AMD,IOMMU: Clean up old entries in remapping
    tables when creating new interrupt mapping. When
    changing the affinity of an IRQ associated with a passed
    through PCI device, clear previous mapping. In addition,
    because some BIOSes may incorrectly program IVRS entries
    for IOAPIC try to check for entry's consistency.
    Specifically, if conflicting entries are found disable
    IOMMU if per-device remapping table is used. If entries
    refer to bogus IOAPIC IDs disable IOMMU unconditionally
    AMD,IOMMU: Disable IOMMU if SATA Combined mode is on
    AMD's SP5100 chipset can be placed into SATA Combined
    mode that may cause prevent dom0 from booting when IOMMU
    is enabled and per-device interrupt remapping table is
    used. While SP5100 erratum 28 requires BIOSes to disable
    this mode, some may still use it. This patch checks
    whether this mode is on and, if per-device table is in
    use, disables IOMMU. AMD,IOMMU: Make per-device
    interrupt remapping table default Using global interrupt
    remapping table may be insecure, as described by XSA-36.
    This patch makes per-device mode default. This is XSA-36
    / CVE-2013-0153. (CVE-2013-0153)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2013-February/000126.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b9fce8b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/07");
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
if (! ereg(pattern:"^OVS" + "3\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.1", reference:"xen-4.1.2-18.el5.37")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-devel-4.1.2-18.el5.37")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-tools-4.1.2-18.el5.37")) flag++;

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
