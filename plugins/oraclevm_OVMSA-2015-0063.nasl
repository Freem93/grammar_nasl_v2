#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0063.
#

include("compat.inc");

if (description)
{
  script_id(83966);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106");
  script_bugtraq_id(74947, 74948, 74949, 74950);
  script_osvdb_id(122855, 122856, 122857, 122858);

  script_name(english:"OracleVM 3.2 : xen (OVMSA-2015-0063)");
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

  - xen/pt: unknown PCI config space fields should be
    read-only ... by default. Add a per-device 'permissive'
    mode similar to pciback's to allow restoring previous
    behavior (and hence break security again, i.e. should be
    used only for trusted guests). This is part of XSA-131.
    (CVE-2015-4106)

  - xen/pt: add a few PCI config space field descriptions
    Since the next patch will turn all not explicitly
    described fields read-only by default, those fields that
    have guest writable bits need to be given explicit
    descriptors. This is a preparatory patch for XSA-131.
    (CVE-2015-4106)

  - xen/pt: mark reserved bits in PCI config space fields
    The adjustments are solely to make the subsequent
    patches work right (and hence make the patch set
    consistent), namely if permissive mode (introduced by
    the last patch) gets used (as both reserved registers
    and reserved fields must be similarly protected from
    guest access in default mode, but the guest should be
    allowed access to them in permissive mode). This is a
    preparatory patch for XSA-131. (CVE-2015-4106)

  - xen/pt: mark all PCIe capability bits read-only
    xen_pt_emu_reg_pcie[]'s PCI_EXP_DEVCAP needs to cover
    all bits as read- only to avoid unintended write-back
    (just a precaution, the field ought to be read-only in
    hardware). This is a preparatory patch for XSA-131.
    (CVE-2015-4106)

  - xen/pt: split out calculation of throughable mask in PCI
    config space handling This is just to avoid having to
    adjust that calculation later in multiple places. Note
    that including ->ro_mask in get_throughable_mask's
    calculation is only an apparent (i.e. benign) behavioral
    change: For r/o fields it doesn't matter > whether they
    get passed through - either the same flag is also set in
    emu_mask (then there's no change at all) or the field is
    r/o in hardware (and hence a write won't change it
    anyway). This is a preparatory patch for XSA-131.
    (CVE-2015-4106)

  - xen/pt: correctly handle PM status bit
    xen_pt_pmcsr_reg_write needs an adjustment to deal with
    the RW1C nature of the not passed through bit 15
    (PCI_PM_CTRL_PME_STATUS). This is a preparatory patch
    for XSA-131. (CVE-2015-4106)

  - xen/pt: consolidate PM capability emu_mask There's no
    point in xen_pt_pmcsr_reg_[read,write] each ORing
    PCI_PM_CTRL_STATE_MASK and PCI_PM_CTRL_NO_SOFT_RESET
    into a local emu_mask variable - we can have the same
    effect by setting the field descriptor's emu_mask member
    suitably right away. Note that xen_pt_pmcsr_reg_write is
    being retained in order to allow later patches to be
    less intrusive. This is a preparatory patch for XSA-131.
    (CVE-2015-4106)

  - xen/MSI: don't open-code pass-through of enable bit
    modifications Without this the actual XSA-131 fix would
    cause the enable bit to not get set anymore (due to the
    write back getting suppressed there based on the OR of
    emu_mask, ro_mask, and res_mask). Note that the fiddling
    with the enable bit shouldn't really be done by qemu,
    but making this work right (via libxc and the
    hypervisor) will require more extensive changes, which
    can be postponed until after the security issue got
    addressed. This is a preparatory patch for XSA-131.
    (CVE-2015-4106)

  - xen/MSI-X: disable logging by default ... to avoid
    allowing the guest to cause the control domain's disk to
    fill. This is XSA-130. (CVE-2015-4105)

  - xen: don't allow guest to control MSI mask register It's
    being used by the hypervisor. For now simply mimic a
    device not capable of masking, and fully emulate any
    accesses a guest may issue nevertheless as simple
    reads/writes without side effects. This is XSA-129.
    (CVE-2015-4104)

  - xen: properly gate host writes of modified PCI CFG
    contents The old logic didn't work as intended when an
    access spanned multiple fields (for example a 32-bit
    access to the location of the MSI Message Data field
    with the high 16 bits not being covered by any known
    field). Remove it and derive which fields not to write
    to from the accessed fields' emulation masks: When
    they're all ones, there's no point in doing any host
    write. This fixes a secondary issue at once: We
    obviously shouldn't make any host write attempt when
    already the host read failed. This is XSA-128.

    Conflicts: tools/ioemu-remote/hw/pass-through.c
    (CVE-2015-4103)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2015-June/000313.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"OVS3.2", reference:"xen-4.1.3-25.el5.127.36.12")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-devel-4.1.3-25.el5.127.36.12")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-tools-4.1.3-25.el5.127.36.12")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-tools");
}
