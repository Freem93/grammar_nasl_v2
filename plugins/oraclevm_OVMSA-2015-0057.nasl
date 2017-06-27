#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0057.
#

include("compat.inc");

if (description)
{
  script_id(83482);
  script_version("$Revision: 2.13 $");
  script_cvs_date("$Date: 2017/02/17 16:18:34 $");

  script_cve_id("CVE-2015-2751", "CVE-2015-2752", "CVE-2015-2756", "CVE-2015-3456");
  script_bugtraq_id(72577, 73443, 73448, 74640);
  script_osvdb_id(120061, 120062, 120063, 122072);
  script_xref(name:"IAVA", value:"2015-A-0112");

  script_name(english:"OracleVM 3.3 : xen (OVMSA-2015-0057) (Venom)");
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

  - fdc: force the fifo access to be in bounds of the
    allocated buffer During processing of certain commands
    such as FD_CMD_READ_ID and
    FD_CMD_DRIVE_SPECIFICATION_COMMAND the fifo memory
    access could get out of bounds leading to memory
    corruption with values coming from the guest. Fix this
    by making sure that the index is always bounded by the
    allocated memory. This is CVE-2015-3456.

    XSA-133 (CVE-2015-3456)

  - fdc: force the fifo access to be in bounds of the
    allocated buffer During processing of certain commands
    such as FD_CMD_READ_ID and
    FD_CMD_DRIVE_SPECIFICATION_COMMAND the fifo memory
    access could get out of bounds leading to memory
    corruption with values coming from the guest. Fix this
    by making sure that the index is always bounded by the
    allocated memory. This is CVE-2015-3456.

    XSA-133 (CVE-2015-3456)

  - domctl: don't allow a toolstack domain to call
    domain_pause on itself These DOMCTL subops were
    accidentally declared safe for disaggregation in the
    wake of XSA-77. This is XSA-127. (CVE-2015-2751)

  - xen: limit guest control of PCI command register
    Otherwise the guest can abuse that control to cause e.g.
    PCIe Unsupported Request responses (by disabling memory
    and/or I/O decoding and subsequently causing [CPU side]
    accesses to the respective address ranges), which
    (depending on system configuration) may be fatal to the
    host. This is CVE-2015-2756 / XSA-126.

    Conflicts:
    tools/qemu-xen-traditional-dir/hw/pass-through.c
    (CVE-2015-2756)

  - xen: limit guest control of PCI command register
    Otherwise the guest can abuse that control to cause e.g.
    PCIe Unsupported Request responses (by disabling memory
    and/or I/O decoding and subsequently causing [CPU side]
    accesses to the respective address ranges), which
    (depending on system configuration) may be fatal to the
    host. This is CVE-2015-2756 / XSA-126. (CVE-2015-2756)

  - Limit XEN_DOMCTL_memory_mapping hypercall to only
    process up to 64 GFNs (or less) Said hypercall for large
    BARs can take quite a while. As such we can require that
    the hypercall MUST break up the request in smaller
    values. Another approach is to add preemption to it -
    whether we do the preemption using
    hypercall_create_continuation or returning EAGAIN to
    userspace (and have it re-invocate the call) - either
    way the issue we cannot easily solve is that in
    'map_mmio_regions' if we encounter an error we MUST call
    'unmap_mmio_regions' for the whole BAR region. Since the
    preemption would re-use input fields such as nr_mfns,
    first_gfn, first_mfn - we would lose the original values
    - and only undo what was done in the current round (i.e.
    ignoring anything that was done prior to earlier
    preemptions). Unless we re-used the return value as
    'EAGAIN|nr_mfns_done<<10' but that puts a limit (since
    the return value is a long) on the amount of nr_mfns
    that can provided. This patch sidesteps this problem 
by :

  - Setting an hard limit of nr_mfns having to be 64 or
    less.

  - Toolstack adjusts correspondingly to the nr_mfn limit.

  - If the there is an error when adding the toolstack will
    call the remove operation to remove the whole region.
    The need to break this hypercall down is for large BARs
    can take more than the guest (initial domain usually)
    time-slice. This has the negative result in that the
    guest is locked out for a long duration and is unable to
    act on any pending events. We also augment the code to
    return zero if nr_mfns instead of trying to the
    hypercall. Suggested-by: Jan Beulich 

    This is CVE-2015-2752 / XSA-125. (CVE-2015-2752)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2015-May/000308.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/14");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/15");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"xen-4.3.0-55.el6.22.24")) flag++;
if (rpm_check(release:"OVS3.3", reference:"xen-tools-4.3.0-55.el6.22.24")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-tools");
}
