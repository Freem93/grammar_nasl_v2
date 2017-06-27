#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87583);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2015-5307", "CVE-2015-8104");

  script_name(english:"Scientific Linux Security Update : kernel on SL7.x x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - It was found that the x86 ISA (Instruction Set
    Architecture) is prone to a denial of service attack
    inside a virtualized environment in the form of an
    infinite loop in the microcode due to the way
    (sequential) delivering of benign exceptions such as #AC
    (alignment check exception) and #DB (debug exception) is
    handled. A privileged user inside a guest could use
    these flaws to create denial of service conditions on
    the host kernel. (CVE-2015-5307, CVE-2015-8104,
    Important)

This update also fixes the following bugs :

  - On Intel Xeon v5 platforms, the processor frequency was
    always tied to the highest possible frequency. Switching
    p-states on these client platforms failed. This update
    sets the idle frequency, busy frequency, and processor
    frequency values by determining the range and adjusting
    the minimal and maximal percent limit values. Now,
    switching p-states on the aforementioned client
    platforms proceeds successfully.

  - Due to a validation error of in-kernel memory-mapped I/O
    (MMIO) tracing, a VM became previously unresponsive when
    connected to RHEV Hypervisor. The provided patch fixes
    this bug by dropping the check in MMIO handler, and a VM
    continues running as expected.

  - Due to retry-able command errors, the NVMe driver
    previously leaked I/O descriptors and DMA mappings. As a
    consequence, the kernel could become unresponsive during
    the hot-unplug operation if a driver was removed. This
    update fixes the driver memory leak bug on command
    retries, and the kernel no longer hangs in this
    situation.

  - The hybrid_dma_data() function was not initialized
    before use, which caused an invalid memory access when
    hot-plugging a PCI card. As a consequence, a kernel oops
    occurred. The provided patch makes sure
    hybrid_dma_data() is initialized before use, and the
    kernel oops no longer occurs in this situation.

  - When running PowerPC (PPC) KVM guests and the host was
    experiencing a lot of page faults, for example because
    it was running low on memory, the host sometimes
    triggered an incorrect kind of interrupt in the guest: a
    data storage exception instead of a data segment
    exception. This caused a kernel panic of the PPC KVM
    guest. With this update, the host kernel synthesizes a
    segment fault if the corresponding Segment Lookaside
    Buffer (SLB) lookup fails, which prevents the kernel
    panic from occurring.

  - The kernel accessed an incorrect area of the khugepaged
    process causing Logical Partitioning (LPAR) to become
    unresponsive, and an oops occurred in medlp5. The
    backported upstream patch prevents an LPAR hang, and the
    oops no longer occurs.

  - When the sctp module was loaded and a route to an
    association endpoint was removed after receiving an
    Out-of-The-Blue (OOTB) chunk but before incrementing the
    'dropped because of missing route' SNMP statistic, a
    NULL pointer Dereference kernel panic previously
    occurred. This update fixes the race condition between
    OOTB response and route removal.

  - The cpuscaling test of the certification test suite
    previously failed due to a rounding bug in the
    intel-pstate driver. This bug has been fixed and the
    cpuscaling test now passes.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=17791
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f299c288"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-327.3.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
