#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2012-0051.
#

include("compat.inc");

if (description)
{
  script_id(79489);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2012-2625", "CVE-2012-4535", "CVE-2012-4536", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-4544");
  script_bugtraq_id(53650, 56289, 56498);

  script_name(english:"OracleVM 3.1 : xen (OVMSA-2012-0051)");
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

  - libxc: builder: limit maximum size of kernel/ramdisk.
    Allowing user supplied kernels of arbitrary sizes,
    especially during decompression, can swallow up dom0
    memory leading to either virtual address space
    exhaustion in the builder process or allocation
    failures/OOM killing of both toolstack and unrelated
    processes. We disable these checks when building in a
    stub domain for pvgrub since this uses the guest's own
    memory and is isolated. Decompression of gzip compressed
    kernels and ramdisks has been safe since
    14954:58205257517d (Xen 3.1.0 onwards). This is XSA-25 /
    CVE-2012-4544. Also make explicit checks for buffer
    overflows in various decompression routines. These were
    already ruled out due to other properties of the code
    but check them as a belt-and-braces measure.

    [ Includes 25589:60f09d1ab1fe for CVE-2012-2625]
    (CVE-2012-4544)

  - compat/gnttab: Prevent infinite loop in compat code c/s
    20281:95ea2052b41b, which introduces Grant Table version
    2 hypercalls introduces a vulnerability whereby the
    compat hypercall handler can fall into an infinite loop.
    If the watchdog is enabled, Xen will die after the
    timeout. This is a security problem, XSA-24 /
    CVE-2012-4539. (CVE-2012-4539)

  - xen/mm/shadow: check toplevel pagetables are present
    before unhooking them. If the guest has not fully
    populated its top-level PAE entries when it calls
    HVMOP_pagetable_dying, the shadow code could try to
    unhook entries from MFN 0. Add a check to avoid that
    case. This issue was introduced by c/s
    21239:b9d2db109cf5. This is a security problem, XSA-23 /
    CVE-2012-4538. (CVE-2012-4538)

  - x86/physmap: Prevent incorrect updates of m2p mappings
    In certain conditions, such as low memory, set_p2m_entry
    can fail. Currently, the p2m and m2p tables will get out
    of sync because we still update the m2p table after the
    p2m update has failed. If that happens, subsequent
    guest-invoked memory operations can cause BUGs and
    ASSERTs to kill Xen. This is fixed by only updating the
    m2p table iff the p2m was successfully updated. This is
    a security problem, XSA-22 / CVE-2012-4537.
    (CVE-2012-4537)

  - x86/physdev: Range check pirq parameter from guests
    Otherwise Xen will read beyond either end of the struct
    domain.arch.pirq_emuirq array, usually resulting in a
    fatal page fault. This vulnerability was introduced by
    c/s 23241:d21100f1d00e, which adds a call to
    domain_pirq_to_emuirq which uses the guest provided pirq
    value before range checking it, and was fixed by c/s
    23573:584c2e5e03d9 which changed the behaviour of the
    domain_pirq_to_emuirq macro to use radix trees instead
    of a flat array. This is XSA-21 / CVE-2012-4536.
    (CVE-2012-4536)

  - VCPU/timers: Prevent overflow in calculations, leading
    to DoS vulnerability The timer action for a vcpu
    periodic timer is to calculate the next expiry time, and
    to reinsert itself into the timer queue. If the deadline
    ends up in the past, Xen never leaves __do_softirq. The
    affected PCPU will stay in an infinite loop until Xen is
    killed by the watchdog (if enabled). This is a security
    problem, XSA-20 / CVE-2012-4535. (CVE-2012-4535)

  - Correct RTC time offset update error for HVM guest
    changeset 24947:b198ada9689d

  - always release vm running lock on VM shutdown Before
    this patch, when xend restarted, the VM running lock
    will not be released on shutdown, so the VM could never
    start again. Talked with Junjie, we recommend always
    releasing the lock on VM shutdown. So even when xend
    restarted, there should be no stale lock leaving there."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2012-November/000109.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6907b516"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
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
if (rpm_check(release:"OVS3.1", reference:"xen-4.1.2-18.el5.24")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-devel-4.1.2-18.el5.24")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-tools-4.1.2-18.el5.24")) flag++;

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
