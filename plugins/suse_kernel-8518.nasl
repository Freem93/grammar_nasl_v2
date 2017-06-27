#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(65959);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/14 00:08:46 $");

  script_cve_id("CVE-2012-4530", "CVE-2013-0160", "CVE-2013-0216", "CVE-2013-0231", "CVE-2013-0268", "CVE-2013-0871");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 8518)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Linux kernel update fixes various security issues and bugs in the
SUSE Linux Enterprise 10 SP4 kernel.

The following security issues have been fixed :

  - A race condition in ptrace(2) could be used by local
    attackers to crash the kernel and/or execute code in
    kernel context. (CVE-2013-0871)

  - Avoid side channel information leaks from the ptys via
    ptmx, which allowed local attackers to guess keypresses.
    (CVE-2013-0160)

  - Avoid leaving bprm->interp on the stack which might have
    leaked information from the kernel to userland
    attackers. (CVE-2012-4530)

  - The msr_open function in arch/x86/kernel/msr.c in the
    Linux kernel allowed local users to bypass intended
    capability restrictions by executing a crafted
    application as root, as demonstrated by msr32.c.
    (CVE-2013-0268)

  - The Xen netback functionality in the Linux kernel
    allowed guest OS users to cause a denial of service
    (loop) by triggering ring pointer corruption.
    (CVE-2013-0216)

  - The pciback_enable_msi function in the PCI backend
    driver (drivers/xen/pciback/conf_space_capability_msi.c)
    in Xen for the Linux kernel allowed guest OS users with
    PCI device access to cause a denial of service via a
    large number of kernel log messages. NOTE: some of these
    details are obtained from third-party information.
    (CVE-2013-0231)

Also the following non-security bugs have been fixed :

S/390 :

  - s390x: tty struct used after free (bnc#809692,
    LTC#90216).

  - s390x/kernel: sched_clock() overflow (bnc#799611,
    LTC#87978).

  - qeth: set new mac even if old mac is gone
    (bnc#789012,LTC#86643).

  - qeth: set new mac even if old mac is gone (2)
    (bnc#792697,LTC#87138).

  - qeth: fix deadlock between recovery and bonding driver
    (bnc#785101,LTC#85905).

  - dasd: check count address during online setting
    (bnc#781485,LTC#85346).

  - hugetlbfs: add missing TLB invalidation
    (bnc#781485,LTC#85463).

  - s390/kernel: make user-access pagetable walk code huge
    page aware (bnc#781485,LTC#85455).

XEN :

  - xen/netback: fix netbk_count_requests().

  - xen: properly bound buffer access when parsing
    cpu/availability.

  - xen/scsiback/usbback: move cond_resched() invocations to
    proper place.

  - xen/pciback: properly clean up after calling
    pcistub_device_find().

  - xen: add further backward-compatibility configure
    options.

  - xen/PCI: suppress bogus warning on old hypervisors.

  - xenbus: fix overflow check in xenbus_dev_write().

  - xen/x86: do not corrupt %eip when returning from a
    signal handler. Other :

  - kernel: Restrict clearing TIF_SIGPENDING. (bnc#742111)

  - kernel: recalc_sigpending_tsk fixes. (bnc#742111)

  - xfs: Do not reclaim new inodes in xfs_sync_inodes().
    (bnc#770980)

  - jbd: Avoid BUG_ON when checkpoint stalls. (bnc#795335)

  - reiserfs: Fix int overflow while calculating free space.
    (bnc#795075)

  - cifs: clarify the meaning of tcpStatus == CifsGood.
    (bnc#769093)

  - cifs: do not allow cifs_reconnect to exit with NULL
    socket pointer. (bnc#769093)

  - cifs: switch to seq_files. (bnc#776370)

  - scsi: fix check of PQ and PDT bits for WLUNs.
    (bnc#765687)

  - hugetlb: preserve hugetlb pte dirty state. (bnc#790236)

  - poll: enforce RLIMIT_NOFILE in poll(). (bnc#787272)

  - proc: fix ->open less usage due to ->proc_fops flip.
    (bnc#776370)

  - rpm/kernel-binary.spec.in: Ignore kabi errors if
    %%ignore_kabi_badness is defined. This is used in the
    Kernel:* projects in the OBS."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4530.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0216.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0231.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0268.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0871.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8518.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"kernel-default-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"kernel-source-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"kernel-debug-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"kernel-default-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"kernel-kdumppae-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"kernel-source-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.101.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
