#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57111);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/25 23:46:55 $");

  script_cve_id("CVE-2011-2928", "CVE-2011-3191", "CVE-2011-3353");

  script_name(english:"SuSE 11.1 Security Update : Linux kernel (SAT Patch Numbers 5219 / 5222 / 5223)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 1 kernel was updated to
2.6.32.46 and fixes various bugs and security issues.

The following security issues have been fixed :

  - A signedness issue in CIFS could possibly have lead to
    to memory corruption, if a malicious server could send
    crafted replies to the host. (CVE-2011-3191)

  - In the fuse filesystem, FUSE_NOTIFY_INVAL_ENTRY did not
    check the length of the write so the message processing
    could overrun and result in a BUG_ON() in
    fuse_copy_fill(). This flaw could be used by local users
    able to mount FUSE filesystems to crash the system.
    (CVE-2011-3353)

  - The befs_follow_link function in fs/befs/linuxvfs.c in
    the Linux kernel did not validate the length attribute
    of long symlinks, which allowed local users to cause a
    denial of service (incorrect pointer dereference and
    OOPS) by accessing a long symlink on a malformed Be
    filesystem. (CVE-2011-2928)

Also the following non security bugs have been fixed :

  - CONFIG_CGROUP_MEM_RES_CTLR_SWAP enabled

  - CONFIG_CGROUP_MEM_RES_CTLR_SWAP_ENABLED disabled by
    default. Swap accounting can be turned on by
    swapaccount=1 kernel command line parameter.
    (bnc#719450)

  - Make swap accounting default behavior configurable
    (bnc#719450, bnc#650309, fate#310471).

  - Added a missing reset for ioc_reset_in_progress in
    SoftReset in the mtpsas driver. (bnc#711969)

  - Add support for the Digi/IBM PCIe 2-port Adapter.
    (bnc#708675)

  - Always enable MSI-X on 5709. (bnc#707737)

  - sched: fix broken SCHED_RESET_ON_FORK handling.
    (bnc#708877)

  - sched: Fix rt_rq runtime leakage bug. (bnc#707096)

  - ACPI: allow passing down C1 information if no other
    C-states exist.

  - KDB: turn off kdb usb support by default. (bnc#694670 /
    bnc#603804)

  - xfs: Added event tracing support.

  - xfs: fix xfs_fsblock_t tracing.

  - igb: extend maximum frame size to receive VLAN tagged
    frames. (bnc#688859)

  - cfq: Do not allow queue merges for queues that have no
    process references. (bnc#712929)

  - cfq: break apart merged cfqqs if they stop cooperating.
    (bnc#712929)

  - cfq: calculate the seek_mean per cfq_queue not per
    cfq_io_context. (bnc#712929)

  - cfq: change the meaning of the cfqq_coop flag.
    (bnc#712929)

  - cfq-iosched: get rid of the coop_preempt flag.
    (bnc#712929)

  - cfq: merge cooperating cfq_queues. (bnc#712929)

  - Fix FDDI and TR config checks in ipv4 arp and LLC.
    (bnc#715235)

  - writeback: do uninterruptible sleep in
    balance_dirty_pages(). (bnc#699354 / bnc#699357)

  - xfs: fix memory reclaim recursion deadlock on locked
    inode buffer. (bnc#699355 / bnc#699354)

  - xfs: use GFP_NOFS for page cache allocation. (bnc#699355
    / bnc#699354)

  - virtio-net: init link state correctly. (bnc#714966)

  - cpufreq: pcc-cpufreq: sanity check to prevent a NULL
    pointer dereference. (bnc#709412)

  - x86: ucode-amd: Do not warn when no ucode is available
    for a CPU

  - patches.arch/x86_64-unwind-annotations: Refresh.
    (bnc#588458)

  - patches.suse/stack-unwind: Refresh. (bnc#588458)

  - splice: direct_splice_actor() should not use pos in sd.
    (bnc#715763)

  - qdio: 2nd stage retry on SIGA-W busy conditions
    (bnc#713138,LTC#74402).

  - TTY: pty, fix pty counting. (bnc#711203)

  - Avoid deadlock in GFP_IO/GFP_FS allocation. (bnc#632870)

  - novfs: fix some DirCache locking issues. (bnc#669378)

  - novfs: fix some kmalloc/kfree issues. (bnc#669378)

  - novfs: fix off-by-one allocation error. (bnc#669378)

  - novfs: unlink directory after unmap. (bnc#649625)

  - novfs: last modification time not reliable. (bnc#642896)

  - x86 / IO APIC: Reset IRR in clear_IO_APIC_pin().
    (bnc#701686, bnc#667386)

  - mptfusion : Added check for SILI bit in READ_6 CDB for
    DATA UNDERRUN ERRATA. (bnc#712456)

  - xfs: serialise unaligned direct IOs. (bnc#707125)

  - NFS: Ensure that we handle NFS4ERR_STALE_STATEID
    correctly. (bnc#701443)

  - NFSv4: Do not call nfs4_state_mark_reclaim_reboot() from
    error handlers. (bnc#701443)

  - NFSv4: Fix open recovery. (bnc#701443)

  - NFSv4.1: Do not call nfs4_schedule_state_recovery()
    unnecessarily. (bnc#701443)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=588458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=603804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=632870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=649625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=650309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=667386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=688859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=694670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=699354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=699355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=699357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=701443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=701686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=704347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=706557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=707096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=707125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=707737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=708675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=708877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=709412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=711203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=711969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=713138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=713430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=715235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=715763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=716901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=719117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=719450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2928.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3191.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3353.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 5219 / 5222 / 5223 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:btrfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:btrfs-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:btrfs-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hyper-v-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hyper-v-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-default-0_2.6.32.46_0.3-0.3.57")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-pae-0_2.6.32.46_0.3-0.3.57")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-xen-0_2.6.32.46_0.3-0.3.57")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hyper-v-kmp-default-0_2.6.32.46_0.3-0.14.11")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hyper-v-kmp-pae-0_2.6.32.46_0.3-0.14.11")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-base-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-devel-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-extra-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-desktop-devel-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-base-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-devel-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-extra-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-source-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-syms-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-base-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-devel-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-extra-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-default-0_2.6.32.46_0.3-0.3.57")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-xen-0_2.6.32.46_0.3-0.3.57")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"hyper-v-kmp-default-0_2.6.32.46_0.3-0.14.11")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-base-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-devel-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-extra-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-desktop-devel-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-source-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-syms-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-base-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-devel-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-extra-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"btrfs-kmp-default-0_2.6.32.46_0.3-0.3.57")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"ext4dev-kmp-default-0_2.6.32.46_0.3-7.9.24")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-base-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-devel-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-source-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-syms-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-base-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-devel-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"btrfs-kmp-pae-0_2.6.32.46_0.3-0.3.57")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"btrfs-kmp-xen-0_2.6.32.46_0.3-0.3.57")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"ext4dev-kmp-pae-0_2.6.32.46_0.3-7.9.24")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"ext4dev-kmp-xen-0_2.6.32.46_0.3-7.9.24")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"hyper-v-kmp-default-0_2.6.32.46_0.3-0.14.11")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"hyper-v-kmp-pae-0_2.6.32.46_0.3-0.14.11")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-ec2-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-ec2-base-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-base-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-devel-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-base-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-devel-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"kernel-default-man-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-xen-0_2.6.32.46_0.3-0.3.57")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"ext4dev-kmp-xen-0_2.6.32.46_0.3-7.9.24")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"hyper-v-kmp-default-0_2.6.32.46_0.3-0.14.11")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-ec2-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-ec2-base-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-base-2.6.32.46-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-devel-2.6.32.46-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
