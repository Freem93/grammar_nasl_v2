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
  script_id(64500);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:46:55 $");

  script_cve_id("CVE-2012-0957", "CVE-2012-4530", "CVE-2012-4565");

  script_name(english:"SuSE 11.2 Security Update : Linux Kernel (SAT Patch Numbers 7273 / 7276 / 7277)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP2 kernel was updated to 3.0.58, fixing
various bugs and security issues.

The updates contains the following feature enhancement :

  - Enable various md/raid10 and DASD enhancements.

  - Make is possible for RAID10 to cope with DASD devices
    being slow for various reasons - the affected device
    will be temporarily removed from the array.

  - Added support for reshaping of RAID10 arrays, mdadm
    changes will be published to support the changes. The
    following security issues were fixed :

  - A division by zero in the TCP Illinois algorithm.
    (CVE-2012-4565)

  - The uname26 personality leaked kernel memory
    information. (CVE-2012-0957)

  - Kernel stack content disclosure via binfmt_script
    load_script(). (CVE-2012-4530) The following
    non-security issues were fixed :

  - BTRFS :

  - btrfs: reset path lock state to zero.

  - btrfs: fix off-by-one in lseek.

  - btrfs: fix btrfs_cont_expand() freeing IS_ERR em.

  - btrfs: update timestamps on truncate().

  - btrfs: put csums on the right ordered extent.

  - btrfs: use existing align macros in btrfs_allocate()

  - btrfs: fix off-by-one error of the reserved size of
    btrfs_allocate()

  - btrfs: add fiemaps flag check

  - btrfs: fix permissions of empty files not affected by
    umask

  - btrfs: do not auto defrag a file when doing directIO

  - btrfs: fix wrong return value of btrfs_truncate_page()

  - btrfs: Notify udev when removing device

  - btrfs: fix permissions of empty files not affected by
    umask

  - btrfs: fix hash overflow handling

  - btrfs: do not delete a subvolume which is in a R/O
    subvolume

  - btrfs: remove call to btrfs_wait_ordered_extents to
    avoid potential deadlock.

  - btrfs: update the checks for mixed block groups with big
    metadata blocks

  - btrfs: Fix use-after-free in __btrfs_end_transaction

  - btrfs: use commit root when loading free space cache.

  - btrfs: avoid setting ->d_op twice (FATE#306586
    bnc#731387).

  - btrfs: fix race in reada (FATE#306586).

  - btrfs: do not add both copies of DUP to reada extent
    tree

  - btrfs: do not mount when we have a sectorsize unequal to
    PAGE_SIZE

  - btrfs: add missing unlocks to transaction abort paths

  - btrfs: avoid sleeping in verify_parent_transid while
    atomic

  - btrfs: disallow unequal data/metadata blocksize for
    mixed block groups

  - btrfs: enhance superblock sanity checks. (bnc#749651)

  - btrfs: sanitizing ->fs_info, parts 1-5.

  - btrfs: make open_ctree() return int.

  - btrfs: kill pointless reassignment of ->s_fs_info in
    btrfs_fill_super().

  - btrfs: merge free_fs_info() calls on fill_super
    failures.

  - btrfs: make free_fs_info() call ->kill_sb()
    unconditional.

  - btrfs: consolidate failure exits in btrfs_mount() a bit.

  - btrfs: let ->s_fs_info point to fs_info, not root...

  - btrfs: take allocation of ->tree_root into open_ctree().

  - Update DASD blk_timeout patches after review by IBM :

  - dasd: Abort all requests from ioctl

  - dasd: Disable block timeouts per default

  - dasd: Reduce amount of messages for specific errors

  - dasd: Rename ioctls

  - dasd: check blk_noretry_request in dasd_times_out()

  - dasd: lock ccw queue in dasd_times_out()

  - dasd: make DASD_FLAG_TIMEOUT setting more robust

  - dasd: rename flag to abortall

  - LPFC :

  - Update lpfc version for 8.3.5.48.3p driver release.

  - lpfc 8.3.32: Correct successful aborts returning error
    status.

  - lpfc 8.3.34: Correct lock handling to eliminate reset
    escalation on I/O abort.

  - lpfc 8.3.34: Streamline fcp underrun message printing.

  - DRM/i915 :

  - drm/i915: EBUSY status handling added to
    i915_gem_fault().

  - drm/i915: Only clear the GPU domains upon a successful
    finish.

  - drm/i915: always use RPNSWREQ for turbo change requests.

  - drm/i915: do not call modeset_init_hw in i915_reset.

  - drm/i915: do not hang userspace when the gpu reset is
    stuck.

  - drm/i915: do not trylock in the gpu reset code.

  - drm/i915: re-init modeset hw state after gpu reset.

  - HyperV :

  - x86: Hyper-V: register clocksource only if its
    advertised.

  - Other :

  - xfrm: fix freed block size calculation in
    xfrm_policy_fini().

  - bonding: in balance-rr mode, set curr_active_slave only
    if it is up.

  - kernel: broken interrupt statistics (LTC#87893).

  - kernel: sched_clock() overflow (LTC#87978).

  - mm: call sleep_on_page_killable from
    __wait_on_page_locked_killable.

  - TTY: do not reset masters packet mode.

  - patches.suse/kbuild-record-built-in-o: Avoid using
    printf(1) in Makefile.build

  - rpm/built-in-where.mk: Do not rely on the *.parts file
    to be newline-separated.

  - NFS: Allow sec=none mounts in certain cases.

  - NFS: fix recent breakage to NFS error handling.

  - bridge: Pull ip header into skb->data before looking
    into ip header.

  - dm mpath: allow ioctls to trigger pg init.

  - dm mpath: only retry ioctl when no paths if
    queue_if_no_path set.

  - radix-tree: fix preload vector size.

  - sched, rt: Unthrottle rt runqueues in
    __disable_runtime().

  - sched/rt: Fix SCHED_RR across cgroups.

  - sched/rt: Do not throttle when PI boosting.

  - sched/rt: Keep period timer ticking when rt throttling
    is active.

  - sched/rt: Prevent idle task boosting.

  - mm: limit mmu_gather batching to fix soft lockups on
    !CONFIG_PREEMPT.

  - kabi fixup for mm: limit mmu_gather batching to fix soft
    lockups on !CONFIG_PREEMPT.

  - Refresh Xen patches after update to 3.0.57.

  - aio: make kiocb->private NUll in init_sync_kiocb().

  - qeth: Fix retry logic in hardsetup. (LTC#87080)

  - netiucv: reinsert dev_alloc_name for device naming.
    (LTC#87086)

  - qeth: set new mac even if old mac is gone (2).
    (LTC#87138)

  - ocfs2: use spinlock irqsave for downconvert lock.patch.

  - af_netlink: force credentials passing.

  - af_unix: dont send SCM_CREDENTIALS by default.

  - sunrpc: increase maximum slots to use.

  - bio: bio allocation failure due to bio_get_nr_vecs().

  - bio: do not overflow in bio_get_nr_vecs().

  - md: close race between removing and adding a device.

  - thp, memcg: split hugepage for memcg oom on cow.

  - bonding: delete migrated IP addresses from the rlb hash
    table.

  - xfs: Fix re-use of EWOULDBLOCK during read on dm-mirror.

  - qla2xxx: Determine the number of outstanding commands
    based on available resources.

  - qla2xxx: Ramp down queue depth for attached SCSI
    devices.

  - autofs4: fix lockdep splat in autofs.

  - ipv6: tcp: fix panic in SYN processing.

  - add splash=black option to bootsplash code, to keep a
    black background, useful for remote access to VMs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=729854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=736255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=739728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=778136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=782721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=783515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=790935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=794231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=794824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=795354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=799209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=799275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=799909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0957.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4530.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4565.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 7273 / 7276 / 7277 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-extra-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-extra-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-source-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-extra-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-extra-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-extra-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-source-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-syms-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-extra-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-extra-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.3_06_3.0.58_0.6.2-0.7.16")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.3_06_3.0.58_0.6.2-0.7.16")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-source-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-syms-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-man-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.58-0.6.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.3_06_3.0.58_0.6.2-0.7.16")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.3_06_3.0.58_0.6.2-0.7.16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
