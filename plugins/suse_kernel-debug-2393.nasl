#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59162);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/05/17 14:34:35 $");

  script_cve_id("CVE-2006-3741", "CVE-2006-4145", "CVE-2006-4538", "CVE-2006-4572", "CVE-2006-4623", "CVE-2006-4997", "CVE-2006-5173", "CVE-2006-5174", "CVE-2006-5619", "CVE-2006-5648", "CVE-2006-5649", "CVE-2006-5751", "CVE-2006-5757", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6056", "CVE-2006-6060");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 2393)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

  - A bug within the UDF filesystem that caused machine
    hangs when truncating files on the filesystem was fixed.
    [#186226]. (CVE-2006-4145)

  - A potential crash when receiving IPX packets was fixed.
    This problem is thought not to be exploitable. [#197809]

  - A problem in DVB packet handling could be used to crash
    the machine when receiving DVB net packages is active.
    [#201429]. (CVE-2006-4623)

  - A struct file leak was fixed in the perfmon(2) system
    call on the Itanium architecture. [#202269].
    (CVE-2006-3741)

  - A malformed ELF image can be used on the Itanium
    architecture to trigger a kernel crash (denial of
    service) when a local attacker can supply it to be
    started. [#203822]. (CVE-2006-4538)

  - A problem in the ATM protocol handling clip_mkip
    function could be used by remote attackers to
    potentially crash the machine. [#205383].
    (CVE-2006-4997)

CVE-2006-5757/

  - A problem in the grow_buffers function could be used to
    crash or hang the machine using a corrupted filesystem.
    This affects filesystem types ISO9660 and NTFS.
    [#205384]. (CVE-2006-6060)

  - On the i386 architecture the ELFAGS content was not
    correctly saved, which could be used by local attackers
    to crash other programs using the AC and NT flag or to
    escalate privileges by waiting for iopl privileges to be
    leaked. [#209386]. (CVE-2006-5173)

  - On the S/390 architecture copy_from_user() could be used
    by local attackers to read kernel memory. [#209880].
    (CVE-2006-5174)

  - A problem in IPv6 flowlabel handling can be used by
    local attackers to hang the machine. [#216590].
    (CVE-2006-5619)

  - On the PowerPC architecture a syscall has been wired
    without the proper futex implementation that can be
    exploited by a local attacker to hang the machine.
    [#217295]. (CVE-2006-5648)

  - On the PowerPC architecture the proper futex
    implementation was missing a fix for alignment check
    which could be used by a local attacker to crash the
    machine. [#217295]. (CVE-2006-5649)

  - A problem in cramfs could be used to crash the machine
    during mounting a crafted cramfs image. This requires an
    attacker to supply such a crafted image and have a user
    mount it. [#218237]. (CVE-2006-5823)

  - A problem in the ext3 filesystem could be used by
    attackers able to supply a crafted ext3 image to cause a
    denial of service or further data corruption if a user
    mounts this image. [#220288]. (CVE-2006-6053)

  - Missing return code checking in the HFS could be used to
    crash machine when a user complicit attacker is able to
    supply a specially crafted HFS image. [#221230].
    (CVE-2006-6056)

  - Multiple unspecified vulnerabilities in netfilter for
    IPv6 code allow remote attackers to bypass intended
    restrictions via fragmentation attack vectors, aka (1)
    'ip6_tables protocol bypass bug' and (2) 'ip6_tables
    extension header bypass bug'. [#221313]. (CVE-2006-4572)

  - An integer overflow in the networking bridge ioctl
    starting with Kernel 2.6.7 could be used by local
    attackers to overflow kernel memory buffers and
    potentially escalate privileges [#222656].
    (CVE-2006-5751)

and the following non security bugs :

  - patches.fixes/dm-bio_list_merge-fix.diff: device-mapper
    snapshot: bio_list fix [#117435]

  - patches.fixes/statd-refcount-fix: Fix refcounting
    problems in host management in lockd. [#148009]

  - patches.fixes/i8042-reentry: Prevents i8042_interrupt()
    from being reentered. [#167187]

  - patches.suse/bonding-workqueue: Replace system timer
    with work queue in monitor functions. Remove rtnl_lock
    calls in monitor functions added in original version.
    [#174843] [#205196]

  - patches.arch/i386-profile-pc: i386: Account spinlocks to
    the caller during profiling for !FP kernels [#176770]

  - patches.arch/add-user-mode: i386/x86-64: Add user_mode
    checks to profile_pc for oprofile [#176770]

  - patches.drivers/aic7xxx-max-sectors-adjust: Adjust
    .max_sectors to 8192 for aic7xxx [#177059]

  - patches.xen/xen-x86-dcr-fallback: Add fallback when
    XENMEM_exchange fails to replace contiguous region
    [#181869]

  - patches.suse/lkcd-support-large-minor-number: LKCD
    should support minor numbers > 256 [#185125]

  - patches.fixes/scsi-scan-limit-luns-seqscan-16k: Limit
    sequential scan to 16k LUNs [#185164]

  - patches.drivers/powernow-ext-mask: Handle extended
    powernow vid mask properly [#185654]

  - patches.fixes/xfs-unlink-recovery-fix: [XFS] unlink
    recovery fix. ([#185796]

  - patches.suse/lkcd-dont-lose-one-page: Fix incorrect
    dumps on machines with memory holes [#186169]

  - patches.fixes/ieee80211-orinoco_ap_workaround.diff:
    ieee80211: workaround for broken Orinoco access points
    [#186879]

  - patches.fixes/sched-group-exclusive: Fix scheduler crash
    with exclusive cpusets [#188921]

  - patches.fixes/bdev-imapping-race.diff: Fix race between
    sync_single_inode() and iput() [#188950]

  - patches.fixes/scsi-scan-blist-update: Update blacklist
    entries for EMC Symmetrix and HP EVA [#191648]

  - patches.arch/ia64-mce-output: Save/restore
    oops_in_progress around printing machine checks
    [#191901]

  - patches.fixes/scsi-add-device-oops-during-eh: Fix Oops
    in scsi_add_device during EH [#195050]

  - Included a set of fixes for [#195940]

  - patches.fixes/dm-fix-alloc_dev-error_path.patch: call
    free_minor in alloc_dev error path.
    patches.fixes/dm-snapshot-fix-origin_write-pe-submission
    .patch: fix origin_write pending_exception submission. -

patches.fixes/dm-snapshot-replace-sibling-list.patch: replace sibling
list.

  - patches.fixes/dm-snapshot-fix-pending-pe-ref.patch: fix
    references to pending pe.

  - patches.fixes/dm-snapshot-fix-invalidation.patch: fix
    invalidation. -

patches.fixes/dm-kcopyd-error-accumulation-fix.patch: kcopyd should
accumulate errors.
patches.fixes/dm-snapshot-fix-metadata-error-handling.patch: fix
read_metadata error handling.
patches.fixes/dm-snapshot-fix-metadata-writing-when-suspending.patch:
fix metadata writing when suspending.

  - patches.fixes/nat-t-pskb-pull.patch: Fix NAT-T VPN with
    certain ethernet chips, in particular recent e1000
    chips. [#196747]

  - patches.drivers/e1000-update: Update so that we no
    longer break the 'Disable Packet Split for PCI express
    adapters' driver option.

  - patches.fixes/e1000-no-packet-split: Discard, no longer
    needed.

  - patches.arch/acpi_T60_ultrabay.patch: Add T60 ACPI dock
    station path to ibm_acpi module [#196884]

  - patches.fixes/acpi_battery_hotplug_fix.patch: Workaround
    ACPI misdesign to recon dock station when booting
    undocked.

  - patches.fixes/acpi_ibm_dock_fix_not_present.patch:
    Workaround ACPI misdesign to recon dock station when
    booting undocked [#196884]

  - patches.arch/x86_64-monotonic-clock: Fix monotonic clock
    on x86-64 [#197548]

  - patches.fixes/nfs-truncate-race: Fix a race when
    truncating over NFS and writing via mmap [#198023]

  - patches.drivers/libata-no-spindown-on-shutdown: Don't
    spindown SCSI disks when rebooting [#198687]

  - patches.drivers/qla2xxx-reset-fix: allow reset for
    qla2xxx via sg_reset [#200325]

  - kabi/s390/symvers-default: Update kABI symbols [#202134]

  - patches.suse/bond_alb_deadlock_fix: bonding: fix
    deadlock on high loads in bond_alb_monitor(). [#202512]

  - patches.arch/i386-fix-tsc-selection: Fix TSC timer
    selection on i386 [#203713]

  - patches.drivers/aic94xx-remove-flash-manfid-reliance:
    Remove reliance on the FLASH MANFID [#203768]

  - patches.fixes/xfs-kern-205110-xfs_dio_locking: Fix ABBA
    deadlock between i_mutex and iolock [#205110]

  - patches.suse/bonding-workqueue: Replace system timer
    with work queue in monitor functions. Remove rtnl_lock
    calls in monitor functions added in original version.
    [#174843] [#205196]

  - add
    patches.fixes/fix-incorrect-hugepage-interleaving.patch
    fix NUMA interleaving for huge pages [#205268]

  - patches.suse/bondalb-hashtbl.patch: fix hang in bonding
    ALB driver. [#206629]
    patches.drivers/usb-add-raritan-kvm-usb-dongle-to-the-hi
    d_quirk_noget-blacklist.patch: USB: add Raritan KVM USB
    Dongle to the HID_QUIRK_NOGET blacklist [#206932]

  - patches.arch/ia64-mca_asm-set_kernel_registers: [IA64]
    set ar.fpsr on MCA/INIT kernel entry. [#206967]

  - patches.fixes/md-bitmap-ffz: Use ffz instead of
    find_first_set to convert multiplier to shift. [#207679]

  - patches.fixes/md-bitmap-compat-ioctl: Allow
    SET_BITMAP_FILE to work on 64bit kernel with 32bit
    userspace. [#207688]

  - patches.drivers/mpt-rport-stall: Fix MPT oops during
    aborting commands [#207768]

  - patches.drivers/libata-jmicron-update: Fix handling of
    JMicron controller [#207939]

  - patches.arch/i386-mmconfig-flush:
    arch/i386/pci/mmconfig.c tlb flush fix [#208414]

  - patches.fixes/scsi-fix-req-page-count: scsi_lib.c:
    properly count the number of pages in scsi_req_map_sg()
    [#208782]

  - patches.fixes/fix-processor-placement.diff: sched: Fix
    longstanding load balancing bug in the scheduler
    [#209460].

  - patches.arch/x86_64-fpu-corruption: Fix FPU corruption
    [#209903]

  - patches.drivers/qla1280-bus-reset-handling: performance
    slowdown after bus reset on qla12160 HBA [#213717]

  - patches.drivers/qla1280-scb-timeout: qla1280 times out
    on long operations such as tape rewind [#214695]

  - patches.fixes/slab-per-cpu-data: Make slab
    initialization use per cpu data of correction CPU
    [#216316]

  - patches.fixes/ocfs2-network-send-lock.diff: ocfs2:
    introduce sc->sc_send_lock to protect outbound network
    messages [#216912]

  - marked module megaraid_sas as supported

  - marked module jsm as supported [#218969]

  - patches.suse/ocfs2-13-fix-quorum-work.diff: ocfs2:
    outstanding scheduled work can oops when quorum is shut
    down [#220694]

  - patches.xen/xen-x86_64-agp: add missing header [#222174]
    [#224170]

  - patches.fixes/md-rebuild-fix: md: Fix bug where a
    rebuild of spares, when interrupted by a rebuild,
    doesn't always get properly completed once the system is
    back up, leading to filesystem corruption. [#224960].

  - patches.fixes/scsi-sdev-initialisation-block-race: SCSI
    midlayer race: scan vs block/unblock deadlocks sdev
    [#225770]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3741.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-4145.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-4538.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-4572.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-4623.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-4997.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5173.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5174.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5619.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5648.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5649.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5751.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5757.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5823.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6053.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6056.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6060.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 2393.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"kernel-default-2.6.16.27-0.6")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"kernel-smp-2.6.16.27-0.6")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"kernel-source-2.6.16.27-0.6")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"kernel-syms-2.6.16.27-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-debug-2.6.16.27-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-default-2.6.16.27-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-kdump-2.6.16.27-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-smp-2.6.16.27-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-source-2.6.16.27-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-syms-2.6.16.27-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-xen-2.6.16.27-0.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
