#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0658-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83709);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2015-0777", "CVE-2015-2150");
  script_bugtraq_id(73014, 73921);
  script_osvdb_id(119409, 120316);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : Security Update for Linux Kernel (SUSE-SU-2015:0658-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise Server 12 kernel was updated to 3.12.39 to
receive various security and bugfixes.

Following security bugs were fixed :

  - CVE-2015-0777: The XEN usb backend could leak
    information to the guest system due to copying
    uninitialized memory.

  - CVE-2015-2150: Xen and the Linux kernel did not properly
    restrict access to PCI command registers, which might
    have allowed local guest users to cause a denial of
    service (non-maskable interrupt and host crash) by
    disabling the (1) memory or (2) I/O decoding for a PCI
    Express device and then accessing the device, which
    triggers an Unsupported Request (UR) response.

The following non-security bugs were fixed :

  - Added Little Endian support to vtpm module (bsc#918620).

  - Add support for pnfs block layout. Patches not included
    by default yet

  - ALSA: hda - Fix regression of HD-audio controller
    fallback modes (bsc#921313).

  - btrfs: add missing blk_finish_plug in btrfs_sync_log()
    (bnc#922284).

  - btrfs: cleanup orphans while looking up default
    subvolume (bsc#914818).

  - btrfs: do not ignore errors from btrfs_lookup_xattr in
    do_setxattr (bnc#922272).

  - btrfs: fix BUG_ON in btrfs_orphan_add() when delete
    unused block group (bnc#922278).

  - btrfs: fix data loss in the fast fsync path
    (bnc#922275).

  - btrfs: fix fsync data loss after adding hard link to
    inode (bnc#922275).

  - cgroup: revert cgroup_mutex removal from idr_remove
    (bnc#918644).

  - cifs: fix use-after-free bug in find_writable_file
    (bnc#909477).

  - crypto: rng - RNGs must return 0 in success case
    (bsc#920805).

  - crypto: testmgr - fix RNG return code enforcement
    (bsc#920805).

  - exit: Always reap resource stats in __exit_signal()
    (Time scalability).

  - fork: report pid reservation failure properly
    (bnc#909684).

  - fsnotify: Fix handling of renames in audit (bnc#915200).

  - HID: hyperv: match wait_for_completion_timeout return
    type.

  - hv: address compiler warnings for hv_fcopy_daemon.c.

  - hv: address compiler warnings for hv_kvp_daemon.c.

  - hv: check vmbus_device_create() return value in
    vmbus_process_offer().

  - hv: do not add redundant / in hv_start_fcopy().

  - hv: hv_balloon: Do not post pressure status from
    interrupt context.

  - hv: hv_balloon: Fix a locking bug in the balloon driver.

  - hv: hv_balloon: Make adjustments in computing the floor.

  - hv: hv_fcopy: drop the obsolete message on transfer
    failure.

  - hv: kvp_daemon: make IPv6-only-injection work.

  - hv: remove unused bytes_written from kvp_update_file().

  - hv: rename sc_lock to the more generic lock.

  - hv: vmbus: Fix a bug in vmbus_establish_gpadl().

  - hv: vmbus: hv_process_timer_expiration() can be static.

  - hv: vmbus: Implement a clockevent device.

  - hv: vmbus: serialize Offer and Rescind offer.

  - hv: vmbus: Support a vmbus API for efficiently sending
    page arrays.

  - hv: vmbus: Use get_cpu() to get the current CPU.

  - hyperv: fix sparse warnings.

  - hyperv: Fix the error processing in netvsc_send().

  - hyperv: match wait_for_completion_timeout return type.

  - hyperv: netvsc.c: match wait_for_completion_timeout
    return type.

  - iommu/vt-d: Fix dmar_domain leak in iommu_attach_device
    (bsc#924460).

  - kabi, mm: prevent endless growth of anon_vma hierarchy
    (bnc#904242).

  - kABI: protect linux/namei.h include in procfs.

  - kABI: protect struct hif_scatter_req.

  - kabi/severities: Stop maintaining the kgraft kabi

  - kernel/sched/clock.c: add another clock for use with the
    soft lockup watchdog (bsc#919939).

  - kgr: Allow patches to require an exact kernel version
    (bnc#920615).

  - KVM: PPC: Book3S HV: ptes are big endian (bsc#920839).

  - mm: convert the rest to new page table lock api (the
    suse-only cases) (fate#315482).

  - mm: fix anon_vma->degree underflow in anon_vma endless
    growing prevention (bnc#904242).

  - mm: fix corner case in anon_vma endless growing
    prevention (bnc#904242).

  - mm: prevent endless growth of anon_vma hierarchy
    (bnc#904242).

  - mm: prevent endless growth of anon_vma hierarchy mm:
    prevent endless growth of anon_vma hierarchy
    (bnc#904242).

  - mm: vmscan: count only dirty pages as congested (VM
    Performance, bnc#910517).

  - module: Clean up ro/nx after early module load failures
    (bsc#921990).

  - module: set nx before marking module MODULE_STATE_COMING
    (bsc#921990).

  - net: add sysfs helpers for netdev_adjacent logic
    (bnc#915660).

  - net: correct error path in rtnl_newlink() (bnc#915660).

  - net: fix creation adjacent device symlinks (bnc#915660).

  - net: prevent of emerging cross-namespace symlinks
    (bnc#915660).

  - net: rename sysfs symlinks on device name change
    (bnc#915660).

  - nfs: cap request size to fit a kmalloced page array
    (bnc#898675).

  - nfs: commit layouts in fdatasync (bnc#898675).

  - NFSv4.1: Do not trust attributes if a pNFS LAYOUTCOMMIT
    is outstanding (bnc#898675).

  - NFSv4.1: Ensure that the layout recall callback matches
    layout stateids (bnc#898675).

  - NFSv4.1: Ensure that we free existing layout segments if
    we get a new layout (bnc#898675).

  - NFSv4.1: Fix a race in nfs4_write_inode (bnc#898675).

  - NFSv4.1: Fix wraparound issues in pnfs_seqid_is_newer()
    (bnc#898675).

  - NFSv4.1: Minor optimisation in get_layout_by_fh_locked()
    (bnc#898675).

  - NFSv4: Do not update the open stateid unless it is newer
    than the old one (bnc#898675).

  - pnfs: add a common GETDEVICELIST implementation
    (bnc#898675).

  - pnfs: add a nfs4_get_deviceid helper (bnc#898675).

  - pnfs: add flag to force read-modify-write in
    ->write_begin (bnc#898675).

  - pnfs: add return_range method (bnc#898675).

  - pnfs: allow splicing pre-encoded pages into the
    layoutcommit args (bnc#898675).

  - pnfs: avoid using stale stateids after layoutreturn
    (bnc#898675).

  - pnfs/blocklayout: allocate separate pages for the
    layoutcommit payload (bnc#898675).

  - pnfs/blocklayout: correctly decrement extent length
    (bnc#898675).

  - pnfs/blocklayout: do not set pages uptodate
    (bnc#898675).

  - pnfs/blocklayout: Fix a 64-bit division/remainder issue
    in bl_map_stripe (bnc#898675).

  - pnfs/blocklayout: implement the return_range method
    (bnc#898675).

  - pnfs/blocklayout: improve GETDEVICEINFO error reporting
    (bnc#898675).

  - pnfs/blocklayout: include vmalloc.h for __vmalloc
    (bnc#898675).

  - pnfs/blocklayout: in-kernel GETDEVICEINFO XDR parsing
    (bnc#898675).

  - pnfs/blocklayout: move all rpc_pipefs related code into
    a single file (bnc#898675).

  - pnfs/blocklayout: move extent processing to
    blocklayout.c (bnc#898675).

  - pnfs/blocklayout: plug block queues (bnc#898675).

  - pnfs/blocklayout: refactor extent processing
    (bnc#898675).

  - pnfs/blocklayout: reject pnfs blocksize larger than page
    size (bnc#898675).

  - pNFS/blocklayout: Remove a couple of unused variables
    (bnc#898675).

  - pnfs/blocklayout: remove read-modify-write handling in
    bl_write_pagelist (bnc#898675).

  - pnfs/blocklayout: remove some debugging (bnc#898675).

  - pnfs/blocklayout: return layouts on setattr
    (bnc#898675).

  - pnfs/blocklayout: rewrite extent tracking (bnc#898675).

  - pnfs/blocklayout: use the device id cache (bnc#898675).

  - pnfs: do not check sequence on new stateids in layoutget
    (bnc#898675).

  - pnfs: do not pass uninitialized lsegs to ->free_lseg
    (bnc#898675).

  - pnfs: enable CB_NOTIFY_DEVICEID support (bnc#898675).

  - pnfs: factor GETDEVICEINFO implementations (bnc#898675).

  - pnfs: force a layout commit when encountering busy
    segments during recall (bnc#898675).

  - pnfs: remove GETDEVICELIST implementation (bnc#898675).

  - pnfs: retry after a bad stateid error from layoutget
    (bnc#898675).

  - powerpc: add running_clock for powerpc to prevent
    spurious softlockup warnings (bsc#919939).

  - powerpc/pseries: Fix endian problems with LE migration
    (bsc#918584).

  - remove cgroup_mutex around deactivate_super because it
    might be dangerous.

  - rtmutex: Document pi chain walk (mutex scalability).

  - rtmutex: No need to keep task ref for lock owner check
    (mutex scalability).

  - rtmutex: Simplify rtmutex_slowtrylock() (mutex
    scalability).

  - rtnetlink: fix a memory leak when ->newlink fails
    (bnc#915660).

  - sched: Change thread_group_cputime() to use
    for_each_thread() (Time scalability).

  - sched: replace INIT_COMPLETION with reinit_completion.

  - sched, time: Atomically increment stime & utime (Time
    scalability).

  - scsi: storvsc: Always send on the selected outgoing
    channel.

  - scsi: storvsc: Do not assume that the scatterlist is not
    chained.

  - scsi: storvsc: Enable clustering.

  - scsi: storvsc: Fix a bug in copy_from_bounce_buffer().

  - scsi: storvsc: Increase the ring buffer size.

  - scsi: storvsc: Retrieve information about the capability
    of the target.

  - scsi: storvsc: Set the tablesize based on the
    information given by the host.

  - scsi: storvsc: Size the queue depth based on the
    ringbuffer size.

  - storvsc: fix a bug in storvsc limits.

  - storvsc: force discovery of LUNs that may have been
    removed.

  - storvsc: force SPC-3 compliance on win8 and win8 r2
    hosts.

  - storvsc: in responce to a scan event, scan the host.

  - take read_seqbegin_or_lock() and friends to seqlock.h
    (Time scalability).

  - tcp: prevent fetching dst twice in early demux code
    (bnc#903997 bnc#919719).

  - time, signal: Protect resource use statistics with
    seqlock -kabi (Time scalability).

  - time, signal: Protect resource use statistics with
    seqlock (Time scalability).

  - udp: only allow UFO for packets from SOCK_DGRAM sockets
    (bnc#909309).

  - Update Xen patches to 3.12.39.

  - virtio: rng: add derating factor for use by hwrng core
    (bsc#918615).

  - x86, AVX-512: AVX-512 Feature Detection (bsc#921527).

  - x86, AVX-512: Enable AVX-512 States Context Switch
    (bsc#921527).

  - xenbus: add proper handling of XS_ERROR from Xenbus for
    transactions.

  - xfs: xfs_alloc_fix_minleft can underflow near ENOSPC
    (bnc#913080).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/898675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/903997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/913080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0777.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2150.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150658-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1adafe84"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-152=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-152=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-152=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2015-152=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2015-152=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-152=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-devel-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-syms-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.39-47.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.39-47.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Security Update for Linux Kernel");
}
