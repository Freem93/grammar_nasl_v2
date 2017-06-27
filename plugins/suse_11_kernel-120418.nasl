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
  script_id(58845);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/25 23:46:55 $");

  script_cve_id("CVE-2011-1083", "CVE-2011-2494", "CVE-2011-4086", "CVE-2011-4127", "CVE-2011-4131", "CVE-2011-4132", "CVE-2012-1090", "CVE-2012-1097", "CVE-2012-1146", "CVE-2012-1179");

  script_name(english:"SuSE 11.2 Security Update : Linux kernel (SAT Patch Numbers 6163 / 6164 / 6172)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP2 kernel has been updated to 3.0.26,
which fixes a lot of bugs and security issues.

The following security issues have been fixed :

  - A locking problem in transparent hugepage support could
    be used by local attackers to potentially crash the
    host, or via kvm a privileged guest user could crash the
    kvm host system. (CVE-2012-1179)

  - A potential hypervisor escape by issuing SG_IO commands
    to partitiondevices was fixed by restricting access to
    these commands. (CVE-2011-4127)

  - A local attacker could oops the kernel using memory
    control groups and eventfds. (CVE-2012-1146)

  - Limit the path length users can build using epoll() to
    avoid local attackers consuming lots of kernel CPU time.
    (CVE-2011-1083)

  - The regset common infrastructure assumed that regsets
    would always have .get and .set methods, but necessarily
    .active methods. Unfortunately people have since written
    regsets without .set method, so NULL pointer dereference
    attacks were possible. (CVE-2012-1097)

  - Access to the /proc/pid/taskstats file requires root
    access to avoid side channel (timing keypresses etc.)
    attacks on other users. (CVE-2011-2494)

  - Fixed a oops in jbd/jbd2 that could be caused by
    specific filesystem access patterns. (CVE-2011-4086)

  - A malicious NFSv4 server could have caused a oops in the
    nfsv4 acl handling. (CVE-2011-4131)

  - Fixed a oops in jbd/jbd2 that could be caused by
    mounting a malicious prepared filesystem. (Also included
    are all fixes from the 3.0.14 -> 3.0.25 stable kernel
    updates.). (CVE-2011-4132)

The following non-security issues have been fixed :

EFI :

  - efivars: add missing parameter to efi_pstore_read().
    BTRFS :

  - add a few error cleanups.

  - btrfs: handle errors when excluding super extents
    (FATE#306586 bnc#751015).

  - btrfs: Fix missing goto in btrfs_ioctl_clone.

  - btrfs: Fixed mishandled -EAGAIN error case from
    btrfs_split_item. (bnc#750459)

  - btrfs: disallow unequal data/metadata blocksize for
    mixed block groups (FATE#306586).

  - btrfs: enhance superblock sanity checks (FATE#306586
    bnc#749651).

  - btrfs: update message levels (FATE#306586).

  - btrfs 3.3-rc6 updates :

  - avoid setting ->d_op twice (FATE#306586 bnc#731387).

  - btrfs: fix wrong information of the directory in the
    snapshot (FATE#306586).

  - btrfs: fix race in reada (FATE#306586).

  - btrfs: do not add both copies of DUP to reada extent
    tree (FATE#306586).

  - btrfs: stop silently switching single chunks to raid0 on
    balance (FATE#306586).

  - btrfs: fix locking issues in find_parent_nodes()
    (FATE#306586).

  - btrfs: fix casting error in scrub reada code
    (FATE#306586).

  - btrfs sync with upstream up to 3.3-rc5 (FATE#306586)

  - btrfs: Sector Size check during Mount

  - btrfs: avoid positive number with ERR_PTR

  - btrfs: return the internal error unchanged if
    btrfs_get_extent_fiemap() call failed for
    SEEK_DATA/SEEK_HOLE inquiry.

  - btrfs: fix trim 0 bytes after a device delete

  - btrfs: do not check DUP chunks twice

  - btrfs: fix memory leak in load_free_space_cache()

  - btrfs: delalloc for page dirtied out-of-band in fixup
    worker

  - btrfs: fix structs where bitfields and spinlock/atomic
    share 8B word.

  - btrfs: silence warning in raid array setup.

  - btrfs: honor umask when creating subvol root.

  - btrfs: fix return value check of extent_io_ops.

  - btrfs: fix deadlock on page lock when doing
    auto-defragment.

  - btrfs: check return value of lookup_extent_mapping()
    correctly.

  - btrfs: skip states when they does not contain bits to
    clear.

  - btrfs: kick out redundant stuff in convert_extent_bit.

  - btrfs: fix a bug on overcommit stuff.

  - btrfs: be less strict on finding next node in
    clear_extent_bit.

  - btrfs: improve error handling for btrfs_insert_dir_item
    callers.

  - btrfs: make sure we update latest_bdev.

  - btrfs: add extra sanity checks on the path names in
    btrfs_mksubvol.

  - btrfs: clear the extent uptodate bits during parent
    transid failures.

  - btrfs: increase the global block reserve estimates.

  - btrfs: fix compiler warnings on 32 bit systems.

  - Clean up unused code, fix use of error-indicated pointer
    in transaction teardown. (bnc#748854)

  - btrfs: fix return value check of extent_io_ops.

  - btrfs: fix deadlock on page lock when doing
    auto-defragment.

  - btrfs: check return value of lookup_extent_mapping()
    correctly.

  - btrfs: skip states when they does not contain bits to
    clear.

  - btrfs: kick out redundant stuff in convert_extent_bit.

  - btrfs: fix a bug on overcommit stuff.

  - btrfs: be less strict on finding next node in
    clear_extent_bit.

  - btrfs: do not reserve data with extents locked in
    btrfs_fallocate.

  - btrfs: avoid positive number with ERR_PTR.

  - btrfs: return the internal error unchanged if
    btrfs_get_extent_fiemap() call failed for
    SEEK_DATA/SEEK_HOLE inquiry.

  - btrfs: fix trim 0 bytes after a device delete.

  - btrfs: do not check DUP chunks twice.

  - btrfs: fix memory leak in load_free_space_cache().

  - btrfs: fix permissions of new subvolume. (bnc#746373)

  - btrfs: set ioprio of scrub readahead to idle.

  - fix logic in condition in
    BTRFS_FEATURE_INCOMPAT_MIXED_GROUPS

  - fix incorrect exclusion of superblock from blockgroups.
    (bnc#751743)

  -
    patches.suse/btrfs-8059-handle-errors-when-excluding-sup
    er-extents.patch: fix incorrect default value.

  - fix aio/dio bio refcounting bnc#718918.

  - btrfs: fix locking issues in find_parent_nodes()

  - Btrfs: fix casting error in scrub reada code

  -
    patches.suse/btrfs-8059-handle-errors-when-excluding-sup
    er-extents.patch: Fix uninitialized variable.

  - btrfs: handle errors from read_tree_block. (bnc#748632)

  - btrfs: push-up errors from btrfs_num_copies.
    (bnc#748632)

  -
    patches.suse/btrfs-8059-handle-errors-when-excluding-sup
    er-extents.patch: disable due to potential corruptions
    (bnc#751743) XFS :

  - XFS read/write calls do not generate DMAPI events.
    (bnc#751885)

  - xfs/dmapi: Remove cached vfsmount. (bnc#749417)

  - xfs: Fix oops on IO error during
    xlog_recover_process_iunlinks() (bnc#716850). NFS :

  - nfs: Do not allow multiple mounts on same mountpoint
    when using -o noac. (bnc#745422)

  - lockd: fix arg parsing for grace_period and timeout
    (bnc#733761). MD :

  - raid10: Disable recovery when recovery cannot proceed.
    (bnc#751171)

  - md/bitmap: ensure to load bitmap when creating via
    sysfs.

  - md: do not set md arrays to readonly on shutdown.
    (bnc#740180, bnc#713148, bnc#734900)

  - md: allow last device to be forcibly removed from
    RAID1/RAID10. (bnc#746717)

  - md: allow re-add to failed arrays. (bnc#746717)

  - md: Correctly handle read failure from last working
    device in RAID10. (bnc#746717)

  -
    patches.suse/0003-md-raid1-add-failfast-handling-for-wri
    tes.patch: Refresh to not crash when handling write
    error on FailFast devices. bnc#747159

  - md/raid10: Fix kernel oops during drive failure.
    (bnc#750995)

  - patches.suse/md-re-add-to-failed: Update references.
    (bnc#746717)

  - md/raid10: handle merge_bvec_fn in member devices.

  - md/raid10 - support resizing some RAID10 arrays. 
Hyper-V :

  - update hyperv drivers to 3.3-rc7 and move them out of
    staging: hv_timesource -> merged into core kernel
    hv_vmbus -> drivers/hv/hv_vmbus hv_utils ->
    drivers/hv/hv_utils hv_storvsc ->
    drivers/scsi/hv_storvsc hv_netvsc ->
    drivers/net/hyperv/hv_netvsc hv_mousevsc ->
    drivers/hid/hid-hyperv add compat modalias for
    hv_mousevsc update supported.conf rename all 333
    patches, use msft-hv- and suse-hv- as prefix

  - net/hyperv: Use netif_tx_disable() instead of
    netif_stop_queue() when necessary.

  - net/hyperv: rx_bytes should account the ether header
    size.

  - net/hyperv: fix the issue that large packets be dropped
    under bridge.

  - net/hyperv: Fix the page buffer when an RNDIS message
    goes beyond page boundary.

  - net/hyperv: fix erroneous NETDEV_TX_BUSY use. SCSI :

  - sd: mark busy sd majors as allocated (bug#744658).

  - st: expand tape driver ability to write immediate
    filemarks. (bnc#688996)

  - scsi scan: do not fail scans when host is in recovery
    (bnc#747867). S/390 :

  - dasd: Implement block timeout handling. (bnc#746717)

  - callhome: fix broken proc interface and activate compid
    (bnc#748862,LTC#79115).

  - ctcmpc: use correct idal word list for ctcmpc
    (bnc#750173,LTC#79264).

  - Fix recovery in case of concurrent asynchronous
    deliveries (bnc#748629,LTC#78309).

  - kernel: 3215 console deadlock (bnc#748629,LTC#78612).

  - qeth: synchronize discipline module loading
    (bnc#748629,LTC#78788).

  - memory hotplug: prevent memory zone interleave
    (bnc#748629,LTC#79113).

  - dasd: fix fixpoint divide exception in define_extent
    (bnc#748629,LTC#79125).

  - kernel: incorrect kernel message tags
    (bnc#744795,LTC#78356).

  - lcs: lcs offline failure (bnc#752484,LTC#79788).

  - qeth: add missing wake_up call (bnc#752484,LTC#79899).

  - dasd: Terminate inactive cqrs correctly. (bnc#750995)

  - dasd: detailed I/O errors. (bnc#746717)

  - patches.suse/dasd-blk-timeout.patch: Only activate
    blk_timeout for failfast requests (bnc#753617). ALSA :

  - ALSA: hda - Set codec to D3 forcibly even if not used.
    (bnc#750426)

  - ALSA: hda - Add Realtek ALC269VC codec support.
    (bnc#748827)

  - ALSA: hda/realtek - Apply the coef-setup only to
    ALC269VB. (bnc#748827)

  - ALSA: pcm - Export snd_pcm_lib_default_mmap() helper.
    (bnc#748384,bnc#738597)

  - ALSA: hda - Add snoop option. (bnc#748384,bnc#738597)

  - ALSA: HDA: Add support for new AMD products.
    (bnc#748384,bnc#738597)

  - ALSA: hda - Fix audio playback support on HP Zephyr
    system. (bnc#749787)

  - ALSA: hda - Fix mute-LED VREF value for new HP laptops
    (bnc#745741). EXT3 :

  - enable
    patches.suse/ext3-increase-reservation-window.patch. 
DRM :

  - drm/i915: Force explicit bpp selection for
    intel_dp_link_required. (bnc#749980)

  - drm/i915/dp: Dither down to 6bpc if it makes the mode
    fit. (bnc#749980)

  - drm/i915/dp: Read more DPCD registers on connection
    probe. (bnc#749980)

  - drm/i915: fixup interlaced bits clearing in PIPECONF on
    PCH_SPLIT. (bnc#749980)

  - drm/i915: read full receiver capability field during DP
    hot plug. (bnc#749980)

  - drm/intel: Fix initialization if startup happens in
    interlaced mode [v2]. (bnc#749980)

  - drm/i915 IVY/SNB fix patches from upstream 3.3-rc5 &amp;
    rc6:
    patches.drivers/drm-i915-Prevent-a-machine-hang-by-check
    ing-crtc-act,
    patches.drivers/drm-i915-do-not-enable-RC6p-on-Sandy-Bri
    dge,
    patches.drivers/drm-i915-fix-operator-precedence-when-en
    abling-RC6p,
    patches.drivers/drm-i915-gen7-Disable-the-RHWO-optimizat
    ion-as-it-ca,
    patches.drivers/drm-i915-gen7-Implement-an-L3-caching-wo
    rkaround,
    patches.drivers/drm-i915-gen7-implement-rczunit-workarou
    nd,
    patches.drivers/drm-i915-gen7-work-around-a-system-hang-
    on-IVB

  - drm/i915: Clear the TV sense state bits on cantiga to
    make TV detection reliable. (bnc#750041)

  - drm/i915: Do not write DSPSURF for old chips.
    (bnc#747071)

  - drm: Do not delete DPLL Multiplier during DAC init.
    (bnc#728840)

  - drm: Set depth on low mem Radeon cards to 16 instead of
    8. (bnc#746883)

  - patches.drivers/drm-i915-set-AUD_CONFIG_N_index-for-DP:
    Refresh. Updated the patch from the upstream.
    (bnc#722560)

  - Add a few missing drm/i915 fixes from upstream 3.2
    kernel (bnc#744392) :

  - drm/i915: Sanitize BIOS debugging bits from PIPECONF.
    (bnc#751916)

  - drm/i915: Add lvds_channel module option. (bnc#739837)

  - drm/i915: Check VBIOS value for determining LVDS dual
    channel mode, too. (bnc#739837)

  - agp: fix scratch page cleanup. (bnc#738679)

  - drm/i915: suspend fbdev device around suspend/hibernate
    (bnc#732908). ACPI :

  - supported.conf: Add acpi_ipmi as supported (bnc#716971).
    MM :

  - cpusets: avoid looping when storing to mems_allowed if
    one.

  - cpusets: avoid stall when updating mems_allowed for
    mempolicy.

  - cpuset: mm: Reduce large amounts of memory barrier
    related slowdown.

  - mm: make swapin readahead skip over holes.

  - mm: allow PF_MEMALLOC from softirq context.

  - mm: Ensure processes do not remain throttled under
    memory pressure. (Swap over NFS (fate#304949,
    bnc#747944).

  - mm: Allow sparsemem usemap allocations for very large
    NUMA nodes. (bnc#749049)

  - backing-dev: fix wakeup timer races with
    bdi_unregister(). (bnc#741824)

  - readahead: fix pipeline break caused by block plug.
    (bnc#746454)

  - Fix uninitialised variable warning and obey the
    [get|put]_mems_allowed API. CIFS :

  - cifs: fix dentry refcount leak when opening a FIFO on
    lookup (CVE-2012-1090 / bnc#749569). USB :

  - xhci: Fix encoding for HS bulk/control NAK rate.
    (bnc#750402)

  - USB: Fix handoff when BIOS disables host PCI device.
    (bnc#747878)

  - USB: Do not fail USB3 probe on missing legacy PCI IRQ.
    (bnc#749543)

  - USB: Adding #define in hub_configure() and hcd.c file.
    (bnc#714604)

  - USB: remove BKL comments. (bnc#714604)

  - xHCI: Adding #define values used for hub descriptor.
    (bnc#714604)

  - xHCI: Kick khubd when USB3 resume really completes.
    (bnc#714604)

  - xhci: Fix oops caused by more USB2 ports than USB3
    ports. (bnc#714604)

  - USB/xhci: Enable remote wakeup for USB3 devices.
    (bnc#714604)

  - USB: Suspend functions before putting dev into U3.
    (bnc#714604)

  - USB/xHCI: Enable USB 3.0 hub remote wakeup. (bnc#714604)

  - USB: Refactor hub remote wake handling. (bnc#714604)

  - USB/xHCI: Support device-initiated USB 3.0 resume.
    (bnc#714604)

  - USB: Set wakeup bits for all children hubs. (bnc#714604)

  - USB: Turn on auto-suspend for USB 3.0 hubs. (bnc#714604)

  - USB: Set hub depth after USB3 hub reset. (bnc#749115)

  - xhci: Fix USB 3.0 device restart on resume. (bnc#745867)

  - xhci: Remove scary warnings about transfer issues.
    (bnc#745867)

  - xhci: Remove warnings about MSI and MSI-X capabilities
    (bnc#745867). Other :

  - PCI / PCIe: Introduce command line option to disable
    ARI. (bnc#742845)

  - PCI: Set device power state to PCI_D0 for device without
    native PM support (bnc#752972). X86 :

  - x86/UV: Lower UV rtc clocksource rating. (bnc#748456)

  - x86, mce, therm_throt: Do not report power limit and
    package level thermal throttle events in mcelog.
    (bnc#745876)

  - x86: Unlock nmi lock after kdb_ipi call. (bnc#745424)

  - x86, tsc: Fix SMI induced variation in
    quick_pit_calibrate(). (bnc#751322) XEN :

  - Update Xen patches to 3.0.22.

  - xenbus_dev: add missing error checks to watch handling.

  - drivers/xen/: use strlcpy() instead of strncpy().

  - xenoprof: backward compatibility for changed
    XENOPROF_ESCAPE_CODE.

  - blkfront: properly fail packet requests. (bnc#745929)

  - Refresh other Xen patches. (bnc#732070, bnc#742871)

  - xenbus: do not free other end details too early.

  - blkback: also call blkif_disconnect() when frontend
    switched to closed.

  - gnttab: add deferred freeing logic.

  - blkback: failure to write 'feature-barrier' node is
    non-fatal. Infiniband :

  - RDMA/cxgb4: Make sure flush CQ entries are collected on
    connection close. (bnc#721587)

  - RDMA/cxgb4: Serialize calls to CQs comp_handler.
    (bnc#721587)

  - mlx4_en: Assigning TX irq per ring (bnc#624072).
    Bluetooth :

  - Bluetooth: Add Atheros AR3012 Maryann PID/VID supported
    in ath3k. (bnc#732296)

  - Bluetooth: btusb: fix bInterval for high/super speed
    isochronous endpoints (bnc#754052). SCTP :

  - dlm: Do not allocate a fd for peeloff. (bnc#729247)

  - sctp: Export sctp_do_peeloff (bnc#729247). Other :

  - qlge: Removing needless prints which are not.
    (bnc#718863)

  - ibft: Fix finding IBFT ACPI table on UEFI. (bnc#746579)

  - proc: Consider NO_HZ when printing idle and iowait
    times. (bnc#705551)

  - procfs: do not confuse jiffies with cputime64_t.
    (bnc#705551)

  - procfs: do not overflow get_{idle,iowait}_time for nohz.
    (bnc#705551)

  - bfa: Do not return DID_ABORT on failure. (bnc#745400)

  - epoll: Do not limit non-nested epoll paths. (bnc#676204)

  - Bridge: Always send NETDEV_CHANGEADDR up on br MAC
    change. (bnc#752408)

  - hp_accel: Ignore the error from lis3lv02d_poweron() at
    resume. (bnc#751903)

  - watchdog: make sure the watchdog thread gets CPU on
    loaded system. (bnc#738583)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=624072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=676204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=688996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=703156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=705551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=713148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=716850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=716971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=718863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=718918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=721587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=722560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=728840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=729247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=730117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=730118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=733761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=734900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=735909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=739837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=741824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4086.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4127.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4131.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4132.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1097.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1146.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1179.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 6163 / 6164 / 6172 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-extra-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-extra-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-source-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-extra-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-extra-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-devel-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-extra-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-source-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-syms-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-devel-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-extra-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-extra-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-devel-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-source-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-syms-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-devel-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-devel-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-man-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.26-0.7.6")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.26-0.7.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
