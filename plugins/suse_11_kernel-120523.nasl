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
  script_id(64174);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:46:55 $");

  script_cve_id("CVE-2012-2127", "CVE-2012-2133", "CVE-2012-2313", "CVE-2012-2319");

  script_name(english:"SuSE 11.2 Security Update : Linux Kernel (SAT Patch Numbers 6338 / 6345 / 6349)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP2 kernel was updated to 3.0.31, fixing
many bugs and security issues.

Various security and bug fixes contained in the Linux 3.0 stable
releases 3.0.27 up to 3.0.31 have been included, but are not
explicitly listed below.

The following notable security issues have been fixed :

  - The dl2k network card driver lacked permission handling
    for some ethtool ioctls, which could allow local
    attackers to start/stop the network card.
    (CVE-2012-2313)

  - A use after free bug in hugetlb support could be used by
    local attackers to crash the system. (CVE-2012-2133)

  - Various leaks in namespace handling over fork where
    fixed, which could be exploited by e.g. vsftpd access by
    remote users. (CVE-2012-2127)

  - A memory corruption when mounting a hfsplus filesystem
    was fixed that could be used by local attackers able to
    mount filesystem to crash the system. (CVE-2012-2319)

The following non security bugs have been fixed by this update :

  - BTRFS

  - Partial revert of truncation improvements.

  - Fix eof while discarding extents.

  - Check return value of bio_alloc() properly.

  - Return void from clear_state_bit.

  - Avoid possible use-after-free in clear_extent_bit().

  - Make free_ipath() deal gracefully with NULL pointers.

  - Do not call free_extent_buffer twice in iterate_irefs.

  - Add missing read locks in backref.c.

  - Fix max chunk size check in chunk allocator.

  - Double unlock bug in error handling.

  - Do not return EINTR.

  - Fix btrfs_ioctl_dev_info() crash on missing device.

  - Fix that check_int_data mount option was ignored.

  - Do not mount when we have a sectorsize unequal to
    PAGE_SIZE.

  - Avoid possible use-after-free in clear_extent_bit().

  - Retrurn void from clear_state_bit.

  - Fix typo in free-space-cache.c.

  - Remove the ideal caching code.

  - Remove search_start and search_end from find_free_extent
    and callers.

  - Adjust the write_lock_level as we unlock.

  - Actually call btrfs_init_lockdep.

  - Fix regression in scrub path resolving.

  - Show useful info in space reservation tracepoint.

  - Flush out and clean up any block device pages during
    mount.

  - Fix deadlock during allocating chunks.

  - Fix race between direct io and autodefrag.

  - Fix the mismatch of page->mapping.

  - Fix recursive defragment with autodefrag option.

  - Add a check to decide if we should defrag the range.

  - Do not bother to defrag an extent if it is a big real
    extent.

  - Update to the right index of defragment.

  - Fix use-after-free in __btrfs_end_transaction.

  - Stop silently switching single chunks to raid0 on
    balance.

  - Add wrappers for working with alloc profiles.

  - Make profile_is_valid() check more strict.

  - Move alloc_profile_is_valid() to volumes.c.

  - Add get_restripe_target() helper.

  - Add __get_block_group_index() helper.

  - Improve the logic in btrfs_can_relocate().

  - Validate target profiles only if we are going to use
    them.

  - Allow dup for data chunks in mixed mode.

  - Fix memory leak in resolver code.

  - Fix infinite loop in btrfs_shrink_device().

  - Error handling locking fixu.

  - Fix uninit variable in repair_eb_io_failure.

  - Always store the mirror we read the eb from.

  - Do not count CRC or header errors twice while scrubbing.

  - Do not start delalloc inodes during sync.

  - Fix repair code for RAID10.

  - Prevent root_list corruption.

  - Fix block_rsv and space_info lock ordering.

  - Fix space checking during fs resize.

  - Avoid deadlocks from GFP_KERNEL allocations during
    btrfs_real_readdir().

  - Reduce lock contention during extent insertion.

  - Add properly locking around add_root_to_dirty_list().

  - Fix mismatching struct members in ioctl.h.

  - netfilter :

  - nf_conntrack: make event callback registration per
    netns.

  - DRM :

  - edid: Add a workaround for 1366x768 HD panel.

  - edid: Add extra_modes.

  - edid: Add packed attribute to new gtf2 and cvt structs.

  - edid: Add the reduced blanking DMT modes to the DMT list

  - edid: Allow drm_mode_find_dmt to hunt for
    reduced-blanking modes.

  - edid: Do drm_dmt_modes_for_range() for all range
    descriptor types.

  - edid: Document drm_mode_find_dmt.

  - edid: Fix some comment typos in the DMT mode list

  - edid: Generate modes from extra_modes for range
    descriptors

  - edid: Give the est3 mode struct a real name.

  - edid: Remove a misleading comment.

  - edid: Rewrite drm_mode_find_dmt search loop.

  - edid: Update range descriptor struct for EDID 1.4

  - edid: add missing NULL checks.

  - edid: s/drm_gtf_modes_for_range/drm_dmt_modes_for_range/

  - Fix kABI for drm EDID improvement patches.

  - Fix the case where multiple modes are returned from EDID

  - i915: Add more standard modes to LVDS output.

  - i915: Disable LVDS at mode change.

  - i915: add Ivy Bridge GT2 Server entries.

  - i915: delay drm_irq_install() at resume.

  - EDD: Check for correct EDD 3.0 length.

  - XEN

  - blkfront: make blkif_io_lock spinlock per-device.

  - blkback: streamline main processing loop (fate#309305).

  - blkback: Implement discard requests handling
    (fate#309305).

  - blkback: Enhance discard support with secure erasing
    support (fate#309305).

  - blkfront: Handle discard requests (fate#309305).

  - blkfront: Enhance discard support with secure erasing
    support (fate#309305).

  - blkif: support discard (fate#309305).

  - blkif: Enhance discard support with secure erasing
    support (fate#309305).

  - xen/smpboot: adjust ordering of operations.

  - x86-64: provide a memset() that can deal with 4Gb or
    above at a time.

  - Update Xen patches to 3.0.27.

  - Update Xen patches to 3.0.31.

  - xen: fix VM_FOREIGN users after c/s 878:eba6fe6d8d53.

  - xen/gntdev: fix multi-page slot allocation.

  - TG3

  - Avoid panic from reserved statblk field access.

  - Fix 5717 serdes powerdown problem.

  - Fix RSS ring refill race condition.

  - Fix single-vector MSI-X code.

  - fix ipv6 header length computation.

  - S/390

  - dasd: Fix I/O stall when reserving dasds.

  - af_iucv: detect down state of HS transport interface
    (LTC#80859).

  - af_iucv: allow shutdown for HS transport sockets
    (LTC#80860).

  - mm: s390: Fix BUG by using __set_page_dirty_no_writeback
    on swap.

  - qeth: Improve OSA Express 4 blkt defaults (LTC#80325).

  - zcrypt: Fix parameter checking for ZSECSENDCPRB ioctl
    (LTC#80378).

  - zfcpdump: Implement async sdias event processing
    (LTC#81330).

  - ALSA

  - hda: Always resume the codec immediately.

  - hda: Add Creative CA0132 HDA codec support.

  - hda: Fix error handling in patch_ca0132.c.

  - hda: Add the support for Creative SoundCore3D.

  - OTHER

  - ixgbe: fix ring assignment issues for SR-IOV and drop
    cases.

  - ixgbe: add missing rtnl_lock in PM resume path.

  - MCE, AMD: Drop too granulary family model checks.

  - EDAC, MCE, AMD: Print CPU number when reporting the
    error.

  - EDAC, MCE, AMD: Print valid addr when reporting an
    error.

  - libata: skip old error history when counting probe
    trials.

  - x86: kdb: restore kdb stack trace.

  - ehea: fix allmulticast support,

  - ehea: fix promiscuous mode.

  - ehea: only register irq after setting up ports.

  - ehea: fix losing of NEQ events when one event occurred
    early.

  - scsi: Silence unnecessary warnings about ioctl to
    partition.

  - scsi_dh_rdac: Update match function to check page C8.

  - scsi_dh_rdac: Add new NetApp IDs.

  - bluetooth: Add support for Foxconn/Hon Hai AR5BBU22
    0489:E03C.

  - x86/amd: Add missing feature flag for fam15h models
    10h-1fh processors.

  - x86: Report cpb and eff_freq_ro flags correctly.

  - x86, amd: Fix up numa_node information for AMD CPU
    family 15h model 0-0fh northbridge functions.

  - x86/PCI: amd: Kill misleading message about enablement
    of IO access to PCI ECS.

  - cdc-wdm: fix race leading leading to memory corruption.

  - tlan: add cast needed for proper 64 bit operation.

  - bonding:update speed/duplex for NETDEV_CHANGE.

  - bonding: comparing a u8 with -1 is always false.

  - bonding: start slaves with link down for ARP monitor.

  - bonding: do not increase rx_dropped after processing
    LACPDUs

  - x86: fix the initialization of physnode_map.

  - sched,rt: fix isolated CPUs leaving root_task_group
    indefinitely throttled.

  - Fix SLE11-SP1->SLE11-SP2 interrupt latency regression.
    Note that this change trades an approximately 400%
    latency regression fix for power consumption progression
    that skew removal bought (at high cost).

  - Revert mainline 0209f649 - rcu: limit rcu_node
    leaf-level fanout.

  - md: fix possible corruption of array metadata on
    shutdown.

  - md/bitmap: prevent bitmap_daemon_work running while
    initialising bitmap.

  - md: ensure changes to write-mostly are reflected in
    metadata.

  - cciss: Add IRQF_SHARED back in for the non-MSI(X)
    interrupt handler.

  - procfs, namespace, pid_ns: fix leakage upon fork()
    failure.

  - mqueue: fix a vfsmount longterm reference leak.

  - procfs: fix a vfsmount longterm reference leak.

  - scsi_dh_alua: Optimize stpg command.

  - scsi_dh_alua: Store pref bit from RTPG.

  - scsi_dh_alua: set_params interface.

  - uwb: fix error handling.

  - uwb: fix use of del_timer_sync() in interrupt.

  - usbhid: fix error handling of not enough bandwidth.

  - mm: Improve preservation of page-age information

  - pagecache limit: Fix the shmem deadlock.

  - USB: sierra: add support for Sierra Wireless MC7710.

  - USB: fix resource leak in xhci power loss path.

  - x86/iommu/intel: Fix identity mapping for sandy bridge.

  - ipv6: Check dest prefix length on original route not
    copied one in rt6_alloc_cow().

  - ipv6: do not use inetpeer to store metrics for routes.

  - ipv6: fix problem with expired dst cache.

  - ipv6: unshare inetpeers.

  - bridge: correct IPv6 checksum after pull.

  - scsi: storvsc: Account for in-transit packets in the
    RESET path.

  -
    patches.fixes/mm-mempolicy.c-fix-pgoff-in-mbind-vma-merg
    e.patch :

  -
    patches.fixes/mm-mempolicy.c-refix-mbind_range-vma-issue
    .patch: Fix vma merging issue during mbind affecting
    JVMs.

  - ACPI, APEI: Fix incorrect APEI register bit width check
    and usage.

  - vmxnet3: cap copy length at size of skb to prevent
    dropped frames on tx.

  - rt2x00: rt2x00dev: move rfkill_polling register to
    proper place.

  - pagecache: fix the BUG_ON safety belt

  - pagecache: Fixed the GFP_NOWAIT is zero and not suitable
    for tests bug

  - igb: reset PHY after recovering from PHY power down.

  - igb: fix rtnl race in PM resume path.

  - watchdog: iTCO_wdt.c - problems with newer hardware due
    to SMI clearing.

  - watchdog: iTCO_wdt.c - problems with newer hardware due
    to SMI clearing redhat#727875).

  - cfq-iosched: Reduce linked group count upon group
    destruction.

  - cdc_ether: Ignore bogus union descriptor for RNDIS
    devices.

  - sys_poll: fix incorrect type for timeout parameter.

  - staging:rts_pstor:Avoid 'Bad target number' message when
    probing driver.

  - staging:rts_pstor:Complete scanning_done variable.

  - staging:rts_pstor:Fix SDIO issue.

  - staging:rts_pstor: Fix a bug that a MMCPlus card ca not
    be accessed.

  - staging:rts_pstor: Fix a miswriting.

  - staging:rts_pstor:Fix possible panic by NULL pointer
    dereference.

  - staging:rts_pstor: fix thread synchronization flow.

  - freezer:do not unnecessarily set PF_NOFREEZE explicitly.

  - staging:rts_pstor: off by one in for loop.

  - patches.suse/cgroup-disable-memcg-when-low-lowmem.patch:
    fix typo: use if defined(CONFIG_) rather than if CONFIG_"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=704280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=708836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=718521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=721857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=725592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=743232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=753172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=753698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=761158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=761387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=761772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2127.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2133.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2313.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2319.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 6338 / 6345 / 6349 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-extra-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-extra-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-source-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-extra-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-extra-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-devel-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-extra-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-source-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-syms-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-devel-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-extra-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-extra-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-devel-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-source-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-syms-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-devel-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-devel-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-man-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.31-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.31-0.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
