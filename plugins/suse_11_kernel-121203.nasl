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
  script_id(64180);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/20 15:05:37 $");

  script_cve_id("CVE-2012-1601", "CVE-2012-2372", "CVE-2012-3412", "CVE-2012-3430", "CVE-2012-4461", "CVE-2012-4508", "CVE-2012-5517");

  script_name(english:"SuSE 11.2 Security Update : Linux kernel (SAT Patch Numbers 7123 / 7127)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP2 kernel has been updated to 3.0.51
which fixes various bugs and security issues.

It contains the following feature enhancements :

  - The cachefiles framework is now supported (FATE#312793,
    bnc#782369). The userland utilities were published
    seperately to support this feature.

  - The ipset netfilter modules are now supported
    (FATE#313309) The ipset userland utility will be
    published seperately to support this feature.

  - The tipc kernel module is now externally supported
    (FATE#305033).

  - Hyper-V KVP IP injection was implemented (FATE#314441).
    A seperate hyper-v package will be published to support
    this feature.

  - Intel Lynx Point PCH chipset support was added.
    (FATE#313409)

  - Enable various md/raid10 and DASD enhancements.
    (FATE#311379) These make it possible for RAID10 to cope
    with DASD devices being slow for various reasons - the
    affected device will be temporarily removed from the
    array.

    Also added support for reshaping of RAID10 arrays.

    mdadm changes will be published to support this feature.

The following security issues have been fixed :

  - A race condition on hot adding memory could be used by
    local attackers to crash the system during hot adding
    new memory. (CVE-2012-5517)

  - A flaw has been found in the way Linux kernels KVM
    subsystem handled vcpu->arch.cr4 X86_CR4_OSXSAVE bit set
    upon guest enter. On hosts without the XSAVE feature and
    using qemu userspace an unprivileged local user could
    have used this flaw to crash the system. (CVE-2012-4461)

  - The KVM implementation in the Linux kernel allowed host
    OS users to cause a denial of service (NULL pointer
    dereference and host OS crash) by making a
    KVM_CREATE_IRQCHIP ioctl call after a virtual CPU
    already exists. (CVE-2012-1601)

  - Attempting an rds connection from the IP address of an
    IPoIB interface to itself causes a kernel panic due to a
    BUG_ON() being triggered. Making the test less strict
    allows rds-ping to work without crashing the machine. A
    local unprivileged user could use this flaw to crash the
    sytem. (CVE-2012-2372)

  - Dimitry Monakhov, one of the ext4 developers, has
    discovered a race involving asynchronous I/O and
    fallocate which can lead to the exposure of stale data
    --- that is, an extent which should have had the
    'uninitialized' bit set indicating that its blocks have
    not yet been written and thus contain data from a
    deleted file will get exposed to anyone with read access
    to the file. (CVE-2012-4508)

  - The rds_recvmsg function in net/rds/recv.c in the Linux
    kernel did not initialize a certain structure member,
    which allows local users to obtain potentially sensitive
    information from kernel stack memory via a (1) recvfrom
    or (2) recvmsg system call on an RDS socket.
    (CVE-2012-3430)

  - The sfc (aka Solarflare Solarstorm) driver in the Linux
    kernel allowed remote attackers to cause a denial of
    service (DMA descriptor consumption and
    network-controller outage) via crafted TCP packets that
    trigger a small MSS value. (CVE-2012-3412)

The following non-security issues have been fixed :

BTRFS :

  - btrfs: fix double mntput() in mount_subvol().

  - btrfs: use common work instead of delayed work

  - btrfs: limit fallocate extent reservation to 256MB

  - btrfs: fix a double free on pending snapshots in error
    handling

  - btrfs: Do not trust the superblock label and simply
    printk('%s') it

  - patches.suse/btrfs-update-message-levels.patch: Refresh.

  - patches.suse/btrfs-enospc-debugging-messages.patch:
    Minor updates.

  - patches.suse/btrfs-update-message-levels.patch: Minor
    updates.

  - btrfs: continue after abort during snapshot drop.
    (bnc#752067)

  - btrfs: Return EINVAL when length to trim is less than
    FSB.

  - btrfs: fix unnecessary while loop when search the free
    space, cache.

  - btrfs: Use btrfs_update_inode_fallback when creating a
    snapshot.

  - btrfs: do not bug when we fail to commit the
    transaction.

  - btrfs: fill the global reserve when unpinning space.

  - btrfs: do not allow degraded mount if too many devices
    are missing.

  -
    patches.suse/btrfs-8112-resume-balance-on-rw-re-mounts-p
    roperly.patch: fix mismerge.

  - btrfs: do not allocate chunks as agressively.

  - btrfs: btrfs_drop_extent_cache should never fail.

  - btrfs: fix full backref problem when inserting shared
    block reference.

  - btrfs: wait on async pages when shrinking delalloc.

  - btrfs: remove bytes argument from do_chunk_alloc.

  - btrfs: cleanup of error processing in
    btree_get_extent().

  - btrfs: remove unnecessary code in btree_get_extent().

  - btrfs: kill obsolete arguments in
    btrfs_wait_ordered_extents.

  - btrfs: do not do anything in our ->freeze_fs and
    ->unfreeze_fs.

  - btrfs: do not async metadata csumming in certain
    situations.

  - btrfs: do not hold the file extent leaf locked when
    adding extent item.

  - btrfs: cache extent state when writing out dirty
    metadata pages.

  - btrfs: do not lookup csums for prealloc extents.

  - btrfs: be smarter about dropping things from the tree
    log.

  - btrfs: confirmation of value is added before
    trace_btrfs_get_extent() is called.

  - btrfs: make filesystem read-only when submitting barrier
    fails.

  - btrfs: cleanup pages properly when ENOMEM in
    compression.

  - btrfs: do not bug on enomem in readpage.

  - btrfs: do not warn_on when we cannot alloc a page for an
    extent buffer.

  - btrfs: enospc debugging messages. S/390 :

  - smsgiucv: reestablish IUCV path after resume
    (bnc#786976,LTC#86245).

  - dasd: move wake_up call (bnc#786976,LTC#86252).

  - kernel: fix get_user_pages_fast() page table walk
    (bnc#786976,LTC#86307).

  - qeth: Fix IPA_CMD_QIPASSIST return code handling
    (bnc#785851,LTC#86101).

  - mm: Fix XFS oops due to dirty pages without buffers on
    s390. (bnc#762259)

  - zfcp: only access zfcp_scsi_dev for valid scsi_device
    (bnc#781484,LTC#85285).

  - dasd: check count address during online setting
    (bnc#781484,LTC#85346).

  - hugetlbfs: fix deadlock in unmap_hugepage_range()
    (bnc#781484,LTC#85449).

  - kernel: make user-access pagetable walk code huge page
    aware (bnc#781484,LTC#85455).

  - hugetlbfs: add missing TLB invalidation
    (bnc#781484,LTC#85463).

  - zfcp: fix adapter (re)open recovery while link to SAN is
    down (bnc#789010,LTC#86283).

  - qeth: set new mac even if old mac is gone
    (bnc#789010,LTC#86643).

  - qdio: fix kernel panic for zfcp 31-bit
    (bnc#789010,LTC#86623).

  - crypto: msgType50 (RSA-CRT) Fix (bnc#789010,LTC#86378).
    DRM :

  - drm/915: Update references, fixed a missing patch chunk.
    (bnc#725355)

  - drm/dp: Document DP spec versions for various DPCD
    registers. (bnc#780461)

  - drm/dp: Make sink count DP 1.2 aware. (bnc#780461)

  - DRM/i915: Restore sdvo_flags after dtd->mode->dtd
    Roundrtrip. (bnc#775577)

  - DRM/i915: Do not clone SDVO LVDS with analog.
    (bnc#766410)

  - DRM/radeon: For single CRTC GPUs move handling of
    CRTC_CRT_ON to crtc_dpms(). (bnc#725152)

  - DRM/Radeon: Fix TV DAC Load Detection for single CRTC
    chips. (bnc#725152)

  - DRM/Radeon: Clean up code in TV DAC load detection.
    (bnc#725152)

  - DRM/Radeon: On DVI-I use Load Detection when EDID is
    bogus. (bnc#725152)

  - DRM/Radeon: Fix primary DAC Load Detection for RV100
    chips. (bnc#725152)

  - DRM/Radeon: Fix Load Detection on legacy primary DAC.
    (bnc#725152)

  - drm/i915: enable plain RC6 on Sandy Bridge by default
    (bnc#725355). Hyper-V :

  - Hyper-V KVP IP injection (fate#31441) :

  - drivers: net: Remove casts to same type.

  - drivers: hv: remove IRQF_SAMPLE_RANDOM which is now a
    no-op.

  - hyperv: Move wait completion msg code into
    rndis_filter_halt_device().

  - hyperv: Add comments for the extended buffer after RNDIS
    message.

  - Drivers: hv: Cleanup the guest ID computation.

  - Drivers: hv: vmbus: Use the standard format string to
    format GUIDs.

  - Drivers: hv: Add KVP definitions for IP address
    injection.

  - Drivers: hv: kvp: Cleanup error handling in KVP.

  - Drivers: hv: kvp: Support the new IP injection messages.

  - Tools: hv: Prepare to expand kvp_get_ip_address()
    functionality.

  - Tools: hv: Further refactor kvp_get_ip_address().

  - Tools: hv: Gather address family information.

  - Tools: hv: Gather subnet information.

  - Tools: hv: Represent the ipv6 mask using CIDR notation.

  - Tools: hv: Gather ipv[4,6] gateway information.

  - hv: fail the probing immediately when we are not in
    hyperv platform.

  - hv: vmbus_drv: detect hyperv through x86_hyper.

  - Tools: hv: Get rid of some unused variables.

  - Tools: hv: Correctly type string variables.

  - Tools: hv: Add an example script to retrieve DNS
    entries.

  - Tools: hv: Gather DNS information.

  - Drivers: hv: kvp: Copy the address family information.

  - Tools: hv: Add an example script to retrieve dhcp state.

  - Tools: hv: Gather DHCP information.

  - Tools: hv: Add an example script to configure an
    interface.

  - Tools: hv: Implement the KVP verb - KVP_OP_SET_IP_INFO.

  - Tools: hv: Rename the function kvp_get_ip_address().

  - Tools: hv: Implement the KVP verb - KVP_OP_GET_IP_INFO.

  - tools/hv: Fix file handle leak.

  - tools/hv: Fix exit() error code.

  - tools/hv: Check for read/write errors.

  - tools/hv: Parse /etc/os-release.

  - hyperv: Fix the max_xfer_size in RNDIS initialization.

  - hyperv: Fix the missing return value in
    rndis_filter_set_packet_filter().

  - hyperv: Fix page buffer handling in
    rndis_filter_send_request().

  - hyperv: Remove extra allocated space for recv_pkt_list
    elements.

  - hyperv: Report actual status in receive completion
    packet.

  - hyperv: Add buffer for extended info after the RNDIS
    response message. Other :

  - net: prevent NULL dereference in check_peer_redir().
    (bnc#776044 / bnc#784576)

  -
    patches.fixes/mm-hotplug-correctly-add-zone-to-other-nod
    es-list.patch: Refresh.

  - igb: fix recent VLAN changes that would leave VLANs
    disabled after reset. (bnc#787168)

  - md: Change goto target to avoid pointless bug messages
    in normal error cases. (bnc#787848)

  - intel_idle: IVB support (fate#313719).

  - x86 cpufreq: Do not complain on missing cpufreq tables
    on ProLiants. (bnc#787202)

  - hpilo: remove pci_disable_device. (bnc#752544)

  - ixgbe: Address fact that RSC was not setting GSO size
    for incoming frames. (bnc#776144)

  - hv: Cleanup error handling in vmbus_open().

  - [SCSI] storvsc: Account for in-transit packets in the
    RESET path.

  - sg: remove sg_mutex. (bnc#785496)

  - perf: Do no try to schedule task events if there are
    none. (bnc#781574)

  - perf: Do not set task_ctx pointer in cpuctx if there are
    no events in the context. (bnc#781574)

  - mm: swap: Implement generic handlers for swap-related
    address ops fix. (bnc#778334)

  - hpwdt: Only BYTE reads/writes to WD Timer port 0x72.

  - xenbus: fix overflow check in xenbus_dev_write().

  - xen/x86: do not corrupt %eip when returning from a
    signal handler.

  - Update Xen patches to 3.0.46.

  - Update Xen patches to 3.0.51.

  - mm: Check if PTE is already allocated during page fault.

  - rpm/kernel-binary.spec.in: Revert f266e647f to allow
    building with icecream again, as
    patches.rpmify/kbuild-fix-gcc-x-syntax.patch is a real
    fix now.

  - ipmi: decrease the IPMI message transaction time in
    interrupt mode. (bnc#763654)

  - ipmi: simplify locking. (bnc#763654)

  - ipmi: use a tasklet for handling received messages.
    (bnc#763654)

  - cxgb3: Set vlan_feature on net_device (bnc#776127,
    LTC#84260).

  - qlge: Add offload features to vlan interfaces
    (bnc#776081,LTC#84322).

  - mlx4_en: Added missing iounmap upon releasing a device
    (bnc#774964,LTC#82768).

  - mlx4: allow device removal by fixing dma unmap size
    (bnc#774964,LTC#82768).

  - qeth: fix deadlock between recovery and bonding driver
    (bnc#785100,LTC#85905).

  - SCSI st: add st_nowait_eof param to module. (bnc#775394)

  -
    patches.fixes/sched-fix-migration-thread-accounting-woes
    .patch: Update references. (bnc#773699, bnc#769251)

  - memcg: oom: fix totalpages calculation for
    swappiness==0. (bnc#783965)

  - fs: cachefiles: add support for large files in
    filesystem caching (FATE#312793, bnc#782369).

  - mm/mempolicy.c: use enum value MPOL_REBIND_ONCE in
    mpol_rebind_policy().

  - mm, mempolicy: fix mbind() to do synchronous migration.

  - revert 'mm: mempolicy: Let vma_merge and vma_split
    handle vma->vm_policy linkages'.

  - mempolicy: fix a race in shared_policy_replace().

  - mempolicy: fix refcount leak in
    mpol_set_shared_policy().

  - mempolicy: fix a memory corruption by refcount imbalance
    in alloc_pages_vma().

  - mempolicy: remove mempolicy sharing. Memory policy
    enhancements for robustness against fuzz attacks and
    force mbind to use synchronous migration.

  - Update scsi_dh_alua to mainline version (bnc#708296,
    bnc#784334) :

  - scsi_dh_alua: Enable STPG for unavailable ports

  - scsi_dh_alua: Re-enable STPG for unavailable ports

  - scsi_dh_alua: backoff alua rtpg retry linearly vs.
    geometrically

  - scsi_dh_alua: implement implied transition timeout

  - scsi_dh_alua: retry alua rtpg extended header for
    illegal request response

  - Revert removal of ACPI procfs entries. (bnc#777283)

  - x86: Clear HPET configuration registers on startup.
    (bnc#748896)

  - mlx4: Fixed build warning, update references
    (bnc#774500,LTC#83966).

  - xen/frontends: handle backend CLOSED without CLOSING.

  - xen/pciback: properly clean up after calling
    pcistub_device_find().

  - xen/netfront: add netconsole support (bnc#763858
    fate#313830).

  - netfilter: nf_conntrack_ipv6: fix tracking of ICMPv6
    error messages containing fragments. (bnc#779750)

  - ipv6, xfrm: use conntrack-reassembled packet for policy
    lookup. (bnc#780216)

  - inetpeer: add namespace support for inetpeer.
    (bnc#779969)

  - inetpeer: add parameter net for inet_getpeer_v4,v6.
    (bnc#779969)

  - inetpeer: make unused_peers list per-netns. (bnc#779969)

  - kABI: use net_generic to protect struct netns_ipv{4,6}.
    (bnc#779969)

  - patches.rpmify/kbuild-fix-gcc-x-syntax.patch: kbuild:
    Fix gcc -x syntax. (bnc#773831)

  - patches.suse/supported-flag: Re-enabled warning on
    unsupported module loading.

  - nbd: clear waiting_queue on shutdown. (bnc#778630)

  - nohz: fix idle ticks in cpu summary line of /proc/stat
    (follow up fix for bnc#767469, bnc#705551).

  - fix TAINT_NO_SUPPORT handling on module load.

  - NFS: Fix Oopses in nfs_lookup_revalidate and
    nfs4_lookup_revalidate. (bnc#780008)

  - svcrpc: fix svc_xprt_enqueue/svc_recv busy-looping
    (bnc@779462).

  - net: do not disable sg for packets requiring no
    checksum. (bnc#774859)

  - sfc: prevent extreme TSO parameters from stalling TX
    queues. (bnc#774523 / CVE-2012-3412)

  - X86 MCE: Fix correct ring/severity identification in V86
    case. (bnc#773267)

  - scsi_dh_rdac: Add a new netapp vendor/product string.
    (bnc#772483)

  - scsi_dh_rdac : Consolidate rdac strings together.
    (bnc#772483)

  - scsi_dh_rdac : minor return fix for rdac. (bnc#772483)

  - dh_rdac: Associate HBA and storage in rdac_controller to
    support partitions in storage. (bnc#772454)

  - scsi_dh_rdac: Fix error path. (bnc#772454)

  - scsi_dh_rdac: Fix for unbalanced reference count.
    (bnc#772454)

  - sd: Ensure we correctly disable devices with unknown
    protection type. (bnc#780876)

  - netfilter: ipset: timeout can be modified for already
    added elements. (bnc#790457)

  - netfilter: ipset: fix adding ranges to hash types.
    (bnc#790498)

  - workqueue: exit rescuer_thread() as TASK_RUNNING.
    (bnc#789993)

  - xhci: Add Lynx Point LP to list of Intel switchable
    hosts. (bnc#791853)

  - tg3: Introduce separate functions to allocate/free RX/TX
    rings. (bnc#785554)

  - net-next: Add netif_get_num_default_rss_queues.
    (bnc#785554)

  - tg3: set maximal number of default RSS queues.
    (bnc#785554)

  - tg3: Allow number of rx and tx rings to be set
    independently. (bnc#785554)

  - tg3: Separate coalescing setup for rx and tx.
    (bnc#785554)

  - tg3: Refactor tg3_open(). (bnc#785554)

  - tg3: Refactor tg3_close(). (bnc#785554)

  - tg3: Add support for ethtool -L|-l to get/set the number
    of rings. (bnc#785554)

  - tg3: Disable multiple TX rings by default due to
    hardware flaw. (bnc#785554)

  - x86, microcode, AMD: Add support for family 16h
    processors (bnc#791498,fate#314145).

  - scsi_remove_target: fix softlockup regression on hot
    remove. (bnc#789836)

  - autofs4: allow autofs to work outside the initial PID
    namespace. (bnc#779294)

  - autofs4: translate pids to the right namespace for the
    daemon. (bnc#779294)

  - vfs: dont chain pipe/anon/socket on superblock s_inodes
    list. (bnc#789703)

  - reiserfs: fix problems with chowning setuid file w/
    xattrs. (bnc#790920)

  - reiserfs: fix double-lock while chowning setuid file w/
    xattrs. (bnc#790920)

  - ALSA: hda - Fix SSYNC register value for non-Intel
    controllers (fate#313409,bnc#760833).

  - ALSA: hda: option to enable arbitrary buffer/period
    sizes (fate#313409,bnc#760833).

  - ALSA: hda - Fix buffer-alignment regression with Nvidia
    HDMI (fate#313409,bnc#760833).

  - ALSA: hda - explicitly set buffer-align flag for Nvidia
    controllers (fate#313409,bnc#760833).

  - ALSA: hda - Add Lynx Point HD Audio Controller DeviceIDs
    (fate#313409,bnc#760833).

  - ALSA: hda_intel: Add Device IDs for Intel Lynx Point-LP
    PCH (fate#313409,bnc#760833).

  - USB: OHCI: workaround for hardware bug: retired TDs not
    added to the Done Queue. (bnc#762158)

  - watchdog: iTCO_wdt: clean-up PCI device IDs
    (fate#313409, bnc#760833).

  - watchdog: iTCO_wdt: add Intel Lynx Point DeviceIDs
    (fate#313409, bnc#760833).

  - ahci: AHCI-mode SATA patch for Intel Lynx Point
    DeviceIDs (fate#313409, bnc#760833).

  - ata_piix: IDE-mode SATA patch for Intel Lynx Point
    DeviceIDs (fate#313409, bnc#760833).

  - i2c-i801: Add device IDs for Intel Lynx Point
    (fate#313409, bnc#760833).

  - jbd: Fix lock ordering bug in journal_unmap_buffer().
    (bnc#790935)

  - usb: host: xhci: Fix Compliance Mode on SN65LVPE502CP
    Hardware. (bnc#788277)

  - usb: host: xhci: Fix NULL pointer dereferencing with
    71c731a for non-x86 systems. (bnc#788277)

  - Do not remove fillup from the buildsystem. (bnc#781327)

  - ibmvfc: Fix double completion on abort timeout.
    (bnc#788452)

  - ibmvfc: Ignore fabric RSCNs when link is dead.
    (bnc#788452)

  - fs: only send IPI to invalidate LRU BH when needed.
    (bnc#763628 / bnc#744692)

  - smp: add func to IPI cpus based on parameter func.
    (bnc#763628 / bnc#744692)

  - smp: introduce a generic on_each_cpu_mask() function.
    (bnc#763628 / bnc#744692)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=705551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=708296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=722560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=723776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=725152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=725355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=730660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=739728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=741814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=778334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=778630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=781018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=781327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=781484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=781574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=782369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=783965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=784192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=784334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=784576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=785100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=785496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=785554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=785851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=788277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=788452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=790457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=790498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=790920"
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
    value:"http://support.novell.com/security/cve/CVE-2012-1601.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2372.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5517.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 7123 / 7127 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-extra-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-extra-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-source-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-extra-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-extra-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-extra-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-source-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-syms-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-extra-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-extra-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-default-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-source-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-default-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-default-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-default-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-source-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-syms-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-trace-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-trace-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-trace-devel-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.51-0.7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.51-0.7.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
