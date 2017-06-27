#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1690-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93165);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2014-9717", "CVE-2015-8816", "CVE-2015-8845", "CVE-2016-0758", "CVE-2016-2053", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-2782", "CVE-2016-2847", "CVE-2016-3134", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3139", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3672", "CVE-2016-3689", "CVE-2016-3951", "CVE-2016-4482", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4805", "CVE-2016-5244");
  script_bugtraq_id(74226);
  script_osvdb_id(121142, 133550, 134938, 135143, 135194, 135678, 135871, 135872, 135873, 135874, 135875, 135876, 135877, 135878, 135879, 135943, 135975, 136533, 136761, 136805, 137180, 137963, 138093, 138176, 138383, 138431, 138451, 139498);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2016:1690-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 kernel was updated to 3.12.60 to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2014-9717: fs/namespace.c in the Linux kernel
    processes MNT_DETACH umount2 system called without
    verifying that the MNT_LOCKED flag is unset, which
    allowed local users to bypass intended access
    restrictions and navigate to filesystem locations
    beneath a mount by calling umount2 within a user
    namespace (bnc#928547).

  - CVE-2015-8816: The hub_activate function in
    drivers/usb/core/hub.c in the Linux kernel did not
    properly maintain a hub-interface data structure, which
    allowed physically proximate attackers to cause a denial
    of service (invalid memory access and system crash) or
    possibly have unspecified other impact by unplugging a
    USB hub device (bnc#968010).

  - CVE-2015-8845: The tm_reclaim_thread function in
    arch/powerpc/kernel/process.c in the Linux kernel on
    powerpc platforms did not ensure that TM suspend mode
    exists before proceeding with a tm_reclaim call, which
    allowed local users to cause a denial of service (TM Bad
    Thing exception and panic) via a crafted application
    (bnc#975533).

  - CVE-2016-0758: Fix ASN.1 indefinite length object
    parsing (bsc#979867).

  - CVE-2016-2053: The asn1_ber_decoder function in
    lib/asn1_decoder.c in the Linux kernel allowed attackers
    to cause a denial of service (panic) via an ASN.1 BER
    file that lacks a public key, leading to mishandling by
    the public_key_verify_signature function in
    crypto/asymmetric_keys/public_key.c (bnc#963762).

  - CVE-2016-2143: The fork implementation in the Linux
    kernel on s390 platforms mishandled the case of four
    page-table levels, which allowed local users to cause a
    denial of service (system crash) or possibly have
    unspecified other impact via a crafted application,
    related to arch/s390/include/asm/mmu_context.h and
    arch/s390/include/asm/pgalloc.h. (bnc#970504)

  - CVE-2016-2184: The create_fixed_stream_quirk function in
    sound/usb/quirks.c in the snd-usb-audio driver in the
    Linux kernel allowed physically proximate attackers to
    cause a denial of service (NULL pointer dereference or
    double free, and system crash) via a crafted endpoints
    value in a USB device descriptor (bnc#971125).

  - CVE-2016-2185: The ati_remote2_probe function in
    drivers/input/misc/ati_remote2.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#971124).

  - CVE-2016-2186: The powermate_probe function in
    drivers/input/misc/powermate.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970958).

  - CVE-2016-2188: The iowarrior_probe function in
    drivers/usb/misc/iowarrior.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a crafted endpoints value in a USB device descriptor
    (bnc#970956).

  - CVE-2016-2782: The treo_attach function in
    drivers/usb/serial/visor.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) or
    possibly have unspecified other impact by inserting a
    USB device that lacks a (1) bulk-in or (2) interrupt-in
    endpoint (bnc#968670).

  - CVE-2016-2847: fs/pipe.c in the Linux kernel did not
    limit the amount of unread data in pipes, which allowed
    local users to cause a denial of service (memory
    consumption) by creating many pipes with non-default
    sizes (bnc#970948).

  - CVE-2016-3134: The netfilter subsystem in the Linux
    kernel did not validate certain offset fields, which
    allowed local users to gain privileges or cause a denial
    of service (heap memory corruption) via an
    IPT_SO_SET_REPLACE setsockopt call (bnc#971126).

  - CVE-2016-3136: The mct_u232_msr_to_state function in
    drivers/usb/serial/mct_u232.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted USB device without two interrupt-in
    endpoint descriptors (bnc#970955).

  - CVE-2016-3137: drivers/usb/serial/cypress_m8.c in the
    Linux kernel allowed physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a USB device without both an
    interrupt-in and an interrupt-out endpoint descriptor,
    related to the cypress_generic_port_probe and
    cypress_open functions (bnc#970970).

  - CVE-2016-3138: The acm_probe function in
    drivers/usb/class/cdc-acm.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a USB device without both a control and a data endpoint
    descriptor (bnc#970911).

  - CVE-2016-3139: The wacom_probe function in
    drivers/input/tablet/wacom_sys.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970909).

  - CVE-2016-3140: The digi_port_init function in
    drivers/usb/serial/digi_acceleport.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970892).

  - CVE-2016-3156: The IPv4 implementation in the Linux
    kernel mishandled destruction of device objects, which
    allowed guest OS users to cause a denial of service
    (host OS networking outage) by arranging for a large
    number of IP addresses (bnc#971360).

  - CVE-2016-3672: The arch_pick_mmap_layout function in
    arch/x86/mm/mmap.c in the Linux kernel did not properly
    randomize the legacy base address, which made it easier
    for local users to defeat the intended restrictions on
    the ADDR_NO_RANDOMIZE flag, and bypass the ASLR
    protection mechanism for a setuid or setgid program, by
    disabling stack-consumption resource limits
    (bnc#974308).

  - CVE-2016-3689: The ims_pcu_parse_cdc_data function in
    drivers/input/misc/ims-pcu.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (system crash) via a USB device without both a
    master and a slave interface (bnc#971628).

  - CVE-2016-3951: Double free vulnerability in
    drivers/net/usb/cdc_ncm.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (system crash) or possibly have unspecified
    other impact by inserting a USB device with an invalid
    USB descriptor (bnc#974418).

  - CVE-2016-4482: The proc_connectinfo function in
    drivers/usb/core/devio.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via a crafted USBDEVFS_CONNECTINFO ioctl call
    (bnc#978401).

  - CVE-2016-4486: The rtnl_fill_link_ifmap function in
    net/core/rtnetlink.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory by reading a Netlink message (bnc#978822).

  - CVE-2016-4565: The InfiniBand (aka IB) stack in the
    Linux kernel incorrectly relied on the write system
    call, which allowed local users to cause a denial of
    service (kernel memory write operation) or possibly have
    unspecified other impact via a uAPI interface
    (bnc#979548).

  - CVE-2016-4569: The snd_timer_user_params function in
    sound/core/timer.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via crafted use of the ALSA timer interface
    (bnc#979213).

  - CVE-2016-4578: sound/core/timer.c in the Linux kernel
    did not initialize certain r1 data structures, which
    allowed local users to obtain sensitive information from
    kernel stack memory via crafted use of the ALSA timer
    interface, related to the (1) snd_timer_user_ccallback
    and (2) snd_timer_user_tinterrupt functions
    (bnc#979879).

  - CVE-2016-4805: Use-after-free vulnerability in
    drivers/net/ppp/ppp_generic.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption and system crash, or spinlock) or possibly
    have unspecified other impact by removing a network
    namespace, related to the ppp_register_net_channel and
    ppp_unregister_channel functions (bnc#980371).

  - CVE-2016-5244: Fixed an infoleak in rds_inc_info_copy
    (bsc#983213).

The following non-security bugs were fixed :

  - ALSA: hrtimer: Handle start/stop more properly
    (bsc#973378).

  - ALSA: timer: Call notifier in the same spinlock
    (bsc#973378).

  - ALSA: timer: Protect the whole snd_timer_close() with
    open race (bsc#973378).

  - ALSA: timer: Sync timer deletion at closing the system
    timer (bsc#973378).

  - ALSA: timer: Use mod_timer() for rearming the system
    timer (bsc#973378).

  -
    Btrfs-8394-qgroup-Account-data-space-in-more-proper-timi
    n.patch: (bsc#963193).

  - Btrfs: do not collect ordered extents when logging that
    inode exists (bsc#977685).

  - Btrfs: do not use src fd for printk (bsc#980348).

  - Btrfs: fix deadlock between direct IO reads and buffered
    writes (bsc#973855).

  - Btrfs: fix empty symlink after creating symlink and
    fsync parent dir (bsc#977685).

  - Btrfs: fix file loss on log replay after renaming a file
    and fsync (bsc#977685).

  - Btrfs: fix file/data loss caused by fsync after rename
    and new inode (bsc#977685).

  - Btrfs: fix for incorrect directory entries after fsync
    log replay (bsc#957805, bsc#977685).

  - Btrfs: fix loading of orphan roots leading to BUG_ON
    (bsc#972844).

  - Btrfs: fix race between fsync and lockless direct IO
    writes (bsc#977685).

  - Btrfs: fix unreplayable log after snapshot delete +
    parent dir fsync (bsc#977685).

  - Btrfs: handle non-fatal errors in btrfs_qgroup_inherit()
    (bsc#972951).

  - Btrfs: qgroup: Fix dead judgement on
    qgroup_rescan_leaf() return value (bsc#969439).

  - Btrfs: qgroup: Fix qgroup accounting when creating
    snapshot (bsc#972933).

  - Btrfs: qgroup: return EINVAL if level of parent is not
    higher than child's (bsc#972951).

  - Btrfs: teach backref walking about backrefs with
    underflowed offset values (bsc#975371).

  - CacheFiles: Fix incorrect test for in-memory object
    collision (bsc#971049).

  - CacheFiles: Handle object being killed before being set
    up (bsc#971049).

  - Ceph: Remove racey watch/notify event infrastructure
    (bsc#964727)

  - Driver: Vmxnet3: set CHECKSUM_UNNECESSARY for IPv6
    packets (bsc#976739).

  - FS-Cache: Add missing initialization of ret in
    cachefiles_write_page() (bsc#971049).

  - FS-Cache: Count culled objects and objects rejected due
    to lack of space (bsc#971049).

  - FS-Cache: Fix cancellation of in-progress operation
    (bsc#971049).

  - FS-Cache: Handle a new operation submitted against a
    killed object (bsc#971049).

  - FS-Cache: Move fscache_report_unexpected_submission() to
    make it more available (bsc#971049).

  - FS-Cache: Out of line fscache_operation_init()
    (bsc#971049).

  - FS-Cache: Permit fscache_cancel_op() to cancel
    in-progress operations too (bsc#971049).

  - FS-Cache: Put an aborted initialised op so that it is
    accounted correctly (bsc#971049).

  - FS-Cache: Reduce cookie ref count if submit fails
    (bsc#971049).

  - FS-Cache: Synchronise object death state change vs
    operation submission (bsc#971049).

  - FS-Cache: The operation cancellation method needs
    calling in more places (bsc#971049).

  - FS-Cache: Timeout for releasepage() (bsc#971049).

  - FS-Cache: When submitting an op, cancel it if the target
    object is dying (bsc#971049).

  - FS-Cache: fscache_object_is_dead() has wrong logic, kill
    it (bsc#971049).

  - Fix cifs_uniqueid_to_ino_t() function for s390x
    (bsc#944309)

  - Fix kabi issue (bsc#971049).

  - Fix kmalloc overflow in LPFC driver at large core count
    (bsc#969690).

  - Fix problem with setting ACL on directories
    (bsc#967251).

  - Input: i8042 - lower log level for 'no controller'
    message (bsc#945345).

  - KVM: SVM: add rdmsr support for AMD event registers
    (bsc#968448).

  - MM: increase safety margin provided by PF_LESS_THROTTLE
    (bsc#956491).

  - NFSv4.1: do not use machine credentials for CLOSE when
    using 'sec=sys' (bsc#972003).

  - PCI/AER: Fix aer_inject error codes (bsc#931448).

  - PCI/AER: Log actual error causes in aer_inject
    (bsc#931448).

  - PCI/AER: Log aer_inject error injections (bsc#931448).

  - PCI/AER: Use dev_warn() in aer_inject (bsc#931448).

  - Revert 'libata: Align ata_device's id on a cacheline'.

  - Revert 'net/ipv6: add sysctl option
    accept_ra_min_hop_limit'.

  - USB: quirk to stop runtime PM for Intel 7260
    (bnc#984456).

  - USB: usbip: fix potential out-of-bounds write
    (bnc#975945).

  - USB: xhci: Add broken streams quirk for Frescologic
    device id 1009 (bnc#982698).

  - Update
    patches.drivers/0001-nvme-fix-max_segments-integer-trunc
    ation.patch (bsc#979419). Fix reference.

  - Update
    patches.drivers/drm-ast-Initialize-data-needed-to-map-fb
    dev-memory.patch (bnc#880007). Fix refs and upstream
    status.

  - Update patches.kernel.org/patch-3.12.55-56 references
    (add bsc#973570).

  - Update patches.suse/kgr-0102-add-TAINT_KGRAFT.patch
    (bsc#974406).

  - acpi: Disable ACPI table override when UEFI Secure Boot
    is enabled (bsc#970604).

  - acpi: Disable APEI error injection if securelevel is set
    (bsc#972891).

  - cachefiles: perform test on s_blocksize when opening
    cache file (bsc#971049).

  - cpuset: Fix potential deadlock w/ set_mems_allowed
    (bsc#960857, bsc#974646).

  - dmapi: fix dm_open_by_handle_rvp taking an extra ref to
    mnt (bsc#967292).

  - drm/core: Preserve the framebuffer after removing it
    (bsc#968812).

  - drm/mgag200: Add support for a new G200eW3 chipset
    (bsc#983904).

  - drm/mgag200: Add support for a new rev of G200e
    (bsc#983904).

  - drm/mgag200: Black screen fix for G200e rev 4
    (bsc#983904).

  - drm/mgag200: remove unused variables (bsc#983904).

  - drm/radeon: fix-up some float to fixed conversion
    thinkos (bsc#968813).

  - drm/radeon: use HDP_MEM_COHERENCY_FLUSH_CNTL for sdma as
    well (bsc#968813).

  - drm: qxl: Workaround for buggy user-space (bsc#981344).

  - efifb: Fix 16 color palette entry calculation
    (bsc#983318).

  - ehci-pci: enable interrupt on BayTrail (bnc#947337).

  - enic: set netdev->vlan_features (bsc#966245).

  - ext4: fix races between page faults and hole punching
    (bsc#972174).

  - ext4: fix races of writeback with punch hole and zero
    range (bsc#972174).

  - fix: print ext4 mountopt data_err=abort correctly
    (bsc#969735).

  - fs, seq_file: fallback to vmalloc instead of oom kill
    processes (bnc#968687).

  - fs, seqfile: always allow oom killer (bnc#968687).

  - fs/pipe.c: skip file_update_time on frozen fs
    (bsc#975488).

  - hid-elo: kill not flush the work (bnc#982354).

  - ibmvscsi: Remove unsupported host config MAD
    (bsc#973556).

  - ipv6: make fib6 serial number per namespace
    (bsc#965319).

  - ipv6: mld: fix add_grhead skb_over_panic for devs with
    large MTUs (bsc#956852).

  - ipv6: per netns FIB garbage collection (bsc#965319).

  - ipv6: per netns fib6 walkers (bsc#965319).

  - ipv6: replace global gc_args with local variable
    (bsc#965319).

  - ipvs: count pre-established TCP states as active
    (bsc#970114).

  - kABI: kgr: fix subtle race with kgr_module_init(), going
    notifier and kgr_modify_kernel().

  - kABI: protect enum enclosure_component_type.

  - kABI: protect function file_open_root.

  - kABI: protect include in evm.

  - kABI: protect struct dm_exception_store_type.

  - kABI: protect struct fib_nh_exception.

  - kABI: protect struct module.

  - kABI: protect struct rq.

  - kABI: protect struct sched_class.

  - kABI: protect struct scm_creds.

  - kABI: protect struct user_struct.

  - kABI: protect struct user_struct.

  - kabi fix for patches.fixes/reduce-m_start-cost
    (bsc#966573).

  - kabi/severities: Whitelist libceph and rbd (bsc#964727).

  - kabi: kgr, add reserved fields

  - kabi: protect struct fc_rport_priv (bsc#953233,
    bsc#962846).

  - kabi: protect struct netns_ipv6 after FIB6 GC series
    (bsc#965319).

  - kgr: add TAINT_KGRAFT

  - kgr: add kgraft annotation to hwrng kthread.

  - kgr: add kgraft annotations to kthreads'
    wait_event_freezable() API calls.

  - kgr: add objname to kgr_patch_fun struct.

  - kgr: add sympos and objname to error and debug messages.

  - kgr: add sympos as disambiguator field to kgr_patch_fun
    structure.

  - kgr: add sympos to sysfs.

  - kgr: call kgr_init_ftrace_ops() only for loaded objects.

  - kgr: change to kallsyms_on_each_symbol iterator.

  - kgr: define pr_fmt and modify all pr_* messages.

  - kgr: do not print error for !abort_if_missing symbols
    (bnc#943989).

  - kgr: do not return and print an error only if the object
    is not loaded.

  - kgr: do not use WQ_MEM_RECLAIM workqueue (bnc#963572).

  - kgr: fix an asymmetric dealing with delayed module
    loading.

  - kgr: fix redirection on s390x arch (bsc#903279).

  - kgr: fix subtle race with kgr_module_init(), going
    notifier and kgr_modify_kernel().

  - kgr: handle btrfs kthreads (bnc#889207).

  - kgr: kmemleak, really mark the kthread safe after an
    interrupt.

  - kgr: log when modifying kernel.

  - kgr: mark some more missed kthreads (bnc#962336).

  - kgr: remove abort_if_missing flag.

  - kgr: usb/storage: do not emit thread awakened
    (bnc#899908).

  - kgraft/gfs2: Do not block livepatching in the log daemon
    for too long.

  - kgraft/xen: Do not block livepatching in the XEN blkif
    kthread.

  - libfc: replace 'rp_mutex' with 'rp_lock' (bsc#953233,
    bsc#962846).

  - memcg: do not hang on OOM when killed by userspace OOM
    access to memory reserves (bnc#969571).

  - mld, igmp: Fix reserved tailroom calculation
    (bsc#956852).

  - mmc: Allow forward compatibility for eMMC (bnc#966054).

  - mmc: sdhci: Allow for irq being shared (bnc#977582).

  - net/qlge: Avoids recursive EEH error (bsc#954847).

  - net: Account for all vlan headers in skb_mac_gso_segment
    (bsc#968667).

  - net: Start with correct mac_len in skb_network_protocol
    (bsc#968667).

  - net: disable fragment reassembly if high_thresh is set
    to zero (bsc#970506).

  - net: fix wrong mac_len calculation for vlans
    (bsc#968667).

  - net: irda: Fix use-after-free in irtty_open()
    (bnc#967903).

  - nfs4: treat lock owners as opaque values (bnc#968141).

  - nfs: fix high load average due to callback thread
    sleeping (bsc#971170).

  - nfsd: fix nfsd_setattr return code for HSM (bsc#969992).

  - nvme: fix max_segments integer truncation (bsc#676471).

  - ocfs2: do not set fs read-only if rec[0] is empty while
    committing truncate (bnc#971947).

  - ocfs2: extend enough credits for freeing one truncate
    record while replaying truncate records (bnc#971947).

  - ocfs2: extend transaction for
    ocfs2_remove_rightmost_path() and
    ocfs2_update_edge_lengths() before to avoid
    inconsistency between inode and et (bnc#971947).

  - perf, nmi: Fix unknown NMI warning (bsc#968512).

  - pipe: limit the per-user amount of pages allocated in
    pipes (bsc#970948).

  - rbd: do not log miscompare as an error (bsc#970062).

  - rbd: handle OBJ_REQUEST_SG types for copyup
    (bsc#983394).

  - rbd: report unsupported features to syslog (bsc#979169).

  - rbd: use GFP_NOIO consistently for request allocations
    (bsc#971159).

  - reduce m_start() cost.. (bsc#966573).

  - rpm/modprobe-xen.conf: Revert comment change to allow
    parallel install (bsc#957986). This reverts commit
    6c6d86d3cdc26f7746fe4ba2bef8859b5aeb346c.

  - s390/pageattr: do a single TLB flush for
    change_page_attr (bsc#940413).

  - sched/x86: Fix up typo in topology detection
    (bsc#974165).

  - scsi: proper state checking and module refcount handling
    in scsi_device_get (boo#966831).

  - series.conf: move netfilter section at the end of core
    networking

  - supported.conf: Add bridge.ko for OpenStack (bsc#971600)

  - supported.conf: Add isofs to -base (bsc#969655).

  - supported.conf:Add
    drivers/infiniband/hw/ocrdma/ocrdma.ko to supported.conf
    (bsc#964461)

  - target/rbd: do not put snap_context twice (bsc#981143).

  - target/rbd: remove caw_mutex usage (bsc#981143).

  - target: Drop incorrect ABORT_TASK put for completed
    commands (bsc#962872).

  - target: Fix LUN_RESET active I/O handling for ACK_KREF
    (bsc#962872).

  - target: Fix LUN_RESET active TMR descriptor handling
    (bsc#962872).

  - target: Fix TAS handling for multi-session se_node_acls
    (bsc#962872).

  - target: Fix race with SCF_SEND_DELAYED_TAS handling
    (bsc#962872).

  - target: Fix remote-port TMR ABORT + se_cmd fabric stop
    (bsc#962872).

  - vgaarb: Add more context to error messages (bsc#976868).

  - x86, sched: Add new topology for multi-NUMA-node CPUs
    (bsc#974165).

  - x86/efi: parse_efi_setup() build fix (bsc#979485).

  - x86: standardize mmap_rnd() usage (bnc#974308).

  - xen/acpi: Disable ACPI table override when UEFI Secure
    Boot is enabled (bsc#970604).

  - xfs/dmapi: drop lock over synchronous XFS_SEND_DATA
    events (bsc#969993).

  - xfs/dmapi: propertly send postcreate event (bsc#967299).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/676471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/880007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/889207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/899908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/903279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9717.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8816.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8845.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0758.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2053.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2143.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2186.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2782.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2847.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3134.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3136.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3137.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3138.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3139.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3140.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3156.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3672.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3689.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3951.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4482.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4486.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4565.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4578.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5244.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161690-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47313d88"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2016-1001=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-1001=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-1001=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2016-1001=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2016-1001=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-1001=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-devel-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-syms-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.60-52.49.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
