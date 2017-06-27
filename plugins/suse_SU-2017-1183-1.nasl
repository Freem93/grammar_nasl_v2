#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1183-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(100023);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/08 13:38:43 $");

  script_cve_id("CVE-2016-10200", "CVE-2016-2117", "CVE-2016-9191", "CVE-2017-2596", "CVE-2017-2671", "CVE-2017-5986", "CVE-2017-6074", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6347", "CVE-2017-6353", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7294", "CVE-2017-7308", "CVE-2017-7374");
  script_osvdb_id(135961, 146761, 151239, 152094, 152302, 152453, 152685, 152704, 152705, 152728, 152729, 153065, 154043, 154359, 154384, 154548, 154633, 154753);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2017:1183-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.58 to
receive various security and bugfixes. Notable new/improved features :

  - Improved support for Hyper-V

  - Support for Matrox G200eH3

  - Support for tcp_westwood The following security bugs
    were fixed :

  - CVE-2017-2671: The ping_unhash function in
    net/ipv4/ping.c in the Linux kernel was too late in
    obtaining a certain lock and consequently could not
    ensure that disconnect function calls are safe, which
    allowed local users to cause a denial of service (panic)
    by leveraging access to the protocol value of
    IPPROTO_ICMP in a socket system call (bnc#1031003).

  - CVE-2017-7308: The packet_set_ring function in
    net/packet/af_packet.c in the Linux kernel did not
    properly validate certain block-size data, which allowed
    local users to cause a denial of service (overflow) or
    possibly have unspecified other impact via crafted
    system calls (bnc#1031579).

  - CVE-2017-7294: The vmw_surface_define_ioctl function in
    drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux
    kernel did not validate addition of certain levels data,
    which allowed local users to trigger an integer overflow
    and out-of-bounds write, and cause a denial of service
    (system hang or crash) or possibly gain privileges, via
    a crafted ioctl call for a /dev/dri/renderD* device
    (bnc#1031440).

  - CVE-2017-7261: The vmw_surface_define_ioctl function in
    drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux
    kernel did not check for a zero value of certain levels
    data, which allowed local users to cause a denial of
    service (ZERO_SIZE_PTR dereference, and GPF and possibly
    panic) via a crafted ioctl call for a /dev/dri/renderD*
    device (bnc#1031052).

  - CVE-2017-7187: The sg_ioctl function in
    drivers/scsi/sg.c in the Linux kernel allowed local
    users to cause a denial of service (stack-based buffer
    overflow) or possibly have unspecified other impact via
    a large command size in an SG_NEXT_CMD_LEN ioctl call,
    leading to out-of-bounds write access in the sg_write
    function (bnc#1030213).

  - CVE-2017-7374: Use-after-free vulnerability in
    fs/crypto/ in the Linux kernel allowed local users to
    cause a denial of service (NULL pointer dereference) or
    possibly gain privileges by revoking keyring keys being
    used for ext4, f2fs, or ubifs encryption, causing
    cryptographic transform objects to be freed prematurely
    (bnc#1032006).

  - CVE-2016-10200: Race condition in the L2TPv3 IP
    Encapsulation feature in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (use-after-free) by making multiple bind system calls
    without properly ascertaining whether a socket has the
    SOCK_ZAPPED status, related to net/l2tp/l2tp_ip.c and
    net/l2tp/l2tp_ip6.c (bnc#1028415).

  - CVE-2017-6345: The LLC subsystem in the Linux kernel did
    not ensure that a certain destructor exists in required
    circumstances, which allowed local users to cause a
    denial of service (BUG_ON) or possibly have unspecified
    other impact via crafted system calls (bnc#1027190).

  - CVE-2017-6346: Race condition in net/packet/af_packet.c
    in the Linux kernel allowed local users to cause a
    denial of service (use-after-free) or possibly have
    unspecified other impact via a multithreaded application
    that made PACKET_FANOUT setsockopt system calls
    (bnc#1027189).

  - CVE-2017-6353: net/sctp/socket.c in the Linux kernel did
    not properly restrict association peel-off operations
    during certain wait states, which allowed local users to
    cause a denial of service (invalid unlock and double
    free) via a multithreaded application. NOTE: this
    vulnerability exists because of an incorrect fix for
    CVE-2017-5986 (bnc#1027066).

  - CVE-2017-6214: The tcp_splice_read function in
    net/ipv4/tcp.c in the Linux kernel allowed remote
    attackers to cause a denial of service (infinite loop
    and soft lockup) via vectors involving a TCP packet with
    the URG flag (bnc#1026722).

  - CVE-2016-2117: The atl2_probe function in
    drivers/net/ethernet/atheros/atlx/atl2.c in the Linux
    kernel incorrectly enables scatter/gather I/O, which
    allowed remote attackers to obtain sensitive information
    from kernel memory by reading packet data (bnc#968697).

  - CVE-2017-6347: The ip_cmsg_recv_checksum function in
    net/ipv4/ip_sockglue.c in the Linux kernel had incorrect
    expectations about skb data layout, which allowed local
    users to cause a denial of service (buffer over-read) or
    possibly have unspecified other impact via crafted
    system calls, as demonstrated by use of the MSG_MORE
    flag in conjunction with loopback UDP transmission
    (bnc#1027179).

  - CVE-2016-9191: The cgroup offline implementation in the
    Linux kernel mishandled certain drain operations, which
    allowed local users to cause a denial of service (system
    hang) by leveraging access to a container environment
    for executing a crafted application (bnc#1008842).

  - CVE-2017-2596: The nested_vmx_check_vmptr function in
    arch/x86/kvm/vmx.c in the Linux kernel improperly
    emulated the VMXON instruction, which allowed KVM L1
    guest OS users to cause a denial of service (host OS
    memory consumption) by leveraging the mishandling of
    page references (bnc#1022785).

  - CVE-2017-6074: The dccp_rcv_state_process function in
    net/dccp/input.c in the Linux kernel mishandled
    DCCP_PKT_REQUEST packet data structures in the LISTEN
    state, which allowed local users to obtain root
    privileges or cause a denial of service (double free)
    via an application that made an IPV6_RECVPKTINFO
    setsockopt system call (bnc#1026024). The following
    non-security bugs were fixed :

  - ACPI, ioapic: Clear on-stack resource before using it
    (bsc#1028819).

  - ACPI: Do not create a platform_device for IOAPIC/IOxAPIC
    (bsc#1028819).

  - ACPI: Remove platform devices from a bus on removal
    (bsc#1028819).

  - HID: usbhid: Quirk a AMI virtual mouse and keyboard with
    ALWAYS_POLL (bsc#1022340).

  - NFS: do not try to cross a mountpount when there isn't
    one there (bsc#1028041).

  - NFS: flush out dirty data on file fput() (bsc#1021762).

  - PCI: hv: Fix wslot_to_devfn() to fix warnings on device
    removal (bug#1028217).

  - PCI: hv: Use device serial number as PCI domain
    (bug#1028217).

  - RAID1: a new I/O barrier implementation to remove resync
    window (bsc#998106,bsc#1020048,bsc#982783).

  - RAID1: avoid unnecessary spin locks in I/O barrier code
    (bsc#998106,bsc#1020048,bsc#982783).

  - Revert 'RDMA/core: Fix incorrect structure packing for
    booleans' (kabi).

  - Revert 'give up on gcc ilog2() constant optimizations'
    (kabi).

  - Revert 'net/mlx4_en: Avoid unregister_netdev at shutdown
    flow' (bsc#1028017).

  - Revert 'net: introduce device min_header_len' (kabi).

  - Revert 'nfit, libnvdimm: fix interleave set cookie
    calculation' (kabi).

  - Revert 'target: Fix NULL dereference during LUN lookup +
    active I/O shutdown' (kabi).

  - acpi, nfit: fix acpi_nfit_flush_probe() crash
    (bsc#1031717).

  - acpi, nfit: fix extended status translations for ACPI
    DSMs (bsc#1031717).

  - arm64: Use full path in KBUILD_IMAGE definition
    (bsc#1010032).

  - arm64: hugetlb: fix the wrong address for several
    functions (bsc#1032681).

  - arm64: hugetlb: fix the wrong return value for
    huge_ptep_set_access_flags (bsc#1032681).

  - arm64: hugetlb: remove the wrong pmd check in
    find_num_contig() (bsc#1032681).

  - arm: Use full path in KBUILD_IMAGE definition
    (bsc#1010032).

  - bnx2x: allow adding VLANs while interface is down
    (bsc#1027273).

  - bonding: fix 802.3ad aggregator reselection
    (bsc#1029514).

  - btrfs: Change qgroup_meta_rsv to 64bit (bsc#1019614).

  - btrfs: allow unlink to exceed subvolume quota
    (bsc#1019614).

  - btrfs: backref: Fix soft lockup in __merge_refs function
    (bsc#1017641).

  - btrfs: incremental send, do not delay rename when parent
    inode is new (bsc#1028325).

  - btrfs: incremental send, do not issue invalid rmdir
    operations (bsc#1028325).

  - btrfs: qgroup: Move half of the qgroup accounting time
    out of commit trans (bsc#1017461).

  - btrfs: qgroups: Retry after commit on getting EDQUOT
    (bsc#1019614).

  - btrfs: send, fix failure to rename top level inode due
    to name collision (bsc#1028325).

  - btrfs: serialize subvolume mounts with potentially
    mismatching rw flags (bsc#951844 bsc#1024015)

  - cgroup/pids: remove spurious suspicious RCU usage
    warning (bnc#1031831).

  - crypto: algif_hash - avoid zero-sized array
    (bnc#1007962).

  - cxgb4vf: do not offload Rx checksums for IPv6 fragments
    (bsc#1026692).

  - device-dax: fix private mapping restriction, permit
    read-only (bsc#1031717).

  - drm/i915: Add intel_uncore_suspend / resume functions
    (bsc#1011913).

  - drm/i915: Fix crash after S3 resume with DP MST mode
    change (bsc#1029634).

  - drm/i915: Listen for PMIC bus access notifications
    (bsc#1011913).

  - drm/i915: Only enable hotplug interrupts if the display
    interrupts are enabled (bsc#1031717).

  - drm/mgag200: Added support for the new device G200eH3
    (bsc#1007959)

  - ext4: fix fencepost in s_first_meta_bg validation
    (bsc#1029986).

  - futex: Add missing error handling to FUTEX_REQUEUE_PI
    (bsc#969755).

  - futex: Fix potential use-after-free in FUTEX_REQUEUE_PI
    (bsc#969755).

  - hv: export current Hyper-V clocksource (bsc#1031206).

  - hv: util: do not forget to init host_ts.lock
    (bsc#1031206).

  - hv: vmbus: Prevent sending data on a rescinded channel
    (bug#1028217).

  - hv_utils: implement Hyper-V PTP source (bsc#1031206).

  - i2c-designware: increase timeout (bsc#1011913).

  - i2c: designware-baytrail: Acquire P-Unit access on bus
    acquire (bsc#1011913).

  - i2c: designware-baytrail: Call
    pmic_bus_access_notifier_chain (bsc#1011913).

  - i2c: designware-baytrail: Fix race when resetting the
    semaphore (bsc#1011913).

  - i2c: designware-baytrail: Only check
    iosf_mbi_available() for shared hosts (bsc#1011913).

  - i2c: designware: Disable pm for PMIC i2c-bus even if
    there is no _SEM method (bsc#1011913).

  - i2c: designware: Never suspend i2c-busses used for
    accessing the system PMIC (bsc#1011913).

  - i2c: designware: Rename accessor_flags to flags
    (bsc#1011913).

  - iommu/vt-d: Make sure IOMMUs are off when
    intel_iommu=off (bsc#1031208).

  - kABI: protect struct iscsi_conn (kabi).

  - kABI: protect struct se_node_acl (kabi).

  - kABI: restore can_rx_register parameters (kabi).

  - kgr/module: make a taint flag module-specific

  - kgr: Mark eeh_event_handler() kthread safe using a
    timeout (bsc#1031662).

  - kgr: remove all arch-specific kgraft header files

  - l2tp: fix address test in __l2tp_ip6_bind_lookup()
    (bsc#1028415).

  - l2tp: fix lookup for sockets not bound to a device in
    l2tp_ip (bsc#1028415).

  - l2tp: fix racy socket lookup in l2tp_ip and l2tp_ip6
    bind() (bsc#1028415).

  - l2tp: hold socket before dropping lock in l2tp_ip{,
    6}_recv() (bsc#1028415).

  - l2tp: hold tunnel socket when handling control frames in
    l2tp_ip and l2tp_ip6 (bsc#1028415).

  - l2tp: lock socket before checking flags in connect()
    (bsc#1028415).

  - libnvdimm, pfn: fix memmap reservation size versus 4K
    alignment (bsc#1031717).

  - locking/semaphore: Add down_interruptible_timeout()
    (bsc#1031662).

  - md/raid1: Refactor raid1_make_request
    (bsc#998106,bsc#1020048,bsc#982783).

  - md/raid1: add rcu protection to rdev in fix_read_error
    (References: bsc#998106,bsc#1020048,bsc#982783).

  - md/raid1: fix a use-after-free bug
    (bsc#998106,bsc#1020048,bsc#982783).

  - md/raid1: handle flush request correctly
    (bsc#998106,bsc#1020048,bsc#982783).

  - mm/huge_memory.c: respect FOLL_FORCE/FOLL_COW for thp
    (bnc#1030118).

  - mm/memblock.c: fix memblock_next_valid_pfn()
    (bnc#1031200).

  - mm/page_alloc: Remove useless parameter of
    __free_pages_boot_core (bnc#1027195).

  - mm: fix set pageblock migratetype in deferred struct
    page init (bnc#1027195).

  - mm: page_alloc: skip over regions of invalid pfns where
    possible (bnc#1031200).

  - module: move add_taint_module() to a header file

  - net/ena: change condition for host attribute
    configuration (bsc#1026509).

  - net/ena: change driver's default timeouts (bsc#1026509).

  - net/ena: fix NULL dereference when removing the driver
    after device reset failed (bsc#1026509).

  - net/ena: fix RSS default hash configuration
    (bsc#1026509).

  - net/ena: fix ethtool RSS flow configuration
    (bsc#1026509).

  - net/ena: fix potential access to freed memory during
    device reset (bsc#1026509).

  - net/ena: fix queues number calculation (bsc#1026509).

  - net/ena: reduce the severity of ena printouts
    (bsc#1026509).

  - net/ena: refactor ena_get_stats64 to be atomic context
    safe (bsc#1026509).

  - net/ena: remove ntuple filter support from device
    feature list (bsc#1026509).

  - net/ena: update driver version to 1.1.2 (bsc#1026509).

  - net/ena: use READ_ONCE to access completion descriptors
    (bsc#1026509).

  - net/mlx4_core: Avoid command timeouts during VF driver
    device shutdown (bsc#1028017).

  - net/mlx4_core: Avoid delays during VF driver device
    shutdown (bsc#1028017).

  - net/mlx4_core: Fix racy CQ (Completion Queue) free
    (bsc#1028017).

  - net/mlx4_core: Fix when to save some qp context flags
    for dynamic VST to VGT transitions (bsc#1028017).

  - net/mlx4_core: Use cq quota in SRIOV when creating
    completion EQs (bsc#1028017).

  - net/mlx4_en: Fix bad WQE issue (bsc#1028017).

  - net: ena: Fix error return code in ena_device_init()
    (bsc#1026509).

  - net: ena: Remove unnecessary pci_set_drvdata()
    (bsc#1026509).

  - net: ena: change the return type of ena_set_push_mode()
    to be void (bsc#1026509).

  - net: ena: remove superfluous check in ena_remove()
    (bsc#1026509).

  - net: ena: use setup_timer() and mod_timer()
    (bsc#1026509).

  - netfilter: allow logging from non-init namespaces
    (bsc#970083).

  - nvme: Do not suspend admin queue that wasn't created
    (bsc#1026505).

  - nvme: Suspend all queues before deletion (bsc#1026505).

  - ping: implement proper locking (bsc#1031003).

  - powerpc: Blacklist GCC 5.4 6.1 and 6.2 (boo#1028895).

  - rtlwifi: rtl_usb: Fix missing entry in USB driver's
    private data (bsc#1026462).

  - s390/kmsg: add missing kmsg descriptions (bnc#1025683).

  - s390/mm: fix zone calculation in arch_add_memory()
    (bnc#1025683).

  - sched/loadavg: Avoid loadavg spikes caused by delayed
    NO_HZ accounting (bsc#1018419).

  - scsi: do not print 'reservation conflict' for TEST UNIT
    READY (bsc#1027054).

  - scsi_dh_alua: Do not modify the interval value for
    retries (bsc#1012910).

  - softirq: Let ksoftirqd do its job (bsc#1019618).

  - x86, mm: fix gup_pte_range() vs DAX mappings
    (bsc#1026405).

  - x86/apic/uv: Silence a shift wrapping warning
    (bsc#1023866).

  - x86/ioapic: Change prototype of acpi_ioapic_add()
    (bsc#1027153, bsc#1027616).

  - x86/ioapic: Fix IOAPIC failing to request resource
    (bsc#1027153, bsc#1027616).

  - x86/ioapic: Fix incorrect pointers in
    ioapic_setup_resources() (bsc#1027153, bsc#1027616).

  - x86/ioapic: Fix lost IOAPIC resource after hot-removal
    and hotadd (bsc#1027153, bsc#1027616).

  - x86/ioapic: Fix setup_res() failing to get resource
    (bsc#1027153, bsc#1027616).

  - x86/ioapic: Ignore root bridges without a companion ACPI
    device (bsc#1027153, bsc#1027616).

  - x86/ioapic: Simplify ioapic_setup_resources()
    (bsc#1027153, bsc#1027616).

  - x86/ioapic: Support hot-removal of IOAPICs present
    during boot (bsc#1027153, bsc#1027616).

  - x86/ioapic: fix kABI (hide added include) (bsc#1027153,
    bsc#1027616).

  - x86/mce: Do not print MCEs when mcelog is active
    (bsc#1013994).

  - x86/mce: Fix copy/paste error in exception table entries

  - x86/mm/gup: Simplify get_user_pages() PTE bit handling
    (bsc#1026405).

  - x86/platform/UV: Add Support for UV4 Hubless NMIs
    (bsc#1023866).

  - x86/platform/UV: Add Support for UV4 Hubless systems
    (bsc#1023866).

  - x86/platform/UV: Add basic CPU NMI health check
    (bsc#1023866).

  - x86/platform/UV: Clean up the NMI code to match current
    coding style (bsc#1023866).

  - x86/platform/UV: Clean up the UV APIC code
    (bsc#1023866).

  - x86/platform/UV: Ensure uv_system_init is called when
    necessary (bsc#1023866).

  - x86/platform/UV: Fix 2 socket config problem
    (bsc#1023866).

  - x86/platform/UV: Fix panic with missing UVsystab support
    (bsc#1023866).

  - x86/platform/UV: Initialize PCH GPP_D_0 NMI Pin to be
    NMI source (bsc#1023866).

  - x86/platform/UV: Verify NMI action is valid, default is
    standard (bsc#1023866).

  - x86/platform/intel/iosf_mbi: Add a PMIC bus access
    notifier (bsc#1011913).

  - x86/platform/intel/iosf_mbi: Add a mutex for P-Unit
    access (bsc#1011913).

  - x86/platform: Remove warning message for duplicate NMI
    handlers (bsc#1029220).

  - x86/ras/therm_throt: Do not log a fake MCE for thermal
    events (bsc#1028027).

  - xen-blkfront: correct maximum segment accounting
    (bsc#1018263).

  - xen-blkfront: do not call talk_to_blkback when already
    connected to blkback.

  - xen-blkfront: free resources if xlvbd_alloc_gendisk
    fails.

  - xen/blkfront: Fix crash if backend does not follow the
    right states.

  - xen/netback: set default upper limit of tx/rx queues to
    8 (bnc#1019163).

  - xen/netfront: set default upper limit of tx/rx queues to
    8 (bnc#1019163).

  - xen: Use machine addresses in /sys/kernel/vmcoreinfo
    when PV (bsc#1014136)

  - xfs: do not take the IOLOCK exclusive for direct I/O
    page invalidation (bsc#1015609).

  - xgene_enet: remove bogus forward declarations
    (bsc#1032673).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1029220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1029514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1029634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1029986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1030118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1030213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1032006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1032673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1032681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/897662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10200.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2117.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9191.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2596.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2671.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6214.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6345.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6346.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6347.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7187.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7261.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7294.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7308.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7374.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171183-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0f706f7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2017-697=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-697=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-697=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-697=1

SUSE Linux Enterprise Live Patching 12:zypper in -t patch
SUSE-SLE-Live-Patching-12-2017-697=1

SUSE Linux Enterprise High Availability 12-SP2:zypper in -t patch
SUSE-SLE-HA-12-SP2-2017-697=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-697=1

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2017-697=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-4.4.59-92.17.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-base-4.4.59-92.17.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-base-debuginfo-4.4.59-92.17.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-debuginfo-4.4.59-92.17.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-debugsource-4.4.59-92.17.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-devel-4.4.59-92.17.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-syms-4.4.59-92.17.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-4.4.59-92.17.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-debuginfo-4.4.59-92.17.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-debugsource-4.4.59-92.17.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-devel-4.4.59-92.17.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-extra-4.4.59-92.17.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-4.4.59-92.17.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-syms-4.4.59-92.17.2")) flag++;


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
