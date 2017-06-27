#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-418.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99156);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/03 14:49:09 $");

  script_cve_id("CVE-2016-10200", "CVE-2016-2117", "CVE-2016-9191", "CVE-2017-2596", "CVE-2017-2636", "CVE-2017-5986", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6347", "CVE-2017-6353", "CVE-2017-7184");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-418)");
  script_summary(english:"Check for the openSUSE-2017-418 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.2 kernel was updated to 4.4.56 fix various
security issues and bugs.

The following security bugs were fixed :

  - CVE-2017-7184: The xfrm_replay_verify_len function in
    net/xfrm/xfrm_user.c in the Linux kernel did not
    validate certain size data after an XFRM_MSG_NEWAE
    update, which allowed local users to obtain root
    privileges or cause a denial of service (heap-based
    out-of-bounds access) by leveraging the CAP_NET_ADMIN
    capability, as demonstrated during a Pwn2Own competition
    at CanSecWest 2017 for the Ubuntu 16.10 linux-image-*
    package 4.8.0.41.52 (bnc#1030573).

  - CVE-2016-10200: Race condition in the L2TPv3 IP
    Encapsulation feature in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (use-after-free) by making multiple bind system calls
    without properly ascertaining whether a socket has the
    SOCK_ZAPPED status, related to net/l2tp/l2tp_ip.c and
    net/l2tp/l2tp_ip6.c (bnc#1028415).

  - CVE-2017-2636: Race condition in drivers/tty/n_hdlc.c in
    the Linux kernel allowed local users to gain privileges
    or cause a denial of service (double free) by setting
    the HDLC line discipline (bnc#1027565).

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
    CVE-2017-5986 (bnc#1025235).

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
    net/ipv4/ip_sockglue.c in the Linux kernel has incorrect
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
    for executing a crafted application, as demonstrated by
    trinity (bnc#1008842).

  - CVE-2017-2596: The nested_vmx_check_vmptr function in
    arch/x86/kvm/vmx.c in the Linux kernel improperly
    emulates the VMXON instruction, which allowed KVM L1
    guest OS users to cause a denial of service (host OS
    memory consumption) by leveraging the mishandling of
    page references (bnc#1022785).

The following non-security bugs were fixed :

  - ACPI: Do not create a platform_device for IOAPIC/IOxAPIC
    (bsc#1028819).

  - ACPI, ioapic: Clear on-stack resource before using it
    (bsc#1028819).

  - ACPI: Remove platform devices from a bus on removal
    (bsc#1028819).

  - add mainline tag to one hyperv patch

  - bnx2x: allow adding VLANs while interface is down
    (bsc#1027273).

  - btrfs: backref: Fix soft lockup in __merge_refs function
    (bsc#1017641).

  - btrfs: incremental send, do not delay rename when parent
    inode is new (bsc#1028325).

  - btrfs: incremental send, do not issue invalid rmdir
    operations (bsc#1028325).

  - btrfs: qgroup: Move half of the qgroup accounting time
    out of commit trans (bsc#1017461).

  - btrfs: send, fix failure to rename top level inode due
    to name collision (bsc#1028325).

  - btrfs: serialize subvolume mounts with potentially
    mismatching rw flags (bsc#951844 bsc#1024015)

  - crypto: algif_hash - avoid zero-sized array
    (bnc#1007962).

  - cxgb4vf: do not offload Rx checksums for IPv6 fragments
    (bsc#1026692).

  - drivers: hv: vmbus: Prevent sending data on a rescinded
    channel (fate#320485, bug#1028217).

  - drm/i915: Add intel_uncore_suspend / resume functions
    (bsc#1011913).

  - drm/i915: Listen for PMIC bus access notifications
    (bsc#1011913).

  - drm/mgag200: Added support for the new device G200eH3
    (bsc#1007959, fate#322780)

  - ext4: fix fencepost in s_first_meta_bg validation
    (bsc#1029986).

  - Fix kABI breakage of dccp in 4.4.56 (stable-4.4.56).

  - futex: Add missing error handling to FUTEX_REQUEUE_PI
    (bsc#969755).

  - futex: Fix potential use-after-free in FUTEX_REQUEUE_PI
    (bsc#969755).

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

  - i2c-designware: increase timeout (bsc#1011913).

  - i2c: designware: Never suspend i2c-busses used for
    accessing the system PMIC (bsc#1011913).

  - i2c: designware: Rename accessor_flags to flags
    (bsc#1011913).

  - kABI: protect struct iscsi_conn (kabi).

  - kABI: protect struct se_node_acl (kabi).

  - kABI: restore can_rx_register parameters (kabi).

  - kgr/module: make a taint flag module-specific
    (fate#313296).

  - kgr: remove all arch-specific kgraft header files
    (fate#313296).

  - l2tp: fix address test in __l2tp_ip6_bind_lookup()
    (bsc#1028415).

  - l2tp: fix lookup for sockets not bound to a device in
    l2tp_ip (bsc#1028415).

  - l2tp: fix racy socket lookup in l2tp_ip and l2tp_ip6
    bind() (bsc#1028415).

  - l2tp: hold socket before dropping lock in l2tp_ip{,
    6}_recv() (bsc#1028415).

  - l2tp: lock socket before checking flags in connect()
    (bsc#1028415).

  - md/raid1: add rcu protection to rdev in fix_read_error
    (References: bsc#998106,bsc#1020048,bsc#982783).

  - md/raid1: fix a use-after-free bug
    (bsc#998106,bsc#1020048,bsc#982783).

  - md/raid1: handle flush request correctly
    (bsc#998106,bsc#1020048,bsc#982783).

  - md/raid1: Refactor raid1_make_request
    (bsc#998106,bsc#1020048,bsc#982783).

  - mm: fix set pageblock migratetype in deferred struct
    page init (bnc#1027195).

  - mm/page_alloc: Remove useless parameter of
    __free_pages_boot_core (bnc#1027195).

  - module: move add_taint_module() to a header file
    (fate#313296).

  - net/ena: change condition for host attribute
    configuration (bsc#1026509).

  - net/ena: change driver's default timeouts (bsc#1026509).

  - net: ena: change the return type of ena_set_push_mode()
    to be void (bsc#1026509).

  - net: ena: Fix error return code in ena_device_init()
    (bsc#1026509).

  - net/ena: fix ethtool RSS flow configuration
    (bsc#1026509).

  - net/ena: fix NULL dereference when removing the driver
    after device reset failed (bsc#1026509).

  - net/ena: fix potential access to freed memory during
    device reset (bsc#1026509).

  - net/ena: fix queues number calculation (bsc#1026509).

  - net/ena: fix RSS default hash configuration
    (bsc#1026509).

  - net/ena: reduce the severity of ena printouts
    (bsc#1026509).

  - net/ena: refactor ena_get_stats64 to be atomic context
    safe (bsc#1026509).

  - net/ena: remove ntuple filter support from device
    feature list (bsc#1026509).

  - net: ena: remove superfluous check in ena_remove()
    (bsc#1026509).

  - net: ena: Remove unnecessary pci_set_drvdata()
    (bsc#1026509).

  - net/ena: update driver version to 1.1.2 (bsc#1026509).

  - net/ena: use READ_ONCE to access completion descriptors
    (bsc#1026509).

  - net: ena: use setup_timer() and mod_timer()
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

  - NFS: do not try to cross a mountpount when there isn't
    one there (bsc#1028041).

  - nvme: Do not suspend admin queue that wasn't created
    (bsc#1026505).

  - nvme: Suspend all queues before deletion (bsc#1026505).

  - PCI: hv: Fix wslot_to_devfn() to fix warnings on device
    removal (fate#320485, bug#1028217).

  - PCI: hv: Use device serial number as PCI domain
    (fate#320485, bug#1028217).

  - powerpc: Blacklist GCC 5.4 6.1 and 6.2 (boo#1028895).

  - RAID1: a new I/O barrier implementation to remove resync
    window (bsc#998106,bsc#1020048,bsc#982783).

  - RAID1: avoid unnecessary spin locks in I/O barrier code
    (bsc#998106,bsc#1020048,bsc#982783).

  - Revert 'give up on gcc ilog2() constant optimizations'
    (kabi).

  - Revert 'net: introduce device min_header_len' (kabi).

  - Revert 'net/mlx4_en: Avoid unregister_netdev at shutdown
    flow' (bsc#1028017).

  - Revert 'nfit, libnvdimm: fix interleave set cookie
    calculation' (kabi).

  - Revert 'RDMA/core: Fix incorrect structure packing for
    booleans' (kabi).

  - Revert 'target: Fix NULL dereference during LUN lookup +
    active I/O shutdown' (kabi).

  - rtlwifi: rtl_usb: Fix missing entry in USB driver's
    private data (bsc#1026462).

  - s390/kmsg: add missing kmsg descriptions (bnc#1025683,
    LTC#151573).

  - s390/mm: fix zone calculation in arch_add_memory()
    (bnc#1025683, LTC#152318).

  - sched/loadavg: Avoid loadavg spikes caused by delayed
    NO_HZ accounting (bsc#1018419).

  - scsi_dh_alua: Do not modify the interval value for
    retries (bsc#1012910).

  - scsi: do not print 'reservation conflict' for TEST UNIT
    READY (bsc#1027054).

  - softirq: Let ksoftirqd do its job (bsc#1019618).

  - supported.conf: Add tcp_westwood as supported module
    (fate#322432)

  - taint/module: Clean up global and module taint flags
    handling (fate#313296).

  - Update mainline reference in
    patches.drivers/drm-ast-Fix-memleaks-in-error-path-in-as
    t_fb_create.patch See (bsc#1028158) for the context in
    which this was discovered upstream.

  - x86/apic/uv: Silence a shift wrapping warning
    (bsc#1023866).

  - x86/mce: Do not print MCEs when mcelog is active
    (bsc#1013994).

  - x86, mm: fix gup_pte_range() vs DAX mappings
    (bsc#1026405).

  - x86/mm/gup: Simplify get_user_pages() PTE bit handling
    (bsc#1026405).

  - x86/platform/intel/iosf_mbi: Add a mutex for P-Unit
    access (bsc#1011913).

  - x86/platform/intel/iosf_mbi: Add a PMIC bus access
    notifier (bsc#1011913).

  - x86/platform: Remove warning message for duplicate NMI
    handlers (bsc#1029220).

  - x86/platform/UV: Add basic CPU NMI health check
    (bsc#1023866).

  - x86/platform/UV: Add Support for UV4 Hubless NMIs
    (bsc#1023866).

  - x86/platform/UV: Add Support for UV4 Hubless systems
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

  - xen-blkfront: correct maximum segment accounting
    (bsc#1018263).

  - xen-blkfront: do not call talk_to_blkback when already
    connected to blkback.

  - xen/blkfront: Fix crash if backend does not follow the
    right states.

  - xen-blkfront: free resources if xlvbd_alloc_gendisk
    fails.

  - xen/netback: set default upper limit of tx/rx queues to
    8 (bnc#1019163).

  - xen/netfront: set default upper limit of tx/rx queues to
    8 (bnc#1019163).

  - xfs: do not take the IOLOCK exclusive for direct I/O
    page invalidation (bsc#1015609)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998106"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.57-18.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.57-18.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.57-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.57-18.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-docs-html / kernel-docs-pdf / kernel-devel / kernel-macros / etc");
}
