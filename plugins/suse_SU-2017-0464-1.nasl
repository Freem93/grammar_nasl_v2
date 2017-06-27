#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0464-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(97189);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_cve_id("CVE-2015-8962", "CVE-2015-8963", "CVE-2015-8964", "CVE-2016-10088", "CVE-2016-7910", "CVE-2016-7911", "CVE-2016-7913", "CVE-2016-7914", "CVE-2016-8399", "CVE-2016-8633", "CVE-2016-8645", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9576", "CVE-2016-9756", "CVE-2016-9793", "CVE-2016-9806", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-5551");
  script_osvdb_id(146370, 146377, 146778, 147000, 147033, 147034, 147056, 147057, 147058, 147059, 147168, 148132, 148137, 148195, 148409, 148443, 150064, 150690, 150899);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2017:0464-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.69 to
receive various security and bugfixes. The following security bugs
were fixed :

  - CVE-2015-8962: Double free vulnerability in the
    sg_common_write function in drivers/scsi/sg.c in the
    Linux kernel allowed local users to gain privileges or
    cause a denial of service (memory corruption and system
    crash) by detaching a device during an SG_IO ioctl call
    (bnc#1010501).

  - CVE-2015-8963: Race condition in kernel/events/core.c in
    the Linux kernel allowed local users to gain privileges
    or cause a denial of service (use-after-free) by
    leveraging incorrect handling of an swevent data
    structure during a CPU unplug operation (bnc#1010502).

  - CVE-2015-8964: The tty_set_termios_ldisc function in
    drivers/tty/tty_ldisc.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory by reading a tty data structure (bnc#1010507).

  - CVE-2016-10088: The sg implementation in the Linux
    kernel did not properly restrict write operations in
    situations where the KERNEL_DS option is set, which
    allowed local users to read or write to arbitrary kernel
    memory locations or cause a denial of service
    (use-after-free) by leveraging access to a /dev/sg
    device, related to block/bsg.c and drivers/scsi/sg.c.
    NOTE: this vulnerability exists because of an incomplete
    fix for CVE-2016-9576 (bnc#1017710).

  - CVE-2016-7910: Use-after-free vulnerability in the
    disk_seqf_stop function in block/genhd.c in the Linux
    kernel allowed local users to gain privileges by
    leveraging the execution of a certain stop operation
    even if the corresponding start operation had failed
    (bnc#1010716).

  - CVE-2016-7911: Race condition in the get_task_ioprio
    function in block/ioprio.c in the Linux kernel allowed
    local users to gain privileges or cause a denial of
    service (use-after-free) via a crafted ioprio_get system
    call (bnc#1010711).

  - CVE-2016-7913: The xc2028_set_config function in
    drivers/media/tuners/tuner-xc2028.c in the Linux kernel
    allowed local users to gain privileges or cause a denial
    of service (use-after-free) via vectors involving
    omission of the firmware name from a certain data
    structure (bnc#1010478).

  - CVE-2016-7914: The assoc_array_insert_into_terminal_node
    function in lib/assoc_array.c in the Linux kernel did
    not check whether a slot is a leaf, which allowed local
    users to obtain sensitive information from kernel memory
    or cause a denial of service (invalid pointer
    dereference and out-of-bounds read) via an application
    that uses associative-array data structures, as
    demonstrated by the keyutils test suite (bnc#1010475).

  - CVE-2016-8399: An elevation of privilege vulnerability
    in the kernel networking subsystem could enable a local
    malicious application to execute arbitrary code within
    the context of the kernel. This issue is rated as
    Moderate because it first requires compromising a
    privileged process and current compiler optimizations
    restrict access to the vulnerable code. Product:
    Android. Versions: Kernel-3.10, Kernel-3.18. Android ID:
    A-31349935 (bnc#1014746).

  - CVE-2016-8633: drivers/firewire/net.c in the Linux
    kernel, in certain unusual hardware configurations,
    allowed remote attackers to execute arbitrary code via
    crafted fragmented packets (bnc#1008833).

  - CVE-2016-8645: The TCP stack in the Linux kernel
    mishandled skb truncation, which allowed local users to
    cause a denial of service (system crash) via a crafted
    application that made sendto system calls, related to
    net/ipv4/tcp_ipv4.c and net/ipv6/tcp_ipv6.c
    (bnc#1009969).

  - CVE-2016-9083: drivers/vfio/pci/vfio_pci.c in the Linux
    kernel allowed local users to bypass integer overflow
    checks, and cause a denial of service (memory
    corruption) or have unspecified other impact, by
    leveraging access to a vfio PCI device file for a
    VFIO_DEVICE_SET_IRQS ioctl call, aka a 'state machine
    confusion bug' (bnc#1007197).

  - CVE-2016-9084: drivers/vfio/pci/vfio_pci_intrs.c in the
    Linux kernel misuses the kzalloc function, which allowed
    local users to cause a denial of service (integer
    overflow) or have unspecified other impact by leveraging
    access to a vfio PCI device file (bnc#1007197).

  - CVE-2016-9756: arch/x86/kvm/emulate.c in the Linux
    kernel did not properly initialize Code Segment (CS) in
    certain error cases, which allowed local users to obtain
    sensitive information from kernel stack memory via a
    crafted application (bnc#1013038).

  - CVE-2016-9793: The sock_setsockopt function in
    net/core/sock.c in the Linux kernel mishandled negative
    values of sk_sndbuf and sk_rcvbuf, which allowed local
    users to cause a denial of service (memory corruption
    and system crash) or possibly have unspecified other
    impact by leveraging the CAP_NET_ADMIN capability for a
    crafted setsockopt system call with the (1)
    SO_SNDBUFFORCE or (2) SO_RCVBUFFORCE option (bnc#1013531
    1013542).

  - CVE-2016-9806: Race condition in the netlink_dump
    function in net/netlink/af_netlink.c in the Linux kernel
    allowed local users to cause a denial of service (double
    free) or possibly have unspecified other impact via a
    crafted application that made sendmsg system calls,
    leading to a free operation associated with a new dump
    that started earlier than anticipated (bnc#1013540
    1017589).

  - CVE-2017-2584: arch/x86/kvm/emulate.c in the Linux
    kernel allowed local users to obtain sensitive
    information from kernel memory or cause a denial of
    service (use-after-free) via a crafted application that
    leverages instruction emulation for fxrstor, fxsave,
    sgdt, and sidt (bsc#1019851).

  - CVE-2017-2583: Fixed broken emulation of 'MOV SS, null
    selector' (bsc#1020602).

  - CVE-2017-5551: Clear SGID bit when setting file
    permissions on tmpfs (bsc#1021258). The following
    non-security bugs were fixed :

  - Fixup acl reference leak and missing conversions in
    ext3, gfs2, jfs, hfsplus

  - RAID1: ignore discard error (bsc#1017164).

  - Update
    patches.suse/btrfs-8446-fix-qgroup-accounting-when-creat
    ing-snap.patch (bsc#972993).

  - blacklist: PCI fixes required only for cxl
    (bsc#1016713).

  - blacklist: cxl fixes on SLE12 SP1 (bsc#1016725)

  - blacklist: ibmvnic fixes on SLE12 SP1 (bsc#1016961)

  - block_dev: do not test bdev->bd_contains when it is not
    stable (bsc#1008557).

  - bna: Add synchronization for tx ring (bsc#993739).

  - bnx2i/bnx2fc : fix randconfig error in next-20140909
    (bsc#922052 fate#318602 bsc#922056 FATE#318604).

  - bnx2x: Correct ringparam estimate when DOWN
    (bsc#1020214).

  - bnx2x: fix lockdep splat (bsc#922052 fate#318602
    bsc#922056 FATE#318604).

  - btrfs: Ensure proper sector alignment for
    btrfs_free_reserved_data_space (bsc#1005666).

  - btrfs: Export and move leaf/subtree qgroup helpers to
    qgroup.c (bsc#983087).

  - btrfs: Revert 'Btrfs: do not delay inode ref updates
    during log replay' (bsc#987192).

  - btrfs: bugfix: handle
    FS_IOC32_{GETFLAGS,SETFLAGS,GETVERSION} in btrfs_ioctl
    (bsc#1018100).

  - btrfs: do not delay inode ref updates during log replay
    (bsc#987192).

  - btrfs: fix incremental send failure caused by balance
    (bsc#985850).

  - btrfs: fix relocation incorrectly dropping data
    references (bsc#990384).

  - btrfs: increment ctx->pos for every emitted or skipped
    dirent in readdir (bsc#981709).

  - btrfs: qgroup: Fix qgroup data leaking by using subtree
    tracing (bsc#983087).

  - btrfs: remove old tree_root dirent processing in
    btrfs_real_readdir() (bsc#981709).

  - btrfs: send, do not bug on inconsistent snapshots
    (bsc#985850).

  - cpufreq: intel_pstate: Fix divide by zero on Knights
    Landing (KNL) (bsc#1008876).

  - ext4: fix data exposure after a crash (bsc#1012985).

  - fs: avoid including 'mountproto=' with no protocol in
    /proc/mounts (bsc#1019260).

  - fuse: do not use iocb after it may have been freed
    (bsc#1012985).

  - hpilo: Add support for iLO5 (bsc#999101).

  - ib/core: Avoid unsigned int overflow in sg_alloc_table
    (bsc#924381 FATE#318568 bsc#921338).

  - ib/mlx5: Fix FW version diaplay in sysfs (bnc#923036
    FATE#318772).

  - ib/mlx5: Fix entries check in mlx5_ib_resize_cq
    (bnc#858727 FATE#315946).

  - ib/mlx5: Fix entries checks in mlx5_ib_create_cq
    (bnc#858727 FATE#315946).

  - ib/mlx5: Remove per-MR pas and dma pointers (bnc#923036
    FATE#318772).

  - ibmveth: calculate gso_segs for large packets
    (bsc#1019148).

  - ibmveth: check return of skb_linearize in
    ibmveth_start_xmit (bsc#1019148).

  - ibmveth: consolidate kmalloc of array, memset 0 to
    kcalloc (bsc#1019148).

  - ibmveth: set correct gso_size and gso_type
    (bsc#1019148).

  - igb: Fix oops caused by missing queue pairing
    (bnc#857394).

  - ipmi_si: create hardware-independent softdep for
    ipmi_devintf (bsc#1009062).

  - ipr: Enable SIS pipe commands for SIS-32 devices
    (bsc#1016961).

  - ipv4: Fix ip_queue_xmit to pass sk into ip_local_out_sk
    (bsc#938963 FATE#319084).

  - kabi fix (bsc#1014410).

  - kabi: Whitelist KVM KABI changes resulting from adding a
    hcall. caused by
    5246adec59458b5d325b8e1462ea9ef3ead7f6ae
    powerpc/pseries: Use H_CLEAR_HPT to clear MMU hash table
    during kexec No problem is expected as result of
    changing KVM KABI so whitelisting for now. If we get
    some additional input from IBM we can back out the
    patch.

  - kabi: protect __sk_mem_reclaim (kabi).

  - kabi: protect struct perf_event_context (kabi).

  - kabi: reintroduce sk_filter (kabi).

  - kbuild: Fix removal of the debian/ directory
    (bsc#1010213).

  - kernel: remove broken memory detection sanity check
    (bnc#1008567, LTC#148072).

  - kgr: ignore zombie tasks during the patching
    (bnc#1008979).

  - kgraft/iscsi-target: Do not block kGraft in iscsi_np
    kthread (bsc#1010612).

  - kgraft/xen: Do not block kGraft in xenbus kthread
    (bsc#1017410).

  - move the call of __d_drop(anon) into
    __d_materialise_unique(dentry, anon) (bsc#984194).

  - net/mlx5: Avoid passing dma address 0 to firmware
    (bnc#858727 FATE#315946).

  - net/mlx5: Fix typo in mlx5_query_port_pvlc (bnc#923036
    FATE#318772).

  - net/mlx5e: Do not modify CQ before it was created
    (bnc#923036 FATE#318772).

  - net/mlx5e: Do not try to modify CQ moderation if it is
    not supported (bnc#923036 FATE#318772).

  - net/mlx5e: Fix MLX5E_100BASE_T define (bnc#923036
    FATE#318772).

  - net/mlx5e: Remove wrong poll CQ optimization (bnc#923036
    FATE#318772).

  - netback: correct array index (bsc#983348).

  - nfsv4: Cap the transport reconnection timer at 1/2 lease
    period (bsc#1014410).

  - nfsv4: Cleanup the setting of the nfs4 lease period
    (bsc#1014410).

  - ocfs2: fix BUG_ON() in ocfs2_ci_checkpointed()
    (bnc#1019783).

  - powerpc/pseries: Use H_CLEAR_HPT to clear MMU hash table
    during kexec (bsc#1003813).

  - reiserfs: fix race in prealloc discard (bsc#987576).

  - rpm/kernel-binary.spec.in: Export a make-stderr.log file
    (bsc#1012422)

  - rpm/kernel-spec-macros: Fix the check if there is no
    rebuild counter (bsc#1012060)

  - rpm/kernel-spec-macros: Ignore too high rebuild counter
    (bsc#1012060)

  - serial: 8250_pci: Detach low-level driver during PCI
    error recovery (bsc#1013001).

  - serial: 8250_pci: Fix potential use-after-free in error
    path (bsc#1013001).

  - sfc: clear napi_hash state when copying channels
    (bsc#923037 FATE#318563).

  - sfc: fix potential stack corruption from running past
    stat bitmask (bsc#923037 FATE#318563).

  - sfc: on MC reset, clear PIO buffer linkage in TXQs
    (bnc#856380 FATE#315942).

  - sunrpc: Enforce an upper limit on the number of cached
    credentials (bsc#1012917).

  - sunrpc: Fix reconnection timeouts (bsc#1014410).

  - sunrpc: Limit the reconnect backoff timer to the max RPC
    message timeout (bsc#1014410).

  - supported.conf: Add lib/*.ko to supported.conf
    (bsc#1019032)

  - target: Make EXTENDED_COPY 0xe4 failure return COPY
    TARGET DEVICE NOT REACHABLE (bsc#991273).

  - target: add XCOPY target/segment desc sense codes
    (bsc#991273).

  - target: bounds check XCOPY segment descriptor list
    (bsc#991273).

  - target: bounds check XCOPY total descriptor list length
    (bsc#991273).

  - target: check XCOPY segment descriptor CSCD IDs
    (bsc#1017170).

  - target: check for XCOPY parameter truncation
    (bsc#991273).

  - target: return UNSUPPORTED TARGET/SEGMENT DESC TYPE CODE
    sense (bsc#991273).

  - target: simplify XCOPY wwn->se_dev lookup helper
    (bsc#991273).

  - target: support XCOPY requests without parameters
    (bsc#991273).

  - target: use XCOPY TOO MANY TARGET DESCRIPTORS sense
    (bsc#991273).

  - target: use XCOPY segment descriptor CSCD IDs
    (bsc#1017170).

  - tg3: Avoid NULL pointer dereference in
    tg3_io_error_detected() (bsc#921778 FATE#318558).

  - tty: Prevent ldisc drivers from re-using stale tty
    fields (bnc#1010507).

  - x86/apic: Order irq_enter/exit() calls correctly vs.
    ack_APIC_irq() (bsc#1013479).

  - xen/ftrace/x86: Set ftrace_stub to weak to prevent gcc
    from using short jumps to it (bsc#984419).

  - xenbus: correctly signal errors from
    xenstored_local_init() (luckily none so far).

  - xfs: allow lazy sb counter sync during filesystem freeze
    sequence (bsc#980560).

  - xfs: refactor xlog_recover_process_data() (bsc#1019300).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/856380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/857394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/858727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/923036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/923037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8962.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8963.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8964.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10088.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7910.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7911.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7913.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7914.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8399.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8633.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8645.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9084.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9756.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9793.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9806.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2583.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2584.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5551.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170464-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae10d1e4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1:zypper in -t patch
SUSE-SLE-WE-12-SP1-2017-238=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2017-238=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-238=1

SUSE Linux Enterprise Module for Public Cloud 12:zypper in -t patch
SUSE-SLE-Module-Public-Cloud-12-2017-238=1

SUSE Linux Enterprise Live Patching 12:zypper in -t patch
SUSE-SLE-Live-Patching-12-2017-238=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2017-238=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/15");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"kernel-default-man-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-debuginfo-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debuginfo-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debugsource-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-devel-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-syms-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-devel-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-syms-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.69-60.64.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.69-60.64.29.1")) flag++;


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
