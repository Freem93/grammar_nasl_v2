#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-532.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99927);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/02 13:34:10 $");

  script_cve_id("CVE-2016-4997", "CVE-2016-4998", "CVE-2017-2671", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7294", "CVE-2017-7308", "CVE-2017-7374", "CVE-2017-7616", "CVE-2017-7618");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-532)");
  script_summary(english:"Check for the openSUSE-2017-532 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.2 kernel was updated to 4.4.62 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2017-7618: crypto/ahash.c in the Linux kernel
    allowed attackers to cause a denial of service (API
    operation calling its own callback, and infinite
    recursion) by triggering EBUSY on a full queue
    (bnc#1033340).

  - CVE-2016-4997: The compat IPT_SO_SET_REPLACE and
    IP6T_SO_SET_REPLACE setsockopt implementations in the
    netfilter subsystem in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (memory corruption) by leveraging in-container root
    access to provide a crafted offset value that triggers
    an unintended decrement (bnc#986362).

  - CVE-2016-4998: The IPT_SO_SET_REPLACE setsockopt
    implementation in the netfilter subsystem in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds read) or possibly obtain sensitive
    information from kernel heap memory by leveraging
    in-container root access to provide a crafted offset
    value that leads to crossing a ruleset blob boundary
    (bnc#986365).

  - CVE-2017-7616: Incorrect error handling in the
    set_mempolicy and mbind compat syscalls in
    mm/mempolicy.c in the Linux kernel allowed local users
    to obtain sensitive information from uninitialized stack
    data by triggering failure of a certain bitmap operation
    (bnc#1033336).

  - CVE-2017-2671: The ping_unhash function in
    net/ipv4/ping.c in the Linux kernel was too late in
    obtaining a certain lock and consequently cannot ensure
    that disconnect function calls are safe, which allowed
    local users to cause a denial of service (panic) by
    leveraging access to the protocol value of IPPROTO_ICMP
    in a socket system call (bnc#1031003).

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

The following non-security bugs were fixed :

  - acpi, nfit: fix acpi_nfit_flush_probe() crash
    (bsc#1031717).

  - acpi, nfit: fix extended status translations for ACPI
    DSMs (bsc#1031717).

  - arm64: hugetlb: fix the wrong address for several
    functions (bsc#1032681).

  - arm64: hugetlb: fix the wrong return value for
    huge_ptep_set_access_flags (bsc#1032681).

  - arm64: hugetlb: remove the wrong pmd check in
    find_num_contig() (bsc#1032681).

  - arm64: Use full path in KBUILD_IMAGE definition
    (bsc#1010032).

  - arm: Use full path in KBUILD_IMAGE definition
    (bsc#1010032).

  - blacklist.conf: 73667e31a153 x86/hyperv: Hide unused
    label

  - blacklist.conf: Add ed10858 ('scsi: smartpqi: fix time
    handling') to blacklist

  - blacklist.conf: blacklist 9770404a which was
    subsequently reverted

  - blacklist.conf: Blacklist f2fs fix

  - blacklist.conf: Blacklist unneeded commit, because of a
    partial backport.

  - blacklist.conf: Split SP2 and SP3 entries to ease
    merging

  - blacklist: Fix blacklisting of 0c313cb20732

  - block: copy NOMERGE flag from bio to request
    (bsc#1030070).

  - bonding: fix 802.3ad aggregator reselection
    (bsc#1029514).

  - btrfs: add transaction space reservation tracepoints
    (bsc#1012452).

  - btrfs: allow unlink to exceed subvolume quota
    (bsc#1019614).

  - btrfs: avoid uninitialized variable warning
    (bsc#1012452).

  - btrfs: __btrfs_buffered_write: Reserve/release extents
    aligned to block size (bsc#1012452).

  - btrfs: btrfs_ioctl_clone: Truncate complete page after
    performing clone operation (bsc#1012452).

  - btrfs: btrfs_page_mkwrite: Reserve space in sectorsized
    units (bsc#1012452).

  - btrfs: btrfs_submit_direct_hook: Handle map_length < bio
    vector length (bsc#1012452).

  - btrfs: change how we update the global block rsv
    (bsc#1012452).

  - btrfs: Change qgroup_meta_rsv to 64bit (bsc#1019614).

  - btrfs: check reserved when deciding to background flush
    (bsc#1012452).

  - btrfs: Clean pte corresponding to page straddling i_size
    (bsc#1012452).

  - btrfs: Compute and look up csums based on sectorsized
    blocks (bsc#1012452).

  - btrfs: csum_tree_block: return proper errno value
    (bsc#1012452).

  - btrfs: device add and remove: use GFP_KERNEL
    (bsc#1012452).

  - btrfs: Direct I/O read: Work on sectorsized blocks
    (bsc#1012452).

  - btrfs: do not write corrupted metadata blocks to disk
    (bsc#1012452).

  - btrfs: extent same: use GFP_KERNEL for page array
    allocations (bsc#1012452).

  - btrfs: fallback to vmalloc in btrfs_compare_tree
    (bsc#1012452).

  - btrfs: fallocate: use GFP_KERNEL (bsc#1012452).

  - btrfs: fallocate: Work with sectorsized blocks
    (bsc#1012452).

  - btrfs: Fix block size returned to user space
    (bsc#1012452).

  - btrfs: fix build warning (bsc#1012452).

  - btrfs: fix delalloc accounting after copy_from_user
    faults (bsc#1012452).

  - btrfs: fix extent_same allowing destination offset
    beyond i_size (bsc#1012452).

  - btrfs: fix handling of faults from btrfs_copy_from_user
    (bsc#1012452).

  - btrfs: fix invalid reference in replace_path
    (bsc#1012452).

  - btrfs: fix listxattrs not listing all xattrs packed in
    the same item (bsc#1012452).

  - btrfs: fix lockdep deadlock warning due to dev_replace
    (bsc#1012452).

  - btrfs: fix truncate_space_check (bsc#1012452).

  - btrfs: Improve FL_KEEP_SIZE handling in fallocate
    (bsc#1012452).

  - btrfs: let callers of btrfs_alloc_root pass gfp flags
    (bsc#1012452).

  - btrfs: Limit inline extents to root->sectorsize
    (bsc#1012452).

  - btrfs: make sure we stay inside the bvec during
    __btrfs_lookup_bio_sums (bsc#1012452).

  - btrfs: Output more info for enospc_debug mount option
    (bsc#1012452).

  - btrfs: Print Warning only if ENOSPC_DEBUG is enabled
    (bsc#1012452).

  - btrfs: qgroups: Retry after commit on getting EDQUOT
    (bsc#1019614).

  - btrfs: reada: add all reachable mirrors into reada
    device list (bsc#1012452).

  - btrfs: reada: Add missed segment checking in
    reada_find_zone (bsc#1012452).

  - btrfs: reada: Avoid many times of empty loop
    (bsc#1012452).

  - btrfs: reada: avoid undone reada extents in
    btrfs_reada_wait (bsc#1012452).

  - btrfs: reada: bypass adding extent when all zone failed
    (bsc#1012452).

  - btrfs: reada: Fix a debug code typo (bsc#1012452).

  - btrfs: reada: Fix in-segment calculation for reada
    (bsc#1012452).

  - btrfs: reada: ignore creating reada_extent for a
    non-existent device (bsc#1012452).

  - btrfs: reada: Jump into cleanup in direct way for
    __readahead_hook() (bsc#1012452).

  - btrfs: reada: limit max works count (bsc#1012452).

  - btrfs: reada: Move is_need_to_readahead contition
    earlier (bsc#1012452).

  - btrfs: reada: move reada_extent_put to place after
    __readahead_hook() (bsc#1012452).

  - btrfs: reada: Pass reada_extent into __readahead_hook
    directly (bsc#1012452).

  - btrfs: reada: reduce additional fs_info->reada_lock in
    reada_find_zone (bsc#1012452).

  - btrfs: reada: Remove level argument in severial
    functions (bsc#1012452).

  - btrfs: reada: simplify dev->reada_in_flight processing
    (bsc#1012452).

  - btrfs: reada: Use fs_info instead of root in
    __readahead_hook's argument (bsc#1012452).

  - btrfs: reada: use GFP_KERNEL everywhere (bsc#1012452).

  - btrfs: readdir: use GFP_KERNEL (bsc#1012452).

  - btrfs: remove redundant error check (bsc#1012452).

  - btrfs: Reset IO error counters before start of device
    replacing (bsc#1012452).

  - btrfs: scrub: use GFP_KERNEL on the submission path
    (bsc#1012452).

  - btrfs: Search for all ordered extents that could span
    across a page (bsc#1012452).

  - btrfs: send: use GFP_KERNEL everywhere (bsc#1012452).

  - btrfs: switch to kcalloc in btrfs_cmp_data_prepare
    (bsc#1012452).

  - btrfs: Use (eb->start, seq) as search key for tree
    modification log (bsc#1012452).

  - btrfs: use proper type for failrec in extent_state
    (bsc#1012452).

  - ceph: fix recursively call between ceph_set_acl and
    __ceph_setattr (bsc#1034902).

  - cgroup/pids: remove spurious suspicious RCU usage
    warning (bnc#1031831).

  - cxgb4: Add control net_device for configuring PCIe VF
    (bsc#1021424).

  - cxgb4: Add llseek operation for flash debugfs entry
    (bsc#1021424).

  - cxgb4: add new routine to get adapter info
    (bsc#1021424).

  - cxgb4: Add PCI device ID for new adapter (bsc#1021424).

  - cxgb4: Add port description for new cards (bsc#1021424).

  - cxgb4: Add support to enable logging of firmware mailbox
    commands (bsc#1021424).

  - cxgb4: Check for firmware errors in the mailbox command
    loop (bsc#1021424).

  - cxgb4: correct device ID of T6 adapter (bsc#1021424).

  - cxgb4/cxgb4vf: Add set VF mac address support
    (bsc#1021424).

  - cxgb4/cxgb4vf: Allocate more queues for 25G and 100G
    adapter (bsc#1021424).

  - cxgb4/cxgb4vf: Assign netdev->dev_port with port ID
    (bsc#1021424).

  - cxgb4/cxgb4vf: Display 25G and 100G link speed
    (bsc#1021424).

  - cxgb4/cxgb4vf: Remove deprecated module parameters
    (bsc#1021424).

  - cxgb4: DCB message handler needs to use correct portid
    to netdev mapping (bsc#1021424).

  - cxgb4: Decode link down reason code obtained from
    firmware (bsc#1021424).

  - cxgb4: Do not assume FW_PORT_CMD reply is always port
    info msg (bsc#1021424).

  - cxgb4: do not call napi_hash_del() (bsc#1021424).

  - cxgb4: Do not sleep when mbox cmd is issued from
    interrupt context (bsc#1021424).

  - cxgb4: Enable SR-IOV configuration via PCI sysfs
    interface (bsc#1021424).

  - cxgb4: Fix issue while re-registering VF mgmt netdev
    (bsc#1021424).

  - cxgb4: MU requested by Chelsio (bsc#1021424).

  - cxgb4: Properly decode port module type (bsc#1021424).

  - cxgb4: Refactor t4_port_init function (bsc#1021424).

  - cxgb4: Reset dcb state machine and tx queue prio only if
    dcb is enabled (bsc#1021424).

  - cxgb4: Support compressed error vector for T6
    (bsc#1021424).

  - cxgb4: Synchronize access to mailbox (bsc#1021424).

  - cxgb4: update latest firmware version supported
    (bsc#1021424).

  - device-dax: fix private mapping restriction, permit
    read-only (bsc#1031717).

  - drivers: hv: util: do not forget to init host_ts.lock
    (bsc#1031206).

  - drivers: hv: vmbus: Raise retry/wait limits in
    vmbus_post_msg() (fate#320485, bsc#1023287,
    bsc#1028217).

  - drm/i915: Fix crash after S3 resume with DP MST mode
    change (bsc#1029634).

  - drm/i915: Introduce Kabypoint PCH for Kabylake H/DT
    (bsc#1032581).

  - drm/i915: Only enable hotplug interrupts if the display
    interrupts are enabled (bsc#1031717).

  - ext4: fix use-after-iput when fscrypt contexts are
    inconsistent (bsc#1012829).

  - hid: usbhid: Quirk a AMI virtual mouse and keyboard with
    ALWAYS_POLL (bsc#1022340).

  - hv: export current Hyper-V clocksource (bsc#1031206).

  - hv_utils: implement Hyper-V PTP source (bsc#1031206).

  - ibmvnic: Allocate number of rx/tx buffers agreed on by
    firmware (fate#322021, bsc#1031512).

  - ibmvnic: Call napi_disable instead of napi_enable in
    failure path (fate#322021, bsc#1031512).

  - ibmvnic: Correct ibmvnic handling of device open/close
    (fate#322021, bsc#1031512).

  - ibmvnic: Fix endian errors in error reporting output
    (fate#322021, bsc#1031512).

  - ibmvnic: Fix endian error when requesting device
    capabilities (fate#322021, bsc#1031512).

  - ibmvnic: Fix initial MTU settings (bsc#1031512).

  - ibmvnic: Fix overflowing firmware/hardware TX queue
    (fate#322021, bsc#1031512).

  - ibmvnic: Free tx/rx scrq pointer array when releasing
    sub-crqs (fate#322021, bsc#1031512).

  - ibmvnic: Handle processing of CRQ messages in a tasklet
    (fate#322021, bsc#1031512).

  - ibmvnic: Initialize completion variables before starting
    work (fate#322021, bsc#1031512).

  - ibmvnic: Make CRQ interrupt tasklet wait for all
    capabilities crqs (fate#322021, bsc#1031512).

  - ibmvnic: Move ibmvnic adapter intialization to its own
    routine (fate#322021, bsc#1031512).

  - ibmvnic: Move login and queue negotiation into
    ibmvnic_open (fate#322021, bsc#1031512).

  - ibmvnic: Move login to its own routine (fate#322021,
    bsc#1031512).

  - ibmvnic: Use common counter for capabilities checks
    (fate#322021, bsc#1031512).

  - ibmvnic: use max_mtu instead of req_mtu for MTU range
    check (bsc#1031512).

  - iommu/vt-d: Make sure IOMMUs are off when
    intel_iommu=off (bsc#1031208).

  - iscsi-target: Return error if unable to add network
    portal (bsc#1032803).

  - kABI: restore ttm_ref_object_add parameters (kabi).

  - kgr: Mark eeh_event_handler() kthread safe using a
    timeout (bsc#1031662).

  - kvm: svm: add support for RDTSCP (bsc#1033117).

  - l2tp: hold tunnel socket when handling control frames in
    l2tp_ip and l2tp_ip6 (bsc#1028415).

  - libcxgb: add library module for Chelsio drivers
    (bsc#1021424).

  - libnvdimm, pfn: fix memmap reservation size versus 4K
    alignment (bsc#1031717).

  - locking/semaphore: Add down_interruptible_timeout()
    (bsc#1031662).

  - md: handle read-only member devices better
    (bsc#1033281).

  - mem-hotplug: fix node spanned pages when we have a
    movable node (bnc#1034671).

  - mm/huge_memory.c: respect FOLL_FORCE/FOLL_COW for thp
    (bnc#1030118).

  - mm/memblock.c: fix memblock_next_valid_pfn()
    (bnc#1031200).

  - mm: page_alloc: skip over regions of invalid pfns where
    possible (bnc#1031200).

  - netfilter: allow logging from non-init namespaces
    (bsc#970083).

  - net: ibmvnic: Remove unused net_stats member from struct
    ibmvnic_adapter (fate#322021, bsc#1031512).

  - nfs: flush out dirty data on file fput() (bsc#1021762).

  - nvme: Delete created IO queues on reset (bsc#1031717).

  - overlayfs: compat, fix incorrect dentry use in
    ovl_rename2 (bsc#1032400).

  - overlayfs: compat, use correct dentry to detect compat
    mode in ovl_compat_is_whiteout (bsc#1032400).

  - ping: implement proper locking (bsc#1031003).

  - powerpc/fadump: Reserve memory at an offset closer to
    bottom of RAM (bsc#1032141).

  - powerpc/fadump: Update fadump documentation
    (bsc#1032141).

  - Revert 'btrfs: qgroup: Move half of the qgroup
    accounting time out of' (bsc#1017461 bsc#1033885).

  - Revert 'btrfs: qgroup: Move half of the qgroup
    accounting time out of' This reverts commit
    f69c1d0f6254c73529a48fd2f87815d047ad7288.

  - Revert 'Revert 'btrfs: qgroup: Move half of the qgroup
    accounting time' This reverts commit
    8567943ca56d937acfc417947cba917de653b09c.

  - sbp-target: Fix second argument of percpu_ida_alloc()
    (bsc#1032803).

  - scsi: cxgb4i: libcxgbi: cxgb4: add T6 iSCSI completion
    feature (bsc#1021424).

  - scsi_error: count medium access timeout only once per EH
    run (bsc#993832, bsc#1032345).

  - scsi: ipr: do not set DID_PASSTHROUGH on CHECK CONDITION
    (bsc#1034419).

  - scsi: ipr: Driver version 2.6.4 (bsc#1031555,
    fate#321595).

  - scsi: ipr: Error path locking fixes (bsc#1031555,
    fate#321595).

  - scsi: ipr: Fix abort path race condition (bsc#1031555,
    fate#321595).

  - scsi: ipr: Fix missed EH wakeup (bsc#1031555,
    fate#321595).

  - scsi: ipr: Fix SATA EH hang (bsc#1031555, fate#321595).

  - scsi: ipr: Remove redundant initialization (bsc#1031555,
    fate#321595).

  - scsi_transport_fc: do not call queue_work under lock
    (bsc#1013887).

  - scsi_transport_fc: fixup race condition in
    fc_rport_final_delete() (bsc#1013887).

  - scsi_transport_fc: return -EBUSY for deleted vport
    (bsc#1013887).

  - sysfs: be careful of error returns from ops->show()
    (bsc#1028883).

  - thp: fix MADV_DONTNEED vs. numa balancing race
    (bnc#1027974).

  - thp: reduce indentation level in change_huge_pmd()
    (bnc#1027974).

  - tpm: fix checks for policy digest existence in
    tpm2_seal_trusted() (bsc#1034048, Pending fixes
    2017-04-10).

  - tpm: fix RC value check in tpm2_seal_trusted
    (bsc#1034048, Pending fixes 2017-04-10).

  - tpm: fix: set continueSession attribute for the unseal
    operation (bsc#1034048, Pending fixes 2017-04-10).

  - vmxnet3: segCnt can be 1 for LRO packets (bsc#988065).

  - x86/CPU/AMD: Fix Zen SMT topology (bsc#1027512).

  - x86/ioapic: Change prototype of acpi_ioapic_add()
    (bsc#1027153, bsc#1027616).

  - x86/ioapic: Fix incorrect pointers in
    ioapic_setup_resources() (bsc#1027153, bsc#1027616).

  - x86/ioapic: Fix IOAPIC failing to request resource
    (bsc#1027153, bsc#1027616).

  - x86/ioapic: fix kABI (hide added include) (bsc#1027153,
    bsc#1027616).

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

  - x86/mce: Fix copy/paste error in exception table entries
    (fate#319858).

  - x86/platform/uv: Fix calculation of Global Physical
    Address (bsc#1031147).

  - x86/ras/therm_throt: Do not log a fake MCE for thermal
    events (bsc#1028027).

  - xen: Use machine addresses in /sys/kernel/vmcoreinfo
    when PV (bsc#1014136)

  - xgene_enet: remove bogus forward declarations
    (bsc#1032673)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993832"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");
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

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.62-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.62-18.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.62-18.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.62-18.6.1") ) flag++;

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
