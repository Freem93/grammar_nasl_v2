#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1678-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86290);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/11/14 14:25:31 $");

  script_cve_id("CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-0777", "CVE-2015-1420", "CVE-2015-1805", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-4167", "CVE-2015-4700", "CVE-2015-5364", "CVE-2015-5366", "CVE-2015-5707", "CVE-2015-6252");
  script_bugtraq_id(72357, 73014, 73699, 73921, 74951, 74963, 74964, 75001, 75356, 75510);
  script_osvdb_id(117759, 119409, 119615, 120284, 120316, 122921, 122965, 122966, 122967, 122968, 123637, 123996, 125710, 126403);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : kernel-source (SUSE-SU-2015:1678-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various
security and bugfixes.

Following security bugs were fixed :

  - CVE-2015-6252: Possible file descriptor leak for each
    VHOST_SET_LOG_FDcommand issued, this could eventually
    wasting available system resources and creating a denial
    of service (bsc#942367).

  - CVE-2015-5707: Possible integer overflow in the
    calculation of total number of pages in
    bio_map_user_iov() (bsc#940338).

  - CVE-2015-5364: The (1) udp_recvmsg and (2) udpv6_recvmsg
    functions in the Linux kernel before 4.0.6 do not
    properly consider yielding a processor, which allowed
    remote attackers to cause a denial of service (system
    hang) via incorrect checksums within a UDP packet flood
    (bsc#936831).

  - CVE-2015-5366: The (1) udp_recvmsg and (2) udpv6_recvmsg
    functions in the Linux kernel before 4.0.6 provide
    inappropriate -EAGAIN return values, which allowed
    remote attackers to cause a denial of service (EPOLLET
    epoll application read outage) via an incorrect checksum
    in a UDP packet, a different vulnerability than
    CVE-2015-5364 (bsc#936831).

  - CVE-2015-1420: Race condition in the handle_to_path
    function in fs/fhandle.c in the Linux kernel through
    3.19.1 allowed local users to bypass intended size
    restrictions and trigger read operations on additional
    memory locations by changing the handle_bytes value of a
    file handle during the execution of this function
    (bsc#915517).

  - CVE-2015-1805: The (1) pipe_read and (2) pipe_write
    implementations in fs/pipe.c in the Linux kernel before
    3.16 do not properly consider the side effects of failed
    __copy_to_user_inatomic and __copy_from_user_inatomic
    calls, which allows local users to cause a denial of
    service (system crash) or possibly gain privileges via a
    crafted application, aka an 'I/O' vector array overrun.
    (bsc#933429)

  - CVE-2015-2150: Xen 3.3.x through 4.5.x and the Linux
    kernel through 3.19.1 do not properly restrict access to
    PCI command registers, which might allow local guest
    users to cause a denial of service (non-maskable
    interrupt and host crash) by disabling the (1) memory or
    (2) I/O decoding for a PCI Express device and then
    accessing the device, which triggers an Unsupported
    Request (UR) response. (bsc#919463)

  - CVE-2015-2830: arch/x86/kernel/entry_64.S in the Linux
    kernel before 3.19.2 does not prevent the TS_COMPAT flag
    from reaching a user-mode task, which might allow local
    users to bypass the seccomp or audit protection
    mechanism via a crafted application that uses the (1)
    fork or (2) close system call, as demonstrated by an
    attack against seccomp before 3.16. (bsc#926240)

  - CVE-2015-4700: The bpf_int_jit_compile function in
    arch/x86/net/bpf_jit_comp.c in the Linux kernel before
    4.0.6 allowed local users to cause a denial of service
    (system crash) by creating a packet filter and then
    loading crafted BPF instructions that trigger late
    convergence by the JIT compiler (bsc#935705).

  - CVE-2015-4167: The udf_read_inode function in
    fs/udf/inode.c in the Linux kernel before 3.19.1 did not
    validate certain length values, which allowed local
    users to cause a denial of service (incorrect data
    representation or integer overflow, and OOPS) via a
    crafted UDF filesystem (bsc#933907).

  - CVE-2015-0777: drivers/xen/usbback/usbback.c in
    linux-2.6.18-xen-3.4.0 (aka the Xen 3.4.x support
    patches for the Linux kernel 2.6.18), as used in the
    Linux kernel 2.6.x and 3.x in SUSE Linux distributions,
    allows guest OS users to obtain sensitive information
    from uninitialized locations in host OS kernel memory
    via unspecified vectors. (bsc#917830)

  - CVE-2014-9728: The UDF filesystem implementation in the
    Linux kernel before 3.18.2 did not validate certain
    lengths, which allowed local users to cause a denial of
    service (buffer over-read and system crash) via a
    crafted filesystem image, related to fs/udf/inode.c and
    fs/udf/symlink.c (bsc#933904).

  - CVE-2014-9730: The udf_pc_to_char function in
    fs/udf/symlink.c in the Linux kernel before 3.18.2
    relies on component lengths that are unused, which
    allowed local users to cause a denial of service (system
    crash) via a crafted UDF filesystem image (bsc#933904).

  - CVE-2014-9729: The udf_read_inode function in
    fs/udf/inode.c in the Linux kernel before 3.18.2 did not
    ensure a certain data-structure size consistency, which
    allowed local users to cause a denial of service (system
    crash) via a crafted UDF filesystem image (bsc#933904).

  - CVE-2014-9731: The UDF filesystem implementation in the
    Linux kernel before 3.18.2 did not ensure that space is
    available for storing a symlink target's name along with
    a trailing \0 character, which allowed local users to
    obtain sensitive information via a crafted filesystem
    image, related to fs/udf/symlink.c and fs/udf/unicode.c
    (bsc#933896).

The following non-security bugs were fixed :

  - Btrfs: be aware of btree inode write errors to avoid fs
    corruption (bnc#942350).

  - Btrfs: be aware of btree inode write errors to avoid fs
    corruption (bnc#942404).

  - Btrfs: check if previous transaction aborted to avoid fs
    corruption (bnc#942350).

  - Btrfs: check if previous transaction aborted to avoid fs
    corruption (bnc#942404).

  - Btrfs: deal with convert_extent_bit errors to avoid fs
    corruption (bnc#942350).

  - Btrfs: deal with convert_extent_bit errors to avoid fs
    corruption (bnc#942404).

  - Btrfs: fix hang when failing to submit bio of directIO
    (bnc#942688).

  - Btrfs: fix memory corruption on failure to submit bio
    for direct IO (bnc#942688).

  - Btrfs: fix put dio bio twice when we submit dio bio fail
    (bnc#942688).

  - DRM/I915: Add enum hpd_pin to intel_encoder
    (bsc#942938).

  - DRM/i915: Convert HPD interrupts to make use of HPD pin
    assignment in encoders (v2) (bsc#942938).

  - DRM/i915: Get rid of the 'hotplug_supported_mask' in
    struct drm_i915_private (bsc#942938).

  - DRM/i915: Remove i965_hpd_irq_setup (bsc#942938).

  - DRM/i915: Remove valleyview_hpd_irq_setup (bsc#942938).

  - Ext4: handle SEEK_HOLE/SEEK_DATA generically
    (bsc#934944).

  - IB/core: Fix mismatch between locked and pinned pages
    (bnc#937855).

  - IB/iser: Add Discovery support (bsc#923002).

  - IB/iser: Move informational messages from error to info
    level (bsc#923002).

  - NFS: never queue requests with rq_cong set on the
    sending queue (bsc#932458).

  - NFSD: Fix nfsv4 opcode decoding error (bsc#935906).

  - NFSv4: Minor cleanups for nfs4_handle_exception and
    nfs4_async_handle_error (bsc#939910).

  - PCI: Disable Bus Master only on kexec reboot
    (bsc#920110).

  - PCI: Disable Bus Master unconditionally in
    pci_device_shutdown() (bsc#920110).

  - PCI: Do not try to disable Bus Master on disconnected
    PCI devices (bsc#920110).

  - PCI: Lock down register access when trusted_kernel is
    true (fate#314486, bnc#884333)(bsc#923431).

  - PCI: disable Bus Master on PCI device shutdown
    (bsc#920110).

  - USB: xhci: Reset a halted endpoint immediately when we
    encounter a stall (bnc#933721).

  - USB: xhci: do not start a halted endpoint before its new
    dequeue is set (bnc#933721).

  - Apparmor: fix file_permission if profile is updated
    (bsc#917968).

  - block: Discard bios do not have data (bsc#928988).

  - cifs: Fix missing crypto allocation (bnc#937402).

  - drm/cirrus: do not attempt to acquire a reservation
    while in an interrupt handler (bsc#935572).

  - drm/i915: (re)init HPD interrupt storm statistics
    (bsc#942938).

  - drm/i915: Add HPD IRQ storm detection (v5) (bsc#942938).

  - drm/i915: Add Reenable Timer to turn Hotplug Detection
    back on (v4) (bsc#942938).

  - drm/i915: Add bit field to record which pins have
    received HPD events (v3) (bsc#942938).

  - drm/i915: Add messages useful for HPD storm detection
    debugging (v2) (bsc#942938).

  - drm/i915: Avoid race of intel_crt_detect_hotplug() with
    HPD interrupt (bsc#942938).

  - drm/i915: Disable HPD interrupt on pin when irq storm is
    detected (v3) (bsc#942938).

  - drm/i915: Do not WARN nor handle unexpected hpd
    interrupts on gmch platforms (bsc#942938).

  - drm/i915: Enable hotplug interrupts after querying hw
    capabilities (bsc#942938).

  - drm/i915: Fix hotplug interrupt enabling for SDVOC
    (bsc#942938).

  - drm/i915: Fix up sdvo hpd pins for i965g/gm
    (bsc#942938).

  - drm/i915: Make hpd arrays big enough to avoid out of
    bounds access (bsc#942938).

  - drm/i915: Mask out the HPD irq bits before setting them
    individually (bsc#942938).

  - drm/i915: Only print hotplug event message when hotplug
    bit is set (bsc#942938).

  - drm/i915: Only reprobe display on encoder which has
    received an HPD event (v2) (bsc#942938).

  - drm/i915: Queue reenable timer also when
    enable_hotplug_processing is false (bsc#942938).

  - drm/i915: Remove pch_rq_mask from struct
    drm_i915_private (bsc#942938).

  - drm/i915: Use an interrupt save spinlock in
    intel_hpd_irq_handler() (bsc#942938).

  - drm/i915: WARN_ONCE() about unexpected interrupts for
    all chipsets (bsc#942938).

  - drm/i915: assert_spin_locked for pipestat interrupt
    enable/disable (bsc#942938).

  - drm/i915: clear crt hotplug compare voltage field before
    setting (bsc#942938).

  - drm/i915: close tiny race in the ilk pcu even interrupt
    setup (bsc#942938).

  - drm/i915: fix hotplug event bit tracking (bsc#942938).

  - drm/i915: fix hpd interrupt register locking
    (bsc#942938).

  - drm/i915: fix hpd work vs. flush_work in the pageflip
    code deadlock (bsc#942938).

  - drm/i915: fix locking around
    ironlake_enable|disable_display_irq (bsc#942938).

  - drm/i915: fold the hpd_irq_setup call into
    intel_hpd_irq_handler (bsc#942938).

  - drm/i915: fold the no-irq check into
    intel_hpd_irq_handler (bsc#942938).

  - drm/i915: fold the queue_work into intel_hpd_irq_handler
    (bsc#942938).

  - drm/i915: implement ibx_hpd_irq_setup (bsc#942938).

  - drm/i915:
    s/hotplug_irq_storm_detect/intel_hpd_irq_handler/
    (bsc#942938).

  - drm/mgag200: Do not do full cleanup if
    mgag200_device_init fails (FATE#317582).

  - drm/mgag200: do not attempt to acquire a reservation
    while in an interrupt handler (FATE#317582).

  - drm: ast,cirrus,mgag200: use drm_can_sleep (FATE#317582,
    bnc#883380, bsc#935572).

  - ehci-pci: enable interrupt on BayTrail (bnc926007).

  - exec: kill the unnecessary mm->def_flags setting in
    load_elf_binary() (fate#317831,bnc#891116)).

  - ext3: Fix data corruption in inodes with journalled data
    (bsc#936637).

  - fanotify: Fix deadlock with permission events
    (bsc#935053).

  - fork: reset mm->pinned_vm (bnc#937855).

  - hrtimer: prevent timer interrupt DoS (bnc#886785).

  - hugetlb, kabi: do not account hugetlb pages as
    NR_FILE_PAGES (bnc#930092).

  - hugetlb: do not account hugetlb pages as NR_FILE_PAGES
    (bnc#930092).

  - hv_storvsc: use small sg_tablesize on x86 (bnc#937256).

  - ibmveth: Add GRO support (bsc#935055).

  - ibmveth: Add support for Large Receive Offload
    (bsc#935055).

  - ibmveth: Add support for TSO (bsc#935055).

  - ibmveth: add support for TSO6.

  - ibmveth: change rx buffer default allocation for CMO
    (bsc#935055).

  - igb: do not reuse pages with pfmemalloc flag fix
    (bnc#920016).

  - inotify: Fix nested sleeps in inotify_read()
    (bsc#940925).

  - iommu/amd: Fix memory leak in free_pagetable
    (bsc#935866).

  - iommu/amd: Handle large pages correctly in
    free_pagetable (bsc#935866).

  - ipv6: probe routes asynchronous in rt6_probe
    (bsc#936118).

  - ixgbe: Use pci_vfs_assigned instead of
    ixgbe_vfs_are_assigned (bsc#927355).

  - kabi: wrapper include file with __GENKSYMS__ check to
    avoid kabi change (bsc920110).

  - kdump: fix crash_kexec()/smp_send_stop() race in panic()
    (bnc#937444).

  - kernel: add panic_on_warn.

  - kernel: do full redraw of the 3270 screen on reconnect
    (bnc#943477, LTC#129509).

  - kvm: irqchip: Break up high order allocations of
    kvm_irq_routing_table (bnc#926953).

  - libata: prevent HSM state change race between ISR and
    PIO (bsc#923245).

  - libiscsi: Exporting new attrs for iscsi session and
    connection in sysfs (bsc#923002).

  - md: use kzalloc() when bitmap is disabled (bsc#939994).

  - megaraid_sas: Use correct reset sequence in adp_reset()
    (bsc#894936).

  - megaraid_sas: Use correct reset sequence in adp_reset()
    (bsc#938485).

  - mlx4: Check for assigned VFs before disabling SR-IOV
    (bsc#927355).

  - mm, THP: do not hold mmap_sem in khugepaged when
    allocating THP (VM Performance).

  - mm, mempolicy: remove duplicate code (VM Functionality,
    bnc#931620).

  - mm, thp: fix collapsing of hugepages on madvise (VM
    Functionality).

  - mm, thp: only collapse hugepages to nodes with affinity
    for zone_reclaim_mode (VM Functionality, bnc#931620).

  - mm, thp: really limit transparent hugepage allocation to
    local node (VM Performance, bnc#931620).

  - mm, thp: respect MPOL_PREFERRED policy with non-local
    node (VM Performance, bnc#931620).

  - mm/hugetlb: check for pte NULL pointer in
    __page_check_address() (bnc#929143).

  - mm/mempolicy.c: merge alloc_hugepage_vma to
    alloc_pages_vma (VM Performance, bnc#931620).

  - mm/thp: allocate transparent hugepages on local node (VM
    Performance, bnc#931620).

  - mm: make page pfmemalloc check more robust (bnc#920016).

  - mm: restrict access to slab files under procfs and sysfs
    (bnc#936077).

  - mm: thp: khugepaged: add policy for finding target node
    (VM Functionality, bnc#931620).

  - net/mlx4_core: Do not disable SRIOV if there are active
    VFs (bsc#927355).

  - net: Fix 'ip rule delete table 256' (bsc#873385).

  - net: fib6: fib6_commit_metrics: fix potential NULL
    pointer dereference (bsc#867362).

  - net: ipv6: fib: do not sleep inside atomic lock
    (bsc#867362).

  - netfilter: nf_conntrack_proto_sctp: minimal multihoming
    support (bsc#932350).

  - nfsd: support disabling 64bit dir cookies (bnc#937503).

  - pagecache limit: Do not skip over small zones that
    easily (bnc#925881).

  - pagecache limit: add tracepoints (bnc#924701).

  - pagecache limit: export debugging counters via
    /proc/vmstat (bnc#924701).

  - pagecache limit: fix wrong nr_reclaimed count
    (FATE#309111, bnc#924701).

  - pagecache limit: reduce starvation due to reclaim
    retries (bnc#925903).

  - pci: Add SRIOV helper function to determine if VFs are
    assigned to guest (bsc#927355).

  - pci: Add flag indicating device has been assigned by KVM
    (bnc#777565 FATE#313819).

  - pci: Add flag indicating device has been assigned by KVM
    (bnc#777565 FATE#313819).

  - perf, nmi: Fix unknown NMI warning (bsc#929142).

  - perf/x86/intel: Move NMI clearing to end of PMI handler
    (bsc#929142).

  - qlcnic: Fix NULL pointer dereference in
    qlcnic_hwmon_show_temp() (bsc#936095).

  - r8169: remember WOL preferences on driver load
    (bsc#942305).

  - s390/dasd: fix kernel panic when alias is set offline
    (bnc#940966, LTC#128595).

  - sched: fix __sched_setscheduler() vs load balancing race
    (bnc#921430)

  - scsi: Correctly set the scsi host/msg/status bytes
    (bnc#933936).

  - scsi: fix scsi_error_handler vs. scsi_host_dev_release
    race (bnc#942204).

  - scsi: Moved iscsi kabi patch to patches.kabi
    (bsc#923002)

  - scsi: Set hostbyte status in scsi_check_sense()
    (bsc#920733).

  - scsi: kabi: allow iscsi disocvery session support
    (bsc#923002).

  - scsi: vmw_pvscsi: Fix pvscsi_abort() function
    (bnc#940398 bsc#930934).

  - scsi_error: add missing case statements in
    scsi_decide_disposition() (bsc#920733).

  - scsi_transport_iscsi: Exporting new attrs for iscsi
    session and connection in sysfs (bsc#923002).

  - sg_start_req(): make sure that there's not too many
    elements in iovec (bsc#940338).

  - st: NULL pointer dereference panic caused by use after
    kref_put by st_open (bsc#936875).

  - supported.conf: enable sch_mqprio (bsc#932882)

  - udf: Remove repeated loads blocksize (bsc#933907).

  - usb: core: Fix USB 3.0 devices lost in NOTATTACHED state
    after a hub port reset (bnc#937641).

  - usb: xhci: Prefer endpoint context dequeue pointer over
    stopped_trb (bnc#933721).

  - usb: xhci: handle Config Error Change (CEC) in xhci
    driver (bnc#933721).

  - vmxnet3: Bump up driver version number (bsc#936423).

  - vmxnet3: Changes for vmxnet3 adapter version 2 (fwd)
    (bug#936423).

  - vmxnet3: Fix memory leaks in rx path (fwd) (bug#936423).

  - vmxnet3: Register shutdown handler for device (fwd)
    (bug#936423).

  - x86, tls, ldt: Stop checking lm in LDT_empty
    (bsc#920250).

  - x86, tls: Interpret an all-zero struct user_desc as 'no
    segment' (bsc#920250).

  - x86-64: Do not apply destructive erratum workaround on
    unaffected CPUs (bsc#929076).

  - x86/mm: Improve AMD Bulldozer ASLR workaround
    (bsc#937032).

  - x86/tsc: Change Fast TSC calibration failed from error
    to info (bnc#942605).

  - xenbus: add proper handling of XS_ERROR from Xenbus for
    transactions.

  - xfs: fix problem when using md+XFS under high load
    (bnc#925705).

  - xhci: Allocate correct amount of scratchpad buffers
    (bnc#933721).

  - xhci: Do not enable/disable RWE on bus suspend/resume
    (bnc#933721).

  - xhci: Solve full event ring by increasing
    TRBS_PER_SEGMENT to 256 (bnc#933721).

  - xhci: Treat not finding the event_seg on COMP_STOP the
    same as COMP_STOP_INVAL (bnc#933721).

  - xhci: Workaround for PME stuck issues in Intel xhci
    (bnc#933721).

  - xhci: do not report PLC when link is in internal resume
    state (bnc#933721).

  - xhci: fix reporting of 0-sized URBs in control endpoint
    (bnc#933721).

  - xhci: report U3 when link is in resume state
    (bnc#933721).

  - xhci: rework cycle bit checking for new dequeue pointers
    (bnc#933721).

  - zcrypt: Fixed reset and interrupt handling of AP queues
    (bnc#936921, bnc#936925, LTC#126491).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/777565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/867362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/873385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/883380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/884333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/886785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/891116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/894936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/923002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/923245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/923431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9728.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9729.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9730.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9731.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0777.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2150.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4167.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4700.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5364.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5366.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5707.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6252.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151678-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ebdd7b0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-kernel-20150908-12114=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-kernel-20150908-12114=1

SUSE Linux Enterprise Server 11-EXTRA :

zypper in -t patch slexsp3-kernel-20150908-12114=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-kernel-20150908-12114=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-kernel-20150908-12114=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/06");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-trace-extra-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"kernel-default-man-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-source-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-syms-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-extra-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-extra-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-extra-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-extra-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-source-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-syms-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-extra-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-source-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-syms-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-trace-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-extra-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-65.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-extra-3.0.101-65.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-source");
}
