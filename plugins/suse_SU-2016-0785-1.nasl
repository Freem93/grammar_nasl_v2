#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0785-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(89993);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2013-7446", "CVE-2015-5707", "CVE-2015-8709", "CVE-2015-8767", "CVE-2015-8785", "CVE-2015-8812", "CVE-2016-0723", "CVE-2016-0774", "CVE-2016-2069", "CVE-2016-2384");
  script_osvdb_id(122968, 125710, 130525, 131735, 132475, 132811, 133409, 133625, 134512, 134538);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2016:0785-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 kernel was updated to 3.12.55 to receive
various security and bugfixes.

Features added :

  - A improved XEN blkfront module was added, which allows
    more I/O bandwidth. (FATE#320625) It is called
    xen-blkfront in PV, and xen-vbd-upstream in HVM mode.

The following security bugs were fixed :

  - CVE-2013-7446: Use-after-free vulnerability in
    net/unix/af_unix.c in the Linux kernel allowed local
    users to bypass intended AF_UNIX socket permissions or
    cause a denial of service (panic) via crafted epoll_ctl
    calls (bnc#955654).

  - CVE-2015-5707: Integer overflow in the sg_start_req
    function in drivers/scsi/sg.c in the Linux kernel
    allowed local users to cause a denial of service or
    possibly have unspecified other impact via a large
    iov_count value in a write request (bnc#940338).

  - CVE-2015-8709: kernel/ptrace.c in the Linux kernel
    mishandled uid and gid mappings, which allowed local
    users to gain privileges by establishing a user
    namespace, waiting for a root process to enter that
    namespace with an unsafe uid or gid, and then using the
    ptrace system call. NOTE: the vendor states 'there is no
    kernel bug here' (bnc#959709 bnc#960561).

  - CVE-2015-8767: net/sctp/sm_sideeffect.c in the Linux
    kernel did not properly manage the relationship between
    a lock and a socket, which allowed local users to cause
    a denial of service (deadlock) via a crafted sctp_accept
    call (bnc#961509).

  - CVE-2015-8785: The fuse_fill_write_pages function in
    fs/fuse/file.c in the Linux kernel allowed local users
    to cause a denial of service (infinite loop) via a
    writev system call that triggers a zero length for the
    first segment of an iov (bnc#963765).

  - CVE-2015-8812: A use-after-free flaw was found in the
    CXGB3 kernel driver when the network was considered to
    be congested. This could be used by local attackers to
    cause machine crashes or potentially code executuon
    (bsc#966437).

  - CVE-2016-0723: Race condition in the tty_ioctl function
    in drivers/tty/tty_io.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory or cause a denial of service (use-after-free and
    system crash) by making a TIOCGETD ioctl call during
    processing of a TIOCSETD ioctl call (bnc#961500).

  - CVE-2016-0774: A pipe buffer state corruption after
    unsuccessful atomic read from pipe was fixed
    (bsc#964730).

  - CVE-2016-2069: Race conditions in TLB syncing was fixed
    which could leak to information leaks (bnc#963767).

  - CVE-2016-2384: A double-free triggered by invalid USB
    descriptor in ALSA usb-audio was fixed, which could be
    exploited by physical local attackers to crash the
    kernel or gain code execution (bnc#966693).

The following non-security bugs were fixed :

  - alsa: rawmidi: Make snd_rawmidi_transmit() race-free
    (bsc#968018).

  - alsa: seq: Fix leak of pool buffer at concurrent writes
    (bsc#968018).

  - be2net: fix some log messages (bnc#855062 FATE#315961,
    bnc#867583).

  - block: xen-blkfront: Fix possible NULL ptr dereference
    (bsc#957986 fate#320625).

  - btrfs: Add handler for invalidate page (bsc#963193).

  - btrfs: check prepare_uptodate_page() error code earlier
    (bnc#966910).

  - btrfs: delayed_ref: Add new function to record reserved
    space into delayed ref (bsc#963193).

  - btrfs: delayed_ref: release and free qgroup reserved at
    proper timing (bsc#963193).

  - btrfs: extent_io: Introduce needed structure for
    recoding set/clear bits (bsc#963193).

  - btrfs: extent_io: Introduce new function
    clear_record_extent_bits() (bsc#963193).

  - btrfs: extent_io: Introduce new function
    set_record_extent_bits (bsc#963193).

  - btrfs: extent-tree: Add new version of
    btrfs_check_data_free_space and
    btrfs_free_reserved_data_space (bsc#963193).

  - btrfs: extent-tree: Add new version of
    btrfs_delalloc_reserve/release_space (bsc#963193).

  - btrfs: extent-tree: Switch to new check_data_free_space
    and free_reserved_data_space (bsc#963193).

  - btrfs: extent-tree: Switch to new delalloc space reserve
    and release (bsc#963193).

  - btrfs: fallocate: Add support to accurate qgroup reserve
    (bsc#963193).

  - btrfs: fix deadlock between direct IO write and
    defrag/readpages (bnc#965344).

  - btrfs: fix invalid page accesses in extent_same (dedup)
    ioctl (bnc#968230).

  - btrfs: fix page reading in extent_same ioctl leading to
    csum errors (bnc#968230).

  - btrfs: fix warning in backref walking (bnc#966278).

  - btrfs: qgroup: Add handler for NOCOW and inline
    (bsc#963193).

  - btrfs: qgroup: Add new trace point for qgroup data
    reserve (bsc#963193).

  - btrfs: qgroup: Avoid calling
    btrfs_free_reserved_data_space in clear_bit_hook
    (bsc#963193).

  - btrfs: qgroup: Check if qgroup reserved space leaked
    (bsc#963193).

  - btrfs: qgroup: Cleanup old inaccurate facilities
    (bsc#963193).

  - btrfs: qgroup: Fix a race in delayed_ref which leads to
    abort trans (bsc#963193).

  - btrfs: qgroup: Fix a rebase bug which will cause qgroup
    double free (bsc#963193).

  - btrfs: qgroup: Introduce btrfs_qgroup_reserve_data
    function (bsc#963193).

  - btrfs: qgroup: Introduce functions to release/free
    qgroup reserve data space (bsc#963193).

  - btrfs: qgroup: Introduce new functions to reserve/free
    metadata (bsc#963193).

  - btrfs: qgroup: Use new metadata reservation
    (bsc#963193).

  - btrfs: skip locking when searching commit root
    (bnc#963825).

  - dcache: use IS_ROOT to decide where dentry is hashed
    (bsc#949752).

  - documentation: Document kernel.panic_on_io_nmi sysctl
    (bsc#940946, bsc#937444).

  - documentation: Fix build of PDF files in kernel-docs
    package Double the spaces for tex, and fix buildrequires
    for docbook.

  - doc: Use fop for creating PDF files in kernel-docs
    package as some files still cannot be built with the
    default backend.

  - driver core: Add BUS_NOTIFY_REMOVED_DEVICE event
    (bnc#962965).

  - drivers: xen-blkfront: only talk_to_blkback() when in
    XenbusStateInitialising (bsc#957986 fate#320625).

  - driver: xen-blkfront: move talk_to_blkback to a more
    suitable place (bsc#957986 fate#320625).

  - ec2: updated kabi files and start tracking

  - fs: Improve fairness when locking the per-superblock
    s_anon list (bsc#957525, bsc#941363).

  - fs/proc_namespace.c: simplify testing nsp and
    nsp->mnt_ns (bug#963960).

  - fuse: break infinite loop in fuse_fill_write_pages()
    (bsc#963765).

  - futex: Drop refcount if requeue_pi() acquired the
    rtmutex (bug#960174).

  - jbd2: Fix unreclaimed pages after truncate in
    data=journal mode (bsc#961516).

  - kabi: Preserve checksum of kvm_x86_ops (bsc#969112).

  - kABI: protect struct af_alg_type.

  - kABI: protect struct crypto_ahash.

  - kABI: reintroduce blk_rq_check_limits.

  - kabi/severities: Fail on changes in kvm_x86_ops, needed
    by lttng-modules

  - kernel: Change ASSIGN_ONCE(val, x) to WRITE_ONCE(x, val)
    (bsc#940946, bsc#937444).

  - kernel: Provide READ_ONCE and ASSIGN_ONCE (bsc#940946,
    bsc#937444).

  - kernel/watchdog.c: perform all-CPU backtrace in case of
    hard lockup (bsc#940946, bsc#937444).

  - kexec: Fix race between panic() and crash_kexec()
    (bsc#940946, bsc#937444).

  - kgr: do not print error for !abort_if_missing symbols
    (bnc#943989).

  - kgr: do not use WQ_MEM_RECLAIM workqueue (bnc#963572).

  - kgr: log when modifying kernel (fate#317827).

  - kgr: mark some more missed kthreads (bnc#962336).

  - kgr: usb/storage: do not emit thread awakened
    (bnc#899908).

  - kvm: x86: Check dest_map->vector to match eoi signals
    for rtc (bsc#966471).

  - kvm: x86: Convert ioapic->rtc_status.dest_map to a
    struct (bsc#966471).

  - kvm: x86: store IOAPIC-handled vectors in each VCPU
    (bsc#966471).

  - kvm: x86: Track irq vectors in
    ioapic->rtc_status.dest_map (bsc#966471).

  - libceph: fix scatterlist last_piece calculation
    (bsc#963746).

  - megaraid_sas: Chip reset if driver fails to get IOC
    ready (bsc#922071). Refresh the patch based on the
    actual upstream commit, and add the commit ID.

  - mm/memory_hotplug.c: check for missing sections in
    test_pages_in_a_zone() (VM Functionality, bnc#961588).

  - module: keep percpu symbols in module's symtab
    (bsc#962788).

  - namespaces: Re-introduce task_nsproxy() helper
    (bug#963960).

  - namespaces: Use task_lock and not rcu to protect nsproxy
    (bug#963960).

  - net: core: Correct an over-stringent device loop
    detection (bsc#945219).

  - nfs: Background flush should not be low priority
    (bsc#955308).

  - nfsd: Do not start lockd when only NFSv4 is running
    (fate#316311).

  - nfs: do not use STABLE writes during writeback
    (bnc#816099).

  - nfs: Fix handling of re-write-before-commit for mmapped
    NFS pages (bsc#964201).

  - nfs: Move nfsd patch to the right section

  - nfsv4: Recovery of recalled read delegations is broken
    (bsc#956514).

  - nmi: provide the option to issue an NMI back trace to
    every cpu but current (bsc#940946, bsc#937444).

  - nmi: provide the option to issue an NMI back trace to
    every cpu but current (bsc#940946, bsc#937444).

  - panic, x86: Allow CPUs to save registers even if looping
    in NMI context (bsc#940946, bsc#937444).

  - panic, x86: Fix re-entrance problem due to panic on NMI
    (bsc#940946, bsc#937444).

  - pci: allow access to VPD attributes with size 0
    (bsc#959146).

  - pciback: Check PF instead of VF for PCI_COMMAND_MEMORY.

  - pciback: Save the number of MSI-X entries to be copied
    later.

  - pci: Blacklist vpd access for buggy devices
    (bsc#959146).

  - pci: Determine actual VPD size on first access
    (bsc#959146).

  - pci: Update VPD definitions (bsc#959146).

  - perf: Do not modify perf bias performance setting by
    default at boot (bnc#812259,bsc#959629).

  - proc: Fix ptrace-based permission checks for accessing
    task maps.

  - rpm/constraints.in: Bump disk space requirements up a
    bit Require 10GB on s390x, 20GB elsewhere.

  - rpm/kernel-binary.spec.in: Fix build if no UEFI certs
    are installed

  - rpm/kernel-binary.spec.in: Fix kernel-vanilla-devel
    dependency (bsc#959090)

  - rpm/kernel-binary.spec.in: Fix paths in
    kernel-vanilla-devel (bsc#959090).

  - rpm/kernel-binary.spec.in: Install libopenssl-devel for
    newer sign-file

  - rpm/kernel-binary.spec.in: Sync the main and -base
    package dependencies (bsc#965830#c51).

  - rpm/kernel-binary.spec.in: Use bzip compression to speed
    up build (bsc#962356)

  - rpm/kernel-module-subpackage: Fix obsoleting dropped
    flavors (bsc#968253)

  - rpm/kernel-source.spec.in: Install kernel-macros for
    kernel-source-vanilla (bsc#959090)

  - rpm/kernel-spec-macros: Do not modify the release string
    in PTFs (bsc#963449)

  - rpm/package-descriptions: Add kernel-zfcpdump and drop
    -desktop

  - sched/fair: Disable tg load_avg/runnable_avg update for
    root_task_group (bnc#960227).

  - sched/fair: Move cache hot load_avg/runnable_avg into
    separate cacheline (bnc#960227).

  - sched: Fix race between task_group and sched_task_group
    (Automatic NUMA Balancing (fate#315482))

  - scsi: Add sd_mod to initrd modules For some reason
    PowerVM backend can't work without sd_mod

  - scsi_dh_alua: Do not block request queue if workqueue is
    active (bsc#960458).

  - scsi: fix soft lockup in scsi_remove_target() on module
    removal (bsc#965199).

  - scsi: restart list search after unlock in
    scsi_remove_target (bsc#959257).

  - series.conf: add section comments

  - supported.conf: Add e1000e (emulated by VMware) to -base
    (bsc#968074)

  - supported.conf: Add Hyper-V modules to -base
    (bsc#965830)

  - supported.conf: Add more QEMU and VMware drivers to
    -base (bsc#965840).

  - supported.conf: Add more qemu device driver (bsc#968234)

  - supported.conf: Add mptspi and mptsas to -base
    (bsc#968206)

  - supported.conf: Add netfilter modules to base
    (bsc#950292)

  - supported.conf: Add nls_iso8859-1 and nls_cp437 to -base
    (bsc#950292)

  - supported.conf: Add the qemu scsi driver (sym53c8xx) to
    -base (bsc#967802)

  - supported.conf: Add tulip to -base for Hyper-V
    (bsc#968234)

  - supported.conf: Add vfat to -base to be able to mount
    the ESP (bsc#950292).

  - supported.conf: Add virtio_{blk,net,scsi} to
    kernel-default-base (bsc#950292)

  - supported.conf: Add virtio-rng (bsc#966026)

  - supported.conf: Add xen-blkfront.

  - supported.conf: Add xfs to -base (bsc#965891)

  - supported.conf: Also add virtio_pci to
    kernel-default-base (bsc#950292).

  - supported.conf: drop +external from ghash-clmulni-intel
    It was agreed that it does not make sense to maintain
    'external' for this specific module. Furthermore it
    causes problems in rather ordinary VMware environments.
    (bsc#961971)

  - supported.conf: Fix usb-common path usb-common moved to
    its own subdirectory in kernel v3.16, and we backported
    that change to SLE12.

  - tcp: Restore RFC5961-compliant behavior for SYN packets
    (bsc#966864).

  - usb: Quiet down false peer failure messages
    (bnc#960629).

  - x86/apic: Introduce apic_extnmi command line parameter
    (bsc#940946, bsc#937444).

  - x86/nmi: Save regs in crash dump on external NMI
    (bsc#940946, bsc#937444).

  - x86/nmi: Save regs in crash dump on external NMI
    (bsc#940946, bsc#937444).

  - xen: Add /etc/modprobe.d/50-xen.conf selecting Xen
    frontend driver implementation (bsc#957986, bsc#956084,
    bsc#961658).

  - xen-blkfront: allow building in our Xen environment
    (bsc#957986 fate#320625).

  - xen, blkfront: factor out flush-related checks from
    do_blkif_request() (bsc#957986 fate#320625).

  - xen-blkfront: fix accounting of reqs when migrating
    (bsc#957986 fate#320625).

  - xen/blkfront: Fix crash if backend does not follow the
    right states (bsc#957986 fate#320625).

  - xen-blkfront: improve aproximation of required grants
    per request (bsc#957986 fate#320625).

  - xen/blkfront: improve protection against issuing
    unsupported REQ_FUA (bsc#957986 fate#320625).

  - xen/blkfront: remove redundant flush_op (bsc#957986
    fate#320625).

  - xen-blkfront: remove type check from
    blkfront_setup_discard (bsc#957986 fate#320625).

  - xen-blkfront: Silence pfn maybe-uninitialized warning
    (bsc#957986 fate#320625).

  - xen: Linux 3.12.52.

  - xen: Refresh patches.xen/xen3-patch-3.9 (bsc#951155).

  - xen: Refresh patches.xen/xen3-patch-3.9 (do not subvert
    NX protection during 1:1 mapping setup).

  - xen-vscsi-large-requests: Fix resource collision for
    racing request maps and unmaps (bsc#966094).

  - xen: Xen config files updated to enable upstream block
    frontend.

  - xfs: add a few more verifier tests (bsc#947953).

  - xfs: fix double free in xlog_recover_commit_trans
    (bsc#947953).

  - xfs: recovery of XLOG_UNMOUNT_TRANS leaks memory
    (bsc#947953).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/812259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/816099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/855062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/867583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/884701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/899908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-7446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5707.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8709.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8785.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8812.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0723.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2069.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2384.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160785-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c2dbd69"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2016-460=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-460=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-460=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2016-460=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2016-460=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-460=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/17");
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
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-devel-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-syms-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.55-52.42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.55-52.42.1")) flag++;


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
