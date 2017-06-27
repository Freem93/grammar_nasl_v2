#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0585-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(89022);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2013-7446", "CVE-2015-0272", "CVE-2015-5707", "CVE-2015-7550", "CVE-2015-7799", "CVE-2015-8215", "CVE-2015-8539", "CVE-2015-8543", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8660", "CVE-2015-8767", "CVE-2015-8785", "CVE-2016-0723", "CVE-2016-2069");
  script_osvdb_id(125710, 127518, 128845, 130525, 131666, 131683, 131685, 131735, 131951, 131952, 132029, 132030, 132260, 132811, 133409, 133625);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2016:0585-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.53 to
receive various security and bugfixes.

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

  - CVE-2015-7550: The keyctl_read_key function in
    security/keys/keyctl.c in the Linux kernel did not
    properly use a semaphore, which allowed local users to
    cause a denial of service (NULL pointer dereference and
    system crash) or possibly have unspecified other impact
    via a crafted application that leverages a race
    condition between keyctl_revoke and keyctl_read calls
    (bnc#958951).

  - CVE-2015-7799: The slhc_init function in
    drivers/net/slip/slhc.c in the Linux kernel did not
    ensure that certain slot numbers are valid, which
    allowed local users to cause a denial of service (NULL
    pointer dereference and system crash) via a crafted
    PPPIOCSMAXCID ioctl call (bnc#949936).

  - CVE-2015-8215: net/ipv6/addrconf.c in the IPv6 stack in
    the Linux kernel did not validate attempted changes to
    the MTU value, which allowed context-dependent attackers
    to cause a denial of service (packet loss) via a value
    that was (1) smaller than the minimum compliant value or
    (2) larger than the MTU of an interface, as demonstrated
    by a Router Advertisement (RA) message that is not
    validated by a daemon, a different vulnerability than
    CVE-2015-0272 (bnc#955354).

  - CVE-2015-8539: The KEYS subsystem in the Linux kernel
    allowed local users to gain privileges or cause a denial
    of service (BUG) via crafted keyctl commands that
    negatively instantiate a key, related to
    security/keys/encrypted-keys/encrypted.c,
    security/keys/trusted.c, and
    security/keys/user_defined.c (bnc#958463).

  - CVE-2015-8543: The networking implementation in the
    Linux kernel did not validate protocol identifiers for
    certain protocol families, which allowed local users to
    cause a denial of service (NULL function pointer
    dereference and system crash) or possibly gain
    privileges by leveraging CLONE_NEWUSER support to
    execute a crafted SOCK_RAW application (bnc#958886).

  - CVE-2015-8550: Optimizations introduced by the compiler
    could have lead to double fetch vulnerabilities,
    potentially possibly leading to arbitrary code execution
    in backend (bsc#957988).

  - CVE-2015-8551: Xen PCI backend driver did not perform
    proper sanity checks on the device's state, allowing for
    DoS (bsc#957990).

  - CVE-2015-8569: The (1) pptp_bind and (2) pptp_connect
    functions in drivers/net/ppp/pptp.c in the Linux kernel
    did not verify an address length, which allowed local
    users to obtain sensitive information from kernel memory
    and bypass the KASLR protection mechanism via a crafted
    application (bnc#959190).

  - CVE-2015-8575: The sco_sock_bind function in
    net/bluetooth/sco.c in the Linux kernel did not verify
    an address length, which allowed local users to obtain
    sensitive information from kernel memory and bypass the
    KASLR protection mechanism via a crafted application
    (bnc#959399).

  - CVE-2015-8660: The ovl_setattr function in
    fs/overlayfs/inode.c in the Linux kernel attempted to
    merge distinct setattr operations, which allowed local
    users to bypass intended access restrictions and modify
    the attributes of arbitrary overlay files via a crafted
    application (bnc#960281).

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

  - CVE-2016-0723: Race condition in the tty_ioctl function
    in drivers/tty/tty_io.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory or cause a denial of service (use-after-free and
    system crash) by making a TIOCGETD ioctl call during
    processing of a TIOCSETD ioctl call (bnc#961500).

  - CVE-2016-2069: A race in invalidating paging structures
    that were not in use locally could have lead to
    disclosoure of information or arbitrary code exectution
    (bnc#963767).

The following non-security bugs were fixed :

  - ACPI: Introduce apic_id in struct processor to save
    parsed APIC id (bsc#959463).

  - ACPI: Make it possible to get local x2apic id via _MAT
    (bsc#959463).

  - ACPI: use apic_id and remove duplicated _MAT evaluation
    (bsc#959463).

  - ACPICA: Correctly cleanup after a ACPI table load
    failure (bnc#937261).

  - Add sd_mod to initrd modules. For some reason PowerVM
    backend can't work without sd_mod

  - Do not modify perf bias performance setting by default
    at boot (bnc#812259, bsc#959629).

  - Documentation: Document kernel.panic_on_io_nmi sysctl
    (bsc#940946, bsc#937444).

  - Driver for IBM System i/p VNIC protocol

  - Drop blktap patches from SLE12, since the driver is
    unsupported

  - Improve fairness when locking the per-superblock s_anon
    list (bsc#957525, bsc#941363).

  - Input: aiptek - fix crash on detecting device without
    endpoints (bnc#956708).

  - NFSD: Do not start lockd when only NFSv4 is running

  - NFSv4: Recovery of recalled read delegations is broken
    (bsc#956514).

  - Replace with 176bed1d vmstat: explicitly schedule
    per-cpu work on the CPU we need it to run on

  - Revert 'ipv6: add complete rcu protection around
    np->opt' (bnc#961257).

  - Revert 874bbfe60 workqueue: make sure delayed work run
    in local cpu 1. Without 22b886dd, 874bbfe60 leads to
    timer corruption. 2. With 22b886dd applied, victim of 1
    reports performance regression (1,2
    https://lkml.org/lkml/2016/2/4/618) 3. Leads to
    scheduling work to offlined CPU (bnc#959463). SLERT: 4.
    NO_HZ_FULL regressession, unbound delayed work timer is
    no longer deflected to a housekeeper CPU.

  - be2net: fix some log messages (bnc#855062, bnc#867583).

  - blktap: also call blkif_disconnect() when frontend
    switched to closed (bsc#952976).

  - blktap: refine mm tracking (bsc#952976).

  - block: Always check queue limits for cloned requests
    (bsc#902606).

  - block: Always check queue limits for cloned requests
    (bsc#902606).

  - bnx2x: Add new device ids under the Qlogic vendor
    (bnc#964821).

  - btrfs: Add qgroup tracing (bnc#935087, bnc#945649).

  - btrfs: Update btrfs qgroup status item when rescan is
    done (bnc#960300).

  - btrfs: backref: Add special time_seq == (u64)-1 case for
    btrfs_find_all_roots() (bnc#935087, bnc#945649).

  - btrfs: backref: Do not merge refs which are not for same
    block (bnc#935087, bnc#945649).

  - btrfs: delayed-ref: Cleanup the unneeded functions
    (bnc#935087, bnc#945649).

  - btrfs: delayed-ref: Use list to replace the ref_root in
    ref_head (bnc#935087, bnc#945649).

  - btrfs: extent-tree: Use ref_node to replace unneeded
    parameters in __inc_extent_ref() and __free_extent()
    (bnc#935087, bnc#945649).

  - btrfs: fix comp_oper to get right order (bnc#935087,
    bnc#945649).

  - btrfs: fix deadlock between direct IO write and
    defrag/readpages (bnc#965344).

  - btrfs: fix leak in qgroup_subtree_accounting() error
    path (bnc#935087, bnc#945649).

  - btrfs: fix order by which delayed references are run
    (bnc#949440).

  - btrfs: fix qgroup sanity tests (bnc#951615).

  - btrfs: fix race waiting for qgroup rescan worker
    (bnc#960300).

  - btrfs: fix regression running delayed references when
    using qgroups (bnc#951615).

  - btrfs: fix regression when running delayed references
    (bnc#951615).

  - btrfs: fix sleeping inside atomic context in qgroup
    rescan worker (bnc#960300).

  - btrfs: keep dropped roots in cache until transaction
    commit (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add function qgroup_update_counters()
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add function qgroup_update_refcnt()
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add new function to record old_roots
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add new qgroup calculation function
    btrfs_qgroup_account_extents() (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add the ability to skip given qgroup for
    old/new_roots (bnc#935087, bnc#945649).

  - btrfs: qgroup: Cleanup open-coded old/new_refcnt update
    and read (bnc#935087, bnc#945649).

  - btrfs: qgroup: Cleanup the old ref_node-oriented
    mechanism (bnc#935087, bnc#945649).

  - btrfs: qgroup: Do not copy extent buffer to do qgroup
    rescan (bnc#960300).

  - btrfs: qgroup: Fix a regression in qgroup reserved space
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Make snapshot accounting work with new
    extent-oriented qgroup (bnc#935087, bnc#945649).

  - btrfs: qgroup: Record possible quota-related extent for
    qgroup (bnc#935087, bnc#945649).

  - btrfs: qgroup: Switch rescan to new mechanism
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Switch self test to extent-oriented
    qgroup mechanism (bnc#935087, bnc#945649).

  - btrfs: qgroup: Switch to new extent-oriented qgroup
    mechanism (bnc#935087, bnc#945649).

  - btrfs: qgroup: account shared subtree during snapshot
    delete (bnc#935087, bnc#945649).

  - btrfs: qgroup: clear STATUS_FLAG_ON in disabling quota
    (bnc#960300).

  - btrfs: qgroup: exit the rescan worker during umount
    (bnc#960300).

  - btrfs: qgroup: fix quota disable during rescan
    (bnc#960300).

  - btrfs: qgroup: move WARN_ON() to the correct location
    (bnc#935087, bnc#945649).

  - btrfs: remove transaction from send (bnc#935087,
    bnc#945649).

  - btrfs: skip locking when searching commit root
    (bnc#963825).

  - btrfs: ulist: Add ulist_del() function (bnc#935087,
    bnc#945649).

  - btrfs: use btrfs_get_fs_root in resolve_indirect_ref
    (bnc#935087, bnc#945649).

  - crypto: nx - use common code for both NX decompress
    success cases (bsc#942476).

  - crypto: nx-842 - Mask XERS0 bit in return value
    (bsc#960221).

  - driver core: Add BUS_NOTIFY_REMOVED_DEVICE event
    (bnc#962965).

  - drivers/firmware/memmap.c: do not allocate
    firmware_map_entry of same memory range (bsc#959463).

  - drivers/firmware/memmap.c: do not create memmap sysfs of
    same firmware_map_entry (bsc#959463).

  - drivers/firmware/memmap.c: pass the correct argument to
    firmware_map_find_entry_bootmem() (bsc#959463).

  - e1000e: Do not read ICR in Other interrupt (bsc#924919).

  - e1000e: Do not write lsc to ics in msi-x mode
    (bsc#924919).

  - e1000e: Fix msi-x interrupt automask (bsc#924919).

  - e1000e: Remove unreachable code (bsc#924919).

  - fuse: break infinite loop in fuse_fill_write_pages()
    (bsc#963765).

  - group-source-files: mark module.lds as devel file ld:
    cannot open linker script file
    /usr/src/linux-4.2.5-1/arch/arm/kernel/module.lds: No
    such file or directory

  - ipv6: fix tunnel error handling (bsc#952579).

  - jbd2: Fix unreclaimed pages after truncate in
    data=journal mode (bsc#961516).

  - kABI: reintroduce blk_rq_check_limits.

  - kabi: protect struct acpi_processor signature
    (bsc#959463).

  - kernel/watchdog.c: perform all-CPU backtrace in case of
    hard lockup (bsc#940946, bsc#937444).

  - kernel: Change ASSIGN_ONCE(val, x) to WRITE_ONCE(x, val)
    (bsc#940946, bsc#937444).

  - kernel: Provide READ_ONCE and ASSIGN_ONCE (bsc#940946,
    bsc#937444).

  - kernel: inadvertent free of the vector register save
    area (bnc#961202).

  - kexec: Fix race between panic() and crash_kexec()
    (bsc#940946, bsc#937444).

  - kgr: Remove the confusing search for fentry

  - kgr: Safe way to avoid an infinite redirection

  - kgr: do not print error for !abort_if_missing symbols
    (bnc#943989).

  - kgr: do not use WQ_MEM_RECLAIM workqueue (bnc#963572).

  - kgr: log when modifying kernel

  - kgr: mark some more missed kthreads (bnc#962336).

  - kgr: usb/storage: do not emit thread awakened
    (bnc#899908).

  - kvm: Add arch specific mmu notifier for page
    invalidation (bsc#959463).

  - kvm: Make init_rmode_identity_map() return 0 on success
    (bsc#959463).

  - kvm: Remove ept_identity_pagetable from struct kvm_arch
    (bsc#959463).

  - kvm: Rename make_all_cpus_request() to
    kvm_make_all_cpus_request() and make it non-static
    (bsc#959463).

  - kvm: Use APIC_DEFAULT_PHYS_BASE macro as the apic access
    page address (bsc#959463).

  - kvm: vmx: Implement set_apic_access_page_addr
    (bsc#959463).

  - kvm: x86: Add request bit to reload APIC access page
    address (bsc#959463).

  - kvm: x86: Unpin and remove kvm_arch->apic_access_page
    (bsc#959463).

  - libiscsi: Fix host busy blocking during connection
    teardown.

  - lpfc: Fix null ndlp dereference in target_reset_handler
    (bsc#951392).

  - md/bitmap: do not pass -1 to bitmap_storage_alloc
    (bsc#955118).

  - md/bitmap: remove confusing code from filemap_get_page.

  - md/bitmap: remove rcu annotation from pointer
    arithmetic.

  - mem-hotplug: reset node managed pages when hot-adding a
    new pgdat (bsc#959463).

  - mem-hotplug: reset node present pages when hot-adding a
    new pgdat (bsc#959463).

  - memory-hotplug: clear pgdat which is allocated by
    bootmem in try_offline_node() (bsc#959463).

  - mm/memory_hotplug.c: check for missing sections in
    test_pages_in_a_zone() (VM Functionality, bnc#961588).

  - mm/mempolicy.c: convert the shared_policy lock to a
    rwlock (VM Performance, bnc#959436).

  - module: keep percpu symbols in module's symtab
    (bsc#962788).

  - nmi: provide the option to issue an NMI back trace to
    every cpu but current (bsc#940946, bsc#937444).

  - nmi: provide the option to issue an NMI back trace to
    every cpu but current (bsc#940946, bsc#937444).

  - nvme: Clear BIO_SEG_VALID flag in nvme_bio_split()
    (bsc#954992).

  - panic, x86: Allow CPUs to save registers even if looping
    in NMI context (bsc#940946, bsc#937444).

  - panic, x86: Fix re-entrance problem due to panic on NMI
    (bsc#940946, bsc#937444).

  - pci: Check for valid tags when calculating the VPD size
    (bsc#959146).

  - qeth: initialize net_device with carrier off
    (bnc#964230).

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

  - rpm/kernel-binary.spec.in: Use bzip compression to speed
    up build (bsc#962356)

  - rpm/kernel-source.spec.in: Install kernel-macros for
    kernel-source-vanilla (bsc#959090)

  - rpm/kernel-spec-macros: Do not modify the release string
    in PTFs (bsc#963449)

  - rpm/package-descriptions: Add kernel-zfcpdump and drop
    -desktop

  - s390/cio: ensure consistent measurement state
    (bnc#964230).

  - s390/cio: fix measurement characteristics memleak
    (bnc#964230).

  - s390/cio: update measurement characteristics
    (bnc#964230).

  - s390/dasd: fix failfast for disconnected devices
    (bnc#961202).

  - s390/vtime: correct scaled cputime for SMT (bnc#964230).

  - s390/vtime: correct scaled cputime of partially idle
    CPUs (bnc#964230).

  - s390/vtime: limit MT scaling value updates (bnc#964230).

  - sched,numa: cap pte scanning overhead to 3% of run time
    (Automatic NUMA Balancing).

  - sched/fair: Care divide error in
    update_task_scan_period() (bsc#959463).

  - sched/fair: Disable tg load_avg/runnable_avg update for
    root_task_group (bnc#960227).

  - sched/fair: Move cache hot load_avg/runnable_avg into
    separate cacheline (bnc#960227).

  - sched/numa: Cap PTE scanning overhead to 3% of run time
    (Automatic NUMA Balancing).

  - sched: Fix race between task_group and sched_task_group
    (Automatic NUMA Balancing).

  - scsi: restart list search after unlock in
    scsi_remove_target (bsc#944749, bsc#959257).

  - supported.conf: Add more QEMU and VMware drivers to
    -base (bsc#965840).

  - supported.conf: Add netfilter modules to base
    (bsc#950292)

  - supported.conf: Add nls_iso8859-1 and nls_cp437 to -base
    (bsc#950292)

  - supported.conf: Add vfat to -base to be able to mount
    the ESP (bsc#950292).

  - supported.conf: Add virtio_{blk,net,scsi} to
    kernel-default-base (bsc#950292)

  - supported.conf: Also add virtio_pci to
    kernel-default-base (bsc#950292).

  - supported.conf: drop +external from ghash-clmulni-intel
    It was agreed that it does not make sense to maintain
    'external' for this specific module. Furthermore it
    causes problems in rather ordinary VMware environments.
    (bsc#961971)

  - udp: properly support MSG_PEEK with truncated buffers
    (bsc#951199 bsc#959364).

  - x86, xsave: Support eager-only xsave features, add MPX
    support (bsc#938577).

  - x86/apic: Introduce apic_extnmi command line parameter
    (bsc#940946, bsc#937444).

  - x86/fpu/xstate: Do not assume the first zero xfeatures
    zero bit means the end (bsc#938577).

  - x86/fpu: Fix double-increment in setup_xstate_features()
    (bsc#938577).

  - x86/fpu: Remove xsave_init() bootmem allocations
    (bsc#938577).

  - x86/nmi: Save regs in crash dump on external NMI
    (bsc#940946, bsc#937444).

  - x86/nmi: Save regs in crash dump on external NMI
    (bsc#940946, bsc#937444).

  - xen/pciback: Do not allow MSI-X ops if
    PCI_COMMAND_MEMORY is not set (bsc#957990 XSA-157).

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
    value:"https://bugzilla.suse.com/855062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/867583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/899908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938577"
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
    value:"https://bugzilla.suse.com/942476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958951"
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
    value:"https://bugzilla.suse.com/959190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959436"
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
    value:"https://bugzilla.suse.com/960221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961202"
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
    value:"https://bugzilla.suse.com/963449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963572"
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
    value:"https://bugzilla.suse.com/964230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lkml.org/lkml/2016/2/4/618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-7446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0272.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5707.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7799.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8215.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8539.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8543.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8551.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8660.html"
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
    value:"https://www.suse.com/security/cve/CVE-2016-0723.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2069.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160585-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f6304bd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1 :

zypper in -t patch SUSE-SLE-WE-12-SP1-2016-329=1

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-329=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-329=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2016-329=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2016-329=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-329=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Overlayfs Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"lttng-modules-2.7.0-3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"lttng-modules-debugsource-2.7.0-3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"lttng-modules-kmp-default-2.7.0_k3.12.53_60.30-3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"lttng-modules-kmp-default-debuginfo-2.7.0_k3.12.53_60.30-3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"kernel-default-man-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-debuginfo-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debuginfo-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debugsource-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-devel-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-syms-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-devel-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-syms-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.53-60.30.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.53-60.30.1")) flag++;


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
