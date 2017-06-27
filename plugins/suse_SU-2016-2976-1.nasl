#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2976-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(95536);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/27 20:33:26 $");

  script_cve_id("CVE-2013-4312", "CVE-2015-7513", "CVE-2015-8956", "CVE-2016-0823", "CVE-2016-3841", "CVE-2016-4998", "CVE-2016-5696", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-7117", "CVE-2016-7425");
  script_osvdb_id(132618, 133379, 135484, 140494, 141441, 142466, 142610, 142992, 143514, 144411, 145048, 145102, 145585);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2016:2976-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various
security and bugfixes. For the PowerPC64 a new 'bigmem' flavor has
been added to support big Power machines. (FATE#319026) The following
security bugs were fixed :

  - CVE-2016-7042: The proc_keys_show function in
    security/keys/proc.c in the Linux kernel, when the GNU
    Compiler Collection (gcc) stack protector is enabled,
    uses an incorrect buffer size for certain timeout data,
    which allowed local users to cause a denial of service
    (stack memory corruption and panic) by reading the
    /proc/keys file (bnc#1004517).

  - CVE-2016-7097: The filesystem implementation in the
    Linux kernel preserves the setgid bit during a setxattr
    call, which allowed local users to gain group privileges
    by leveraging the existence of a setgid program with
    restrictions on execute permissions (bnc#995968).

  - CVE-2015-8956: The rfcomm_sock_bind function in
    net/bluetooth/rfcomm/sock.c in the Linux kernel allowed
    local users to obtain sensitive information or cause a
    denial of service (NULL pointer dereference) via vectors
    involving a bind system call on a Bluetooth RFCOMM
    socket (bnc#1003925).

  - CVE-2016-7117: Use-after-free vulnerability in the
    __sys_recvmmsg function in net/socket.c in the Linux
    kernel allowed remote attackers to execute arbitrary
    code via vectors involving a recvmmsg system call that
    is mishandled during error processing (bnc#1003077).

  - CVE-2016-0823: The pagemap_open function in
    fs/proc/task_mmu.c in the Linux kernel allowed local
    users to obtain sensitive physical-address information
    by reading a pagemap file, aka Android internal bug
    25739721 (bnc#994759).

  - CVE-2016-7425: The arcmsr_iop_message_xfer function in
    drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did
    not restrict a certain length field, which allowed local
    users to gain privileges or cause a denial of service
    (heap-based buffer overflow) via an
    ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).

  - CVE-2016-3841: The IPv6 stack in the Linux kernel
    mishandled options data, which allowed local users to
    gain privileges or cause a denial of service
    (use-after-free and system crash) via a crafted sendmsg
    system call (bnc#992566).

  - CVE-2016-6828: The tcp_check_send_head function in
    include/net/tcp.h in the Linux kernel did not properly
    maintain certain SACK state after a failed data copy,
    which allowed local users to cause a denial of service
    (tcp_xmit_retransmit_queue use-after-free and system
    crash) via a crafted SACK option (bnc#994296).

  - CVE-2016-5696: net/ipv4/tcp_input.c in the Linux kernel
    did not properly determine the rate of challenge ACK
    segments, which made it easier for remote attackers to
    hijack TCP sessions via a blind in-window attack
    (bnc#989152).

  - CVE-2016-6480: Race condition in the ioctl_send_fib
    function in drivers/scsi/aacraid/commctrl.c in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds access or system crash) by changing a
    certain size value, aka a 'double fetch' vulnerability
    (bnc#991608).

  - CVE-2016-4998: The IPT_SO_SET_REPLACE setsockopt
    implementation in the netfilter subsystem in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds read) or possibly obtain sensitive
    information from kernel heap memory by leveraging
    in-container root access to provide a crafted offset
    value that leads to crossing a ruleset blob boundary
    (bnc#986365).

  - CVE-2015-7513: arch/x86/kvm/x86.c in the Linux kernel
    did not reset the PIT counter values during state
    restoration, which allowed guest OS users to cause a
    denial of service (divide-by-zero error and host OS
    crash) via a zero value, related to the
    kvm_vm_ioctl_set_pit and kvm_vm_ioctl_set_pit2 functions
    (bnc#960689).

  - CVE-2013-4312: The Linux kernel allowed local users to
    bypass file-descriptor limits and cause a denial of
    service (memory consumption) by sending each descriptor
    over a UNIX socket before closing it, related to
    net/unix/af_unix.c and net/unix/garbage.c (bnc#839104
    bsc#922947 bsc#968014). The following non-security bugs
    were fixed :

  - ahci: Order SATA device IDs for codename Lewisburg
    (fate#319286).

  - ahci: Remove obsolete Intel Lewisburg SATA RAID device
    IDs (fate#319286).

  - alsa: hda - Add Intel Lewisburg device IDs Audio
    (fate#319286).

  - arch/powerpc: Remove duplicate/redundant Altivec entries
    (bsc#967716).

  - avoid dentry crash triggered by NFS (bsc#984194).

  - bigmem: Add switch to configure bigmem patches
    (bsc#928138,fate#319026).

  - blktap2: eliminate deadlock potential from shutdown path
    (bsc#909994).

  - blktap2: eliminate race from deferred work queue
    handling (bsc#911687).

  - bnx2x: fix lockdep splat (bsc#908684 FATE#317539).

  - bonding: always set recv_probe to bond_arp_rcv in arp
    monitor (bsc#977687).

  - bonding: fix bond_arp_rcv setting and arp validate
    desync state (bsc#977687).

  - btrfs: account for non-CoW'd blocks in
    btrfs_abort_transaction (bsc#983619).

  - btrfs: ensure that file descriptor used with subvol
    ioctls is a dir (bsc#999600).

  - cdc-acm: added sanity checking for probe() (bsc#993891).

  - config.conf: add bigmem flavour on ppc64

  - cpumask, nodemask: implement cpumask/nodemask_pr_args()
    (bnc1003866).

  - cxgb4: Set VPD size so we can read both VPD structures
    (bsc#976867).

  - dm space map metadata: fix sm_bootstrap_get_nr_blocks()
    (FATE#313903).

  - dm thin: fix race condition when destroying thin pool
    workqueue (FATE#313903).

  - drivers: hv: vmbus: avoid scheduling in interrupt
    context in vmbus_initiate_unload() (bnc#986337).

  - drivers: hv: vmbus: avoid wait_for_completion() on crash
    (bnc#986337).

  - drivers: hv: vmbus: do not loose HVMSG_TIMER_EXPIRED
    messages (bnc#986337).

  - drivers: hv: vmbus: do not send CHANNELMSG_UNLOAD on
    pre-Win2012R2 hosts (bnc#986337).

  - drivers: hv: vmbus: handle various crash scenarios
    (bnc#986337).

  - drivers: hv: vmbus: remove code duplication in message
    handling (bnc#986337).

  - drivers: hv: vss: run only on supported host versions
    (bnc#986337).

  - fs/cifs: cifs_get_root shouldn't use path with tree name
    (bsc#963655, bsc#979681).

  - fs/cifs: Compare prepaths when comparing superblocks
    (bsc#799133).

  - fs/cifs: Fix memory leaks in cifs_do_mount()
    (bsc#799133).

  - fs/cifs: Fix regression which breaks DFS mounting
    (bsc#799133).

  - fs/cifs: fix wrongly prefixed path to root (bsc#963655,
    bsc#979681)

  - fs/cifs: make share unaccessible at root level mountable
    (bsc#799133).

  - fs/cifs: Move check for prefix path to within
    cifs_get_root() (bsc#799133).

  - fs/select: add vmalloc fallback for select(2)
    (bsc#1000189).

  - hv: do not lose pending heartbeat vmbus packets
    (bnc#1006919).

  - i2c: i801: add Intel Lewisburg device IDs (fate#319286).

  - i40e: fix an uninitialized variable bug (bsc#909484
    FATE#317397).

  - include/linux/mmdebug.h: should include linux/bug.h
    (bnc#971975 VM performance -- git fixes).

  - increase CONFIG_NR_IRQS 512 -> 2048 reportedly irq error
    with multiple nvme and tg3 in the same machine is
    resolved by increasing CONFIG_NR_IRQS (bsc#998399)

  - introduce SIZE_MAX (bsc#1000189).

  - ipv6: replacing a rt6_info needs to purge possible
    propagated rt6_infos too (bsc#865783).

  - kabi: Import kabi files from 3.0.101-80

  - kabi-fix for flock_owner addition (bsc#998689).

  - kabi, unix: properly account for FDs passed over unix
    sockets (bnc#839104).

  - kaweth: fix firmware download (bsc#993890).

  - kaweth: fix oops upon failed memory allocation
    (bsc#993890).

  - kvm: x86: only channel 0 of the i8254 is linked to the
    HPET (bsc#960689).

  - kvm: x86: SYSENTER emulation is broken (bsc#994618).

  - libata: support the ata host which implements a queue
    depth less than 32 (bsc#871728)

  - libfc: sanity check cpu number extracted from xid
    (bsc#988440).

  - lib/vsprintf: implement bitmap printing through
    '%*pb[l]' (bnc#1003866).

  - lpfc: call lpfc_sli_validate_fcp_iocb() with the hbalock
    held (bsc#951392).

  - bigmem: make bigmem patches configurable
    (bsc#928138,fate#319026).

  - md: check command validity early in md_ioctl()
    (bsc#1004520).

  - md: Drop sending a change uevent when stopping
    (bsc#1003568).

  - md: fix problem when adding device to read-only array
    with bitmap (bnc#771065).

  - md: lockless I/O submission for RAID1 (bsc#982783).

  - md/raid10: always set reshape_safe when initializing
    reshape_position (fate#311379).

  - md/raid10: Fix memory leak when raid10 reshape completes
    (fate#311379).

  - mm: fix sleeping function warning from __put_anon_vma
    (bnc#1005857).

  - mm/memory.c: actually remap enough memory (bnc#1005903).

  - mm: thp: fix SMP race condition between THP page fault
    and MADV_DONTNEED (VM Functionality, bnc#986445).

  - mm, vmscan: Do not wait for page writeback for GFP_NOFS
    allocations (bnc#763198).

  - Move patches that create ppc64-bigmem to the powerpc
    section. Add comments that outline the procedure and
    warn the unsuspecting.

  - move the call of __d_drop(anon) into
    __d_materialise_unique(dentry, anon) (bsc#984194).

  - mpt2sas, mpt3sas: Fix panic when aer correct error
    occurred (bsc#997708).

  - mshyperv: fix recognition of Hyper-V guest crash MSR's
    (bnc#986337).

  - net: add pfmemalloc check in sk_add_backlog()
    (bnc#920016).

  - netback: fix flipping mode (bsc#996664).

  - netfilter: ipv4: defrag: set local_df flag on
    defragmented skb (bsc#907611).

  - netvsc: fix incorrect receive checksum offloading
    (bnc#1006917).

  - nfs4: reset states to use open_stateid when returning
    delegation voluntarily (bsc#1007944).

  - nfs: Do not disconnect open-owner on NFS4ERR_BAD_SEQID
    (bsc#989261).

  - nfs: Do not drop directory dentry which is in use
    (bsc#993127).

  - nfs: Do not write enable new pages while an invalidation
    is proceeding (bsc#999584).

  - nfs: Fix an LOCK/OPEN race when unlinking an open file
    (bsc#956514).

  - nfs: Fix a regression in the read() syscall
    (bsc#999584).

  - nfs: Fix races in nfs_revalidate_mapping (bsc#999584).

  - nfs: fix the handling of NFS_INO_INVALID_DATA flag in
    nfs_revalidate_mapping (bsc#999584).

  - nfs: Fix writeback performance issue on cache
    invalidation (bsc#999584).

  - nfs: Refresh open-owner id when server says SEQID is bad
    (bsc#989261).

  - nfsv4.1: Fix an NFSv4.1 state renewal regression
    (bnc#863873).

  - nfsv4: add flock_owner to open context (bnc#998689).

  - nfsv4: change nfs4_do_setattr to take an open_context
    instead of a nfs4_state (bnc#998689).

  - nfsv4: change nfs4_select_rw_stateid to take a
    lock_context inplace of lock_owner (bnc#998689).

  - nfsv4: do not check MAY_WRITE access bit in OPEN
    (bsc#985206).

  - nfsv4: enhance nfs4_copy_lock_stateid to use a flock
    stateid if there is one (bnc#998689).

  - nfsv4: fix broken patch relating to v4 read delegations
    (bsc#956514, bsc#989261, bsc#979595).

  - nfsv4: Fix range checking in __nfs4_get_acl_uncached and
    __nfs4_proc_set_acl (bsc#982218).

  - oom: print nodemask in the oom report (bnc#1003866).

  - pci: Add pci_set_vpd_size() to set VPD size
    (bsc#976867).

  - pciback: fix conf_space read/write overlap check.

  - pciback: return proper values during BAR sizing.

  - pci_ids: Add PCI device ID functions 3 and 4 for newer
    F15h models (fate#321400).

  - pm / hibernate: Fix rtree_next_node() to avoid walking
    off list ends (bnc#860441).

  - powerpc/64: Fix incorrect return value from
    __copy_tofrom_user (bsc#1005896).

  - powerpc: Add ability to build little endian kernels
    (bsc#967716).

  - powerpc: add kernel parameter iommu_alloc_quiet
    (bsc#994926).

  - powerpc: Avoid load of static chain register when
    calling nested functions through a pointer on 64bit
    (bsc#967716).

  - powerpc: blacklist fixes for unsupported
    subarchitectures ppc32 only: 6e0fdf9af216 powerpc: fix
    typo 'CONFIG_PMAC' obscure hardware: f7e9e3583625
    powerpc: Fix missing L2 cache size in
    /sys/devices/system/cpu

  - powerpc: Build fix for powerpc KVM
    (bsc#928138,fate#319026).

  - powerpc: Do not build assembly files with ABIv2
    (bsc#967716).

  - powerpc: Do not use ELFv2 ABI to build the kernel
    (bsc#967716).

  - powerpc: dtc is required to build dtb files
    (bsc#967716).

  - powerpc: Fix 64 bit builds with binutils 2.24
    (bsc#967716).

  - powerpc: Fix error when cross building TAGS & cscope
    (bsc#967716).

  - powerpc: Make the vdso32 also build big-endian
    (bsc#967716).

  - powerpc: Make VSID_BITS* dependency explicit
    (bsc#928138,fate#319026).

  - powerpc/mm: Add 64TB support (bsc#928138,fate#319026).

  - powerpc/mm: Change the swap encoding in pte
    (bsc#973203).

  - powerpc/mm: Convert virtual address to vpn
    (bsc#928138,fate#319026).

  - powerpc/mm: Fix hash computation function
    (bsc#928138,fate#319026).

  - powerpc/mm: Increase the slice range to 64TB
    (bsc#928138,fate#319026).

  - powerpc/mm: Make KERN_VIRT_SIZE not dependend on
    PGTABLE_RANGE (bsc#928138,fate#319026).

  - powerpc/mm: Make some of the PGTABLE_RANGE dependency
    explicit (bsc#928138,fate#319026).

  - powerpc/mm: Replace open coded CONTEXT_BITS value
    (bsc#928138,fate#319026).

  - powerpc/mm: Simplify hpte_decode
    (bsc#928138,fate#319026).

  - powerpc/mm: Update VSID allocation documentation
    (bsc#928138,fate#319026).

  - powerpc/mm: Use 32bit array for slb cache
    (bsc#928138,fate#319026).

  - powerpc/mm: Use hpt_va to compute virtual address
    (bsc#928138,fate#319026).

  - powerpc/mm: Use the required number of VSID bits in
    slbmte (bsc#928138,fate#319026).

  - powerpc: Move kdump default base address to half RMO
    size on 64bit (bsc#1003344).

  - powerpc: Remove altivec fix for gcc versions before 4.0
    (bsc#967716).

  - powerpc: Remove buggy 9-year-old test for binutils 

  - powerpc: Rename USER_ESID_BITS* to ESID_BITS*
    (bsc#928138,fate#319026).

  - powerpc: Require gcc 4.0 on 64-bit (bsc#967716).

  - powerpc: Update kernel VSID range
    (bsc#928138,fate#319026).

  - ppp: defer netns reference release for ppp channel
    (bsc#980371).

  - qlcnic: fix a timeout loop (bsc#909350 FATE#317546)

  - random32: add prandom_u32_max (bsc#989152).

  - remove problematic preprocessor constructs
    (bsc#928138,fate#319026).

  - REVERT fs/cifs: fix wrongly prefixed path to root
    (bsc#963655, bsc#979681)

  - rpm/constraints.in: Bump x86 disk space requirement to
    20GB Clamav tends to run out of space nowadays.

  - rpm/package-descriptions: add -bigmem description

  - s390/cio: fix accidental interrupt enabling during
    resume (bnc#1003677, LTC#147606).

  - s390/dasd: fix hanging device after clear subchannel
    (bnc#994436, LTC#144640).

  - s390/time: LPAR offset handling (bnc#1003677,
    LTC#146920).

  - s390/time: move PTFF definitions (bnc#1003677,
    LTC#146920).

  - sata: Adding Intel Lewisburg device IDs for SATA
    (fate#319286).

  - sched/core: Fix an SMP ordering race in try_to_wake_up()
    vs. schedule() (bnc#1001419).

  - sched/core: Fix a race between try_to_wake_up() and a
    woken up task (bnc#1002165).

  - sched: Fix possible divide by zero in avg_atom()
    calculation (bsc#996329).

  - scripts/bigmem-generate-ifdef-guard: auto-regen
    patches.suse/ppc64-bigmem-introduce-CONFIG_BIGMEM

  - scripts/bigmem-generate-ifdef-guard: Include this script
    to regenerate
    patches.suse/ppc64-bigmem-introduce-CONFIG_BIGMEM

  - scripts/bigmem-generate-ifdef-guard: make executable

  - scsi_dh_rdac: retry inquiry for UNIT ATTENTION
    (bsc#934760).

  - scsi: do not print 'reservation conflict' for TEST UNIT
    READY (bsc#984102).

  - scsi: ibmvfc: add FC Class 3 Error Recovery support
    (bsc#984992).

  - scsi: ibmvfc: Fix I/O hang when port is not mapped
    (bsc#971989)

  - scsi: ibmvfc: Set READ FCP_XFER_READY DISABLED bit in
    PRLI (bsc#984992).

  - scsi_scan: Send TEST UNIT READY to LUN0 before LUN
    scanning (bnc#843236,bsc#989779).

  - scsi: zfcp: spin_lock_irqsave() is not nestable
    (bsc#1003677,LTC#147374).

  - Set CONFIG_DEBUG_INFO=y and CONFIG_DEBUG_INFO_REDUCED=n
    on all platforms The specfile adjusts the config if
    necessary, but a new version of run_oldconfig.sh
    requires the settings to be present in the repository.

  - sfc: on MC reset, clear PIO buffer linkage in TXQs
    (bsc#909618 FATE#317521).

  - sort hyperv patches properly in series.conf

  - sunrpc/cache: drop reference when
    sunrpc_cache_pipe_upcall() detects a race (bnc#803320).

  - tg3: Avoid NULL pointer dereference in
    tg3_io_error_detected() (bsc#908458 FATE#317507).

  - tmpfs: change final i_blocks BUG to WARNING
    (bsc#991923).

  - tty: Signal SIGHUP before hanging up ldisc (bnc#989764).

  - Update patches.xen/xen3-auto-arch-x86.diff (bsc#929141,
    a.o.).

  - usb: fix typo in wMaxPacketSize validation (bsc#991665).

  - usb: hub: Fix auto-remount of safely removed or ejected
    USB-3 devices (bsc#922634).

  - usb: hub: Fix unbalanced reference count/memory
    leak/deadlocks (bsc#968010).

  - usb: validate wMaxPacketValue entries in endpoint
    descriptors (bnc#991665).

  - vlan: do not deliver frames for unknown vlans to
    protocols (bsc#979514).

  - vlan: mask vlan prio bits (bsc#979514).

  - vmxnet3: Wake queue from reset work (bsc#999907).

  - x86, amd_nb: Clarify F15h, model 30h GART and L3 support
    (fate#321400).

  - x86/asm/traps: Disable tracing and kprobes in
    fixup_bad_iret and sync_regs (bsc#909077).

  - x86/cpu/amd: Set X86_FEATURE_EXTD_APICID for future
    processors (fate#321400).

  - x86/gart: Check for GART support before accessing GART
    registers (fate#321400).

  - x86/MCE/intel: Cleanup CMCI storm logic (bsc#929141).

  - xenbus: inspect the correct type in
    xenbus_dev_request_and_reply().

  - xen: x86/mm/pat, /dev/mem: Remove superfluous error
    message (bsc#974620).

  - xfs: Avoid grabbing ilock when file size is not changed
    (bsc#983535).

  - xfs: Silence warnings in xfs_vm_releasepage()
    (bnc#915183 bsc#987565).

  - zfcp: close window with unblocked rport during rport
    gone (bnc#1003677, LTC#144310).

  - zfcp: fix D_ID field with actual value on tracing SAN
    responses (bnc#1003677, LTC#144312).

  - zfcp: fix ELS/GS request&response length for hardware
    data router (bnc#1003677, LTC#144308).

  - zfcp: fix payload trace length for SAN request&response
    (bnc#1003677, LTC#144312).

  - zfcp: restore: Dont use 0 to indicate invalid LUN in rec
    trace (bnc#1003677, LTC#144312).

  - zfcp: restore tracing of handle for port and LUN with
    HBA records (bnc#1003677, LTC#144312).

  - zfcp: retain trace level for SCSI and HBA FSF response
    records (bnc#1003677, LTC#144312).

  - zfcp: trace full payload of all SAN records
    (req,resp,iels) (bnc#1003677, LTC#144312).

  - zfcp: trace on request for open and close of WKA port
    (bnc#1003677, LTC#144312).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/763198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/771065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/799133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/803320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/839104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/843236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/860441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/863873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/865783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/871728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/911687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/996329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/996664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4312.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7513.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8956.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0823.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4998.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5696.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6828.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7097.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7117.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7425.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162976-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f491f38"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-kernel-12869=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-kernel-12869=1

SUSE Linux Enterprise Server 11-EXTRA:zypper in -t patch
slexsp3-kernel-12869=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-kernel-12869=1

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/05");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"kernel-default-man-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-base-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-devel-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-source-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-syms-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-base-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-devel-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-base-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-88.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-88.1")) flag++;


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
