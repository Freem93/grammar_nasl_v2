#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0437-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(97097);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/02/13 20:45:10 $");

  script_cve_id("CVE-2004-0230", "CVE-2012-6704", "CVE-2013-6368", "CVE-2015-1350", "CVE-2015-8962", "CVE-2015-8964", "CVE-2016-10088", "CVE-2016-5696", "CVE-2016-7910", "CVE-2016-7911", "CVE-2016-7916", "CVE-2016-8399", "CVE-2016-8632", "CVE-2016-8633", "CVE-2016-8646", "CVE-2016-9555", "CVE-2016-9576", "CVE-2016-9685", "CVE-2016-9756", "CVE-2016-9793", "CVE-2017-5551");
  script_bugtraq_id(10183, 64291);
  script_osvdb_id(4030, 13619, 100986, 117818, 141441, 146777, 146778, 147000, 147033, 147034, 147055, 147059, 147301, 147698, 148103, 148132, 148195, 148409, 148443, 148446, 150899);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2017:0437-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP4 kernel was updated to 3.0.101-94 to
receive various security and bugfixes. The following security bugs
were fixed :

  - CVE-2017-5551: tmpfs: clear S_ISGID when setting posix
    ACLs (bsc#1021258).

  - CVE-2016-10088: The sg implementation in the Linux
    kernel did not properly restrict write operations in
    situations where the KERNEL_DS option is set, which
    allowed local users to read or write to arbitrary kernel
    memory locations or cause a denial of service
    (use-after-free) by leveraging access to a /dev/sg
    device NOTE: this vulnerability existed because of an
    incomplete fix for CVE-2016-9576 (bnc#1017710).

  - CVE-2016-5696: TCP, when using a large Window Size, made
    it easier for remote attackers to guess sequence numbers
    and cause a denial of service (connection loss) to
    persistent TCP connections by repeatedly injecting a TCP
    RST packet, especially in protocols that use long-lived
    connections, such as BGP (bnc#989152).

  - CVE-2015-1350: The VFS subsystem in the Linux kernel 3.x
    provided an incomplete set of requirements for setattr
    operations that underspecified removing extended
    privilege attributes, which allowed local users to cause
    a denial of service (capability stripping) via a failed
    invocation of a system call, as demonstrated by using
    chown to remove a capability from the ping or Wireshark
    dumpcap program (bnc#914939).

  - CVE-2016-8632: The tipc_msg_build function in
    net/tipc/msg.c in the Linux kernel did not validate the
    relationship between the minimum fragment length and the
    maximum packet size, which allowed local users to gain
    privileges or cause a denial of service (heap-based
    buffer overflow) by leveraging the CAP_NET_ADMIN
    capability (bnc#1008831).

  - CVE-2016-8399: An elevation of privilege vulnerability
    in the kernel networking subsystem could enable a local
    malicious application to execute arbitrary code within
    the context of the kernel. This issue is rated as
    Moderate because it first requires compromising a
    privileged process and current compiler optimizations
    restrict access to the vulnerable code. (bnc#1014746).

  - CVE-2016-9793: The sock_setsockopt function in
    net/core/sock.c in the Linux kernel mishandled negative
    values of sk_sndbuf and sk_rcvbuf, which allowed local
    users to cause a denial of service (memory corruption
    and system crash) or possibly have unspecified other
    impact by leveraging the CAP_NET_ADMIN capability for a
    crafted setsockopt system call with the (1)
    SO_SNDBUFFORCE or (2) SO_RCVBUFFORCE option
    (bnc#1013531).

  - CVE-2012-6704: The sock_setsockopt function in
    net/core/sock.c in the Linux kernel mishandled negative
    values of sk_sndbuf and sk_rcvbuf, which allowed local
    users to cause a denial of service (memory corruption
    and system crash) or possibly have unspecified other
    impact by leveraging the CAP_NET_ADMIN capability for a
    crafted setsockopt system call with the (1) SO_SNDBUF or
    (2) SO_RCVBUF option (bnc#1013542).

  - CVE-2016-9756: arch/x86/kvm/emulate.c in the Linux
    kernel did not properly initialize Code Segment (CS) in
    certain error cases, which allowed local users to obtain
    sensitive information from kernel stack memory via a
    crafted application (bnc#1013038).

  - CVE-2016-9685: Multiple memory leaks in error paths in
    fs/xfs/xfs_attr_list.c in the Linux kernel allowed local
    users to cause a denial of service (memory consumption)
    via crafted XFS filesystem operations (bnc#1012832).

  - CVE-2015-8962: Double free vulnerability in the
    sg_common_write function in drivers/scsi/sg.c in the
    Linux kernel allowed local users to gain privileges or
    cause a denial of service (memory corruption and system
    crash) by detaching a device during an SG_IO ioctl call
    (bnc#1010501).

  - CVE-2016-9555: The sctp_sf_ootb function in
    net/sctp/sm_statefuns.c in the Linux kernel lacked
    chunk-length checking for the first chunk, which allowed
    remote attackers to cause a denial of service
    (out-of-bounds slab access) or possibly have unspecified
    other impact via crafted SCTP data (bnc#1011685).

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

  - CVE-2013-6368: The KVM subsystem in the Linux kernel
    allowed local users to gain privileges or cause a denial
    of service (system crash) via a VAPIC synchronization
    operation involving a page-end address (bnc#853052).

  - CVE-2015-8964: The tty_set_termios_ldisc function in
    drivers/tty/tty_ldisc.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory by reading a tty data structure (bnc#1010507).

  - CVE-2016-7916: Race condition in the environ_read
    function in fs/proc/base.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory by reading a /proc/*/environ file during a
    process-setup time interval in which
    environment-variable copying is incomplete
    (bnc#1010467).

  - CVE-2016-8646: The hash_accept function in
    crypto/algif_hash.c in the Linux kernel allowed local
    users to cause a denial of service (OOPS) by attempting
    to trigger use of in-kernel hash algorithms for a socket
    that has received zero bytes of data (bnc#1010150).

  - CVE-2016-8633: drivers/firewire/net.c in the Linux
    kernel, in certain unusual hardware configurations,
    allowed remote attackers to execute arbitrary code via
    crafted fragmented packets (bnc#1008833). The following
    non-security bugs were fixed :

  - 8250_pci: Fix potential use-after-free in error path
    (bsc#1013070).

  - KABI fix (bsc#1014410).

  - apparmor: fix IRQ stack overflow during free_profile
    (bsc#1009875).

  - be2net: Do not leak iomapped memory on removal
    (bug#925065).

  - block_dev: do not test bdev->bd_contains when it is not
    stable (bsc#1008557).

  - bna: Add synchronization for tx ring (bsc#993739).

  - bnx2x: Correct ringparam estimate when DOWN
    (bsc#1020214).

  - crypto: add ghash-generic in the
    supported.conf(bsc#1016824)

  - crypto: aesni - Add support for 192 & 256 bit keys to
    AESNI RFC4106 (bsc#913387).

  - dm: do not call dm_sync_table() when creating new
    devices (bnc#901809).

  - drm/mgag200: Added support for the new deviceID for
    G200eW3 (bnc#1019348)

  - ext3: Avoid premature failure of ext3_has_free_blocks()
    (bsc#1016668).

  - ext4: do not leave i_crtime.tv_sec uninitialized
    (bsc#1013018).

  - ext4: fix reference counting bug on block allocation
    error (bsc#1013018).

  - futex: Acknowledge a new waiter in counter before plist
    (bsc#851603).

  - futex: Drop refcount if requeue_pi() acquired the
    rtmutex (bsc#851603).

  - hpilo: Add support for iLO5 (bsc#999101).

  - ibmveth: calculate gso_segs for large packets
    (bsc#1019165).

  - ibmveth: set correct gso_size and gso_type
    (bsc#1019165).

  - igb: Enable SR-IOV configuration via PCI sysfs interface
    (bsc#909491 FATE#317388).

  - igb: Fix NULL assignment to incorrect variable in
    igb_reset_q_vector (bsc#795297 FATE#313656).

  - igb: Fix oops caused by missing queue pairing
    (bsc#909491 FATE#317388).

  - igb: Fix oops on changing number of rings (bsc#909491
    FATE#317388).

  - igb: Remove unnecessary flag setting in
    igb_set_flag_queue_pairs() (bsc#909491 FATE#317388).

  - igb: Unpair the queues when changing the number of
    queues (bsc#909491 FATE#317388).

  - kexec: add a kexec_crash_loaded() function (bsc#973691).

  - kvm: APIC: avoid instruction emulation for EOI writes
    (bsc#989680).

  - kvm: Distangle eventfd code from irqchip (bsc#989680).

  - kvm: Iterate over only vcpus that are preempted
    (bsc#989680).

  - kvm: Record the preemption status of vcpus using preempt
    notifiers (bsc#989680).

  - kvm: VMX: Pass vcpu to __vmx_complete_interrupts
    (bsc#989680).

  - kvm: fold kvm_pit_timer into kvm_kpit_state
    (bsc#989680).

  - kvm: make processes waiting on vcpu mutex killable
    (bsc#989680).

  - kvm: nVMX: Add preemption timer support (bsc#989680).

  - kvm: remove a wrong hack of delivery PIT intr to vcpu0
    (bsc#989680).

  - kvm: use symbolic constant for nr interrupts
    (bsc#989680).

  - kvm: x86: Remove support for reporting coalesced APIC
    IRQs (bsc#989680).

  - kvm: x86: Run PIT work in own kthread (bsc#989680).

  - kvm: x86: limit difference between kvmclock updates
    (bsc#989680).

  - libata: introduce ata_host->n_tags to avoid oops on SAS
    controllers (bsc#871728).

  - libata: remove n_tags to avoid kABI breakage
    (bsc#871728).

  - libfc: Do not take rdata->rp_mutex when processing a
    -FC_EX_CLOSED ELS response (bsc#962846).

  - libfc: Fixup disc_mutex handling (bsc#962846).

  - libfc: Issue PRLI after a PRLO has been received
    (bsc#962846).

  - libfc: Revisit kref handling (bnc#990245).

  - libfc: Update rport reference counting (bsc#953233).

  - libfc: do not send ABTS when resetting exchanges
    (bsc#962846).

  - libfc: fixup locking of ptp_setup() (bsc#962846).

  - libfc: reset exchange manager during LOGO handling
    (bsc#962846).

  - libfc: send LOGO for PLOGI failure (bsc#962846).

  - locking/mutex: Explicitly mark task as running after
    wakeup (bsc#1012411).

  - memstick: mspro_block: add missing curly braces
    (bsc#1016688).

  - mlx4: Fix error flow when sending mads under SRIOV
    (bsc#786036 FATE#314304).

  - mlx4: Fix incorrect MC join state bit-masking on SR-IOV
    (bsc#786036 FATE#314304).

  - mlx4: Fix memory leak if QP creation failed (bsc#786036
    FATE#314304).

  - mlx4: Fix potential deadlock when sending mad to wire
    (bsc#786036 FATE#314304).

  - mlx4: Forbid using sysfs to change RoCE pkeys
    (bsc#786036 FATE#314304).

  - mlx4: Use correct subnet-prefix in QP1 mads under SR-IOV
    (bsc#786036 FATE#314304).

  - mlx4: add missing braces in verify_qp_parameters
    (bsc#786036 FATE#314304).

  - mm/memory_hotplug.c: check for missing sections in
    test_pages_in_a_zone() (bnc#961589).

  - mm: fix crashes from mbind() merging vmas (bnc#1005877).

  - mpi: Fix NULL ptr dereference in mpi_powm() [ver #3]
    (bsc#1011820).

  - mremap: enforce rmap src/dst vma ordering in case of
    vma_merge() succeeding in copy_vma() (bsc#1008645).

  - net/mlx4: Copy/set only sizeof struct mlx4_eqe bytes
    (bsc#786036 FATE#314304).

  - net/mlx4_core: Allow resetting VF admin mac to zero
    (bsc#919382 FATE#317529).

  - net/mlx4_core: Avoid returning success in case of an
    error flow (bsc#786036 FATE#314304).

  - net/mlx4_core: Do not BUG_ON during reset when PCI is
    offline (bsc#924708).

  - net/mlx4_core: Do not access comm channel if it has not
    yet been initialized (bsc#924708).

  - net/mlx4_core: Fix error message deprecation for
    ConnectX-2 cards (bsc#919382 FATE#317529).

  - net/mlx4_core: Fix the resource-type enum in res tracker
    to conform to FW spec (bsc#786036 FATE#314304).

  - net/mlx4_core: Implement pci_resume callback
    (bsc#924708).

  - net/mlx4_core: Update the HCA core clock frequency after
    INIT_PORT (bug#919382 FATE#317529).

  - net/mlx4_en: Choose time-stamping shift value according
    to HW frequency (bsc#919382 FATE#317529).

  - net/mlx4_en: Fix HW timestamp init issue upon system
    startup (bsc#919382 FATE#317529).

  - net/mlx4_en: Fix potential deadlock in port statistics
    flow (bsc#786036 FATE#314304).

  - net/mlx4_en: Move filters cleanup to a proper location
    (bsc#786036 FATE#314304).

  - net/mlx4_en: Remove dependency between timestamping
    capability and service_task (bsc#919382 FATE#317529).

  - net/mlx4_en: fix spurious timestamping callbacks
    (bsc#919382 FATE#317529).

  - netfront: do not truncate grant references.

  - nfsv4: Cap the transport reconnection timer at 1/2 lease
    period (bsc#1014410).

  - nfsv4: Cleanup the setting of the nfs4 lease period
    (bsc#1014410).

  - nfsv4: Handle timeouts correctly when probing for lease
    validity (bsc#1014410).

  - nvme: Automatic namespace rescan (bsc#1017686).

  - nvme: Metadata format support (bsc#1017686).

  - ocfs2: fix BUG_ON() in ocfs2_ci_checkpointed()
    (bnc#1019783).

  - posix-timers: Remove remaining uses of tasklist_lock
    (bnc#997401).

  - posix-timers: Use sighand lock instead of tasklist_lock
    for task clock sample (bnc#997401).

  - posix-timers: Use sighand lock instead of tasklist_lock
    on timer deletion (bnc#997401).

  - powerpc/MSI: Fix race condition in tearing down MSI
    interrupts (bsc#1010201).

  - powerpc/mm/hash64: Fix subpage protection with 4K HPTE
    config (bsc#1010201).

  - powerpc/numa: Fix multiple bugs in memory_hotplug_max()
    (bsc#1010201).

  - powerpc/pseries: Use H_CLEAR_HPT to clear MMU hash table
    during kexec (bsc#1003813).

  - powerpc: fix typo 'CONFIG_PPC_CPU' (bsc#1010201).

  - powerpc: scan_features() updates incorrect bits for
    REAL_LE (bsc#1010201).

  - printk/sched: Introduce special printk_sched() for those
    awkward (bsc#996541).

  - ptrace: __ptrace_may_access() should not deny
    sub-threads (bsc#1012851).

  - qlcnic: fix a loop exit condition better (bsc#909350
    FATE#317546).

  - qlcnic: use the correct ring in
    qlcnic_83xx_process_rcv_ring_diag() (bnc#800999
    FATE#313899).

  - reiserfs: fix race in prealloc discard (bsc#987576).

  - rpm/constraints.in: Bump ppc64 disk requirements to fix
    OBS builds again

  - rpm/kernel-binary.spec.in: Export a make-stderr.log file
    (bsc#1012422)

  - rt2x00: fix rfkill regression on rt2500pci (bnc#748806).

  - s390/zcrypt: kernel: Fix invalid domain response
    handling (bsc#1016320).

  - scsi: Fix erratic device offline during EH (bsc#993832).

  - scsi: lpfc: Set elsiocb contexts to NULL after freeing
    it (bsc#996557).

  - scsi: lpfc: avoid double free of resource identifiers
    (bsc#989896).

  - scsi_error: count medium access timeout only once per EH
    run (bsc#993832).

  - scsi_error: fixup crash in scsi_eh_reset (bsc#993832)

  - serial: 8250_pci: Detach low-level driver during PCI
    error recovery (bsc#1013070).

  - sunrpc: Enforce an upper limit on the number of cached
    credentials (bsc#1012917).

  - sunrpc: Fix reconnection timeouts (bsc#1014410).

  - sunrpc: Fix two issues with drop_caches and the sunrpc
    auth cache (bsc#1012917).

  - sunrpc: Limit the reconnect backoff timer to the max RPC
    message timeout (bsc#1014410).

  - tcp: fix inet6_csk_route_req() for link-local addresses
    (bsc#1010175).

  - tcp: pass fl6 to inet6_csk_route_req() (bsc#1010175).

  - tcp: plug dst leak in tcp_v6_conn_request()
    (bsc#1010175).

  - tcp: use inet6_csk_route_req() in tcp_v6_send_synack()
    (bsc#1010175).

  - tg3: Fix temperature reporting (bnc#790588 FATE#313912).

  - usb: console: fix potential use after free
    (bsc#1015817).

  - usb: console: fix uninitialised ldisc semaphore
    (bsc#1015817).

  - usb: cp210x: Corrected USB request type definitions
    (bsc#1015932).

  - usb: cp210x: relocate private data from USB interface to
    port (bsc#1015932).

  - usb: cp210x: work around cp2108 GET_LINE_CTL bug
    (bsc#1015932).

  - usb: ftdi_sio: fix null deref at port probe
    (bsc#1015796).

  - usb: ipaq.c: fix a timeout loop (bsc#1015848).

  - usb: opticon: fix non-atomic allocation in write path
    (bsc#1015803).

  - usb: option: fix runtime PM handling (bsc#1015752).

  - usb: serial: cp210x: add 16-bit register access
    functions (bsc#1015932).

  - usb: serial: cp210x: add 8-bit and 32-bit register
    access functions (bsc#1015932).

  - usb: serial: cp210x: add new access functions for large
    registers (bsc#1015932).

  - usb: serial: cp210x: fix hardware flow-control disable
    (bsc#1015932).

  - usb: serial: fix potential use-after-free after failed
    probe (bsc#1015828).

  - usb: serial: io_edgeport: fix memory leaks in attach
    error path (bsc#1016505).

  - usb: serial: io_edgeport: fix memory leaks in probe
    error path (bsc#1016505).

  - usb: serial: keyspan: fix use-after-free in probe error
    path (bsc#1016520).

  - usb: sierra: fix AA deadlock in open error path
    (bsc#1015561).

  - usb: sierra: fix remote wakeup (bsc#1015561).

  - usb: sierra: fix urb and memory leak in resume error
    path (bsc#1015561).

  - usb: sierra: fix urb and memory leak on disconnect
    (bsc#1015561).

  - usb: sierra: fix use after free at suspend/resume
    (bsc#1015561).

  - usb: usb_wwan: fix potential blocked I/O after resume
    (bsc#1015760).

  - usb: usb_wwan: fix race between write and resume
    (bsc#1015760).

  - usb: usb_wwan: fix urb leak at shutdown (bsc#1015760).

  - usb: usb_wwan: fix urb leak in write error path
    (bsc#1015760).

  - usb: usb_wwan: fix write and suspend race (bsc#1015760).

  - usbhid: add ATEN CS962 to list of quirky devices
    (bsc#1007615).

  - usblp: do not set TASK_INTERRUPTIBLE before lock
    (bsc#1015844).

  - xenbus: do not invoke is_ready() for most device states
    (bsc#987333).

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
    value:"https://bugzilla.suse.com/1005877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013531"
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
    value:"https://bugzilla.suse.com/1014454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/748806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/786036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/790588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/795297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/800999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/821612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/824171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/851603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/853052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/871728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/901809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/913387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/996541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/996557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2004-0230.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2012-6704.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-6368.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1350.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8962.html"
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
    value:"https://www.suse.com/security/cve/CVE-2016-5696.html"
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
    value:"https://www.suse.com/security/cve/CVE-2016-7916.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8399.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8632.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8633.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8646.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9685.html"
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
    value:"https://www.suse.com/security/cve/CVE-2017-5551.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170437-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2478355"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-kernel-12977=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-kernel-12977=1

SUSE Linux Enterprise Server 11-EXTRA:zypper in -t patch
slexsp3-kernel-12977=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-kernel-12977=1

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/20");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"kernel-default-man-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-base-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-devel-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-source-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-syms-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-base-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-devel-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-base-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-94.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-94.1")) flag++;


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
