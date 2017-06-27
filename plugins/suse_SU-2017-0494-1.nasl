#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0494-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(97297);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/21 14:37:43 $");

  script_cve_id("CVE-2004-0230", "CVE-2012-6704", "CVE-2015-1350", "CVE-2015-8956", "CVE-2015-8962", "CVE-2015-8964", "CVE-2015-8970", "CVE-2016-0823", "CVE-2016-10088", "CVE-2016-3841", "CVE-2016-6828", "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-7117", "CVE-2016-7425", "CVE-2016-7910", "CVE-2016-7911", "CVE-2016-7916", "CVE-2016-8399", "CVE-2016-8632", "CVE-2016-8633", "CVE-2016-8646", "CVE-2016-9555", "CVE-2016-9576", "CVE-2016-9685", "CVE-2016-9756", "CVE-2016-9793", "CVE-2017-5551");
  script_bugtraq_id(10183);
  script_osvdb_id(4030, 13619, 117818, 135484, 142466, 142992, 143514, 144411, 145048, 145102, 145585, 146704, 146777, 146778, 147000, 147033, 147034, 147055, 147059, 147301, 147698, 148103, 148132, 148195, 148409, 148443, 148446, 150899);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2017:0494-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP3 LTSS kernel was updated to receive
various security and bugfixes. The following security bugs were 
fixed :

  - CVE-2015-8970: crypto/algif_skcipher.c in the Linux
    kernel did not verify that a setkey operation has been
    performed on an AF_ALG socket before an accept system
    call is processed, which allowed local users to cause a
    denial of service (NULL pointer dereference and system
    crash) via a crafted application that did not supply a
    key, related to the lrw_crypt function in crypto/lrw.c
    (bnc#1008374).

  - CVE-2017-5551: Clear S_ISGID on tmpfs when setting posix
    ACLs (bsc#1021258).

  - CVE-2016-7097: The filesystem implementation in the
    Linux kernel preserves the setgid bit during a setxattr
    call, which allowed local users to gain group privileges
    by leveraging the existence of a setgid program with
    restrictions on execute permissions (bnc#995968).

  - CVE-2016-10088: The sg implementation in the Linux
    kernel did not properly restrict write operations in
    situations where the KERNEL_DS option is set, which
    allowed local users to read or write to arbitrary kernel
    memory locations or cause a denial of service
    (use-after-free) by leveraging access to a /dev/sg
    device, related to block/bsg.c and drivers/scsi/sg.c.
    NOTE: this vulnerability exists because of an incomplete
    fix for CVE-2016-9576 (bnc#1017710).

  - CVE-2004-0230: TCP, when using a large Window Size, made
    it easier for remote attackers to guess sequence numbers
    and cause a denial of service (connection loss) to
    persistent TCP connections by repeatedly injecting a TCP
    RST packet, especially in protocols that use long-lived
    connections, such as BGP (bnc#969340).

  - CVE-2016-8632: The tipc_msg_build function in
    net/tipc/msg.c in the Linux kernel did not validate the
    relationship between the minimum fragment length and the
    maximum packet size, which allowed local users to gain
    privileges or cause a denial of service (heap-based
    buffer overflow) by leveraging the CAP_NET_ADMIN
    capability (bnc#1008831).

  - CVE-2016-8399: An elevation of privilege vulnerability
    in the kernel networking subsystem could have enabled a
    local malicious application to execute arbitrary code
    within the context of the kernel bnc#1014746).

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

  - CVE-2016-3841: The IPv6 stack in the Linux kernel
    mishandled options data, which allowed local users to
    gain privileges or cause a denial of service
    (use-after-free and system crash) via a crafted sendmsg
    system call (bnc#992566).

  - CVE-2016-9685: Multiple memory leaks in error paths in
    fs/xfs/xfs_attr_list.c in the Linux kernel allowed local
    users to cause a denial of service (memory consumption)
    via crafted XFS filesystem operations (bnc#1012832).

  - CVE-2015-1350: The VFS subsystem in the Linux kernel
    provided an incomplete set of requirements for setattr
    operations that underspecifies removing extended
    privilege attributes, which allowed local users to cause
    a denial of service (capability stripping) via a failed
    invocation of a system call, as demonstrated by using
    chown to remove a capability from the ping or Wireshark
    dumpcap program (bnc#914939).

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
    kernel in certain unusual hardware configurations
    allowed remote attackers to execute arbitrary code via
    crafted fragmented packets (bnc#1008833).

  - CVE-2016-7042: The proc_keys_show function in
    security/keys/proc.c in the Linux, when the GNU Compiler
    Collection (gcc) stack protector is enabled, used an
    incorrect buffer size for certain timeout data, which
    allowed local users to cause a denial of service (stack
    memory corruption and panic) by reading the /proc/keys
    file (bnc#1004517).

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
    by reading a pagemap file (bnc#994759).

  - CVE-2016-7425: The arcmsr_iop_message_xfer function in
    drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did
    not restrict a certain length field, which allowed local
    users to gain privileges or cause a denial of service
    (heap-based buffer overflow) via an
    ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).

  - CVE-2016-6828: The tcp_check_send_head function in
    include/net/tcp.h in the Linux kernel did not properly
    maintain certain SACK state after a failed data copy,
    which allowed local users to cause a denial of service
    (tcp_xmit_retransmit_queue use-after-free and system
    crash) via a crafted SACK option (bnc#994296). The
    following non-security bugs were fixed :

  - Always include the git commit in KOTD builds. This
    allows us not to set it explicitly in builds submitted
    to the official distribution (bnc#821612, bnc#824171).

  - KVM: x86: SYSENTER emulation is broken (bsc#994618).

  - NFS: Do not disconnect open-owner on NFS4ERR_BAD_SEQID
    (bsc#989261).

  - NFS: Refresh open-owner id when server says SEQID is bad
    (bsc#989261).

  - NFSv4: Ensure that we do not drop a state owner more
    than once (bsc#979595).

  - NFSv4: add flock_owner to open context (bnc#998689).

  - NFSv4: change nfs4_do_setattr to take an open_context
    instead of a nfs4_state (bnc#998689).

  - NFSv4: change nfs4_select_rw_stateid to take a
    lock_context inplace of lock_owner (bnc#998689).

  - NFSv4: enhance nfs4_copy_lock_stateid to use a flock
    stateid if there is one (bnc#998689).

  - NFSv4: fix broken patch relating to v4 read delegations
    (bsc#956514, bsc#989261, bsc#979595).

  - SELinux: Fix possible NULL pointer dereference in
    selinux_inode_permission() (bsc#1012895).

  - USB: fix typo in wMaxPacketSize validation (bsc#991665).

  - USB: validate wMaxPacketValue entries in endpoint
    descriptors (bnc#991665).

  - Update patches.xen/xen3-auto-arch-x86.diff (bsc#929141,
    among others).

  - __ptrace_may_access() should not deny sub-threads
    (bsc#1012851).

  - apparmor: fix IRQ stack overflow during free_profile
    (bsc#1009875).

  - arch/powerpc: Remove duplicate/redundant Altivec entries
    (bsc#967716).

  - cdc-acm: added sanity checking for probe() (bsc#993891).

  - include/linux/math64.h: add div64_ul() (bsc#996329).

  - kabi-fix for flock_owner addition (bsc#998689).

  - kabi: get back scsi_device.current_cmnd (bsc#935436).

  - kaweth: fix firmware download (bsc#993890).

  - kaweth: fix oops upon failed memory allocation
    (bsc#993890).

  - kexec: add a kexec_crash_loaded() function (bsc#973691).

  - md linear: fix a race between linear_add() and
    linear_congested() (bsc#1018446).

  - mpi: Fix NULL ptr dereference in mpi_powm() [ver #3]
    (bsc#1011820).

  - mpt3sas: Fix panic when aer correct error occurred
    (bsc#997708, bsc#999943).

  - mremap: enforce rmap src/dst vma ordering in case of
    vma_merge() succeeding in copy_vma() (VM Functionality,
    bsc#1008645).

  - nfs4: reset states to use open_stateid when returning
    delegation voluntarily (bsc#1007944).

  - ocfs2: fix BUG_ON() in ocfs2_ci_checkpointed()
    (bnc#1019783).

  - posix-timers: Remove remaining uses of tasklist_lock
    (bnc#997401).

  - posix-timers: Use sighand lock instead of tasklist_lock
    for task clock sample (bnc#997401).

  - posix-timers: Use sighand lock instead of tasklist_lock
    on timer deletion (bnc#997401).

  - powerpc: Add ability to build little endian kernels
    (bsc#967716).

  - powerpc: Avoid load of static chain register when
    calling nested functions through a pointer on 64bit
    (bsc#967716).

  - powerpc: Do not build assembly files with ABIv2
    (bsc#967716).

  - powerpc: Do not use ELFv2 ABI to build the kernel
    (bsc#967716).

  - powerpc: Fix 64 bit builds with binutils 2.24
    (bsc#967716).

  - powerpc: Fix error when cross building TAGS and cscope
    (bsc#967716).

  - powerpc: Make the vdso32 also build big-endian
    (bsc#967716).

  - powerpc: Remove altivec fix for gcc versions before 4.0
    (bsc#967716).

  - powerpc: Remove buggy 9-year-old test for binutils lower
    than 2.12.1 (bsc#967716).

  - powerpc: Require gcc 4.0 on 64-bit (bsc#967716).

  - powerpc: dtc is required to build dtb files
    (bsc#967716).

  - printk/sched: Introduce special printk_sched() for those
    awkward (bsc#1013042, bsc#996541, bsc#1015878).

  - qlcnic: Schedule napi directly in netpoll (bsc#966826).

  - reiserfs: fix race in prealloc discard (bsc#987576).

  - rpm/config.sh: Set a fitting release string (bsc#997059)

  - rpm/kernel-binary.spec.in: Export a make-stderr.log file
    (bsc#1012422)

  - rpm/mkspec: Read a default release string from
    rpm/config.sh (bsc997059)

  - s390/dasd: fix failfast for disconnected devices
    (bnc#961923, LTC#135138).

  - sched/core: Fix a race between try_to_wake_up() and a
    woken up task (bnc#1002165).

  - sched/core: Fix an SMP ordering race in try_to_wake_up()
    vs. schedule() (bnc#1001419).

  - sched: Fix possible divide by zero in avg_atom()
    calculation (bsc#996329).

  - scsi: lpfc: Set elsiocb contexts to NULL after freeing
    it (bsc#996557).

  - scsi: remove current_cmnd field from struct scsi_device
    (bsc#935436).

  - x86/MCE/intel: Cleanup CMCI storm logic (bsc#929141).

  - xfs: remove the deprecated nodelaylog option
    (bsc#992906).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
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
    value:"https://bugzilla.suse.com/1003253"
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
    value:"https://bugzilla.suse.com/1007944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008374"
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
    value:"https://bugzilla.suse.com/1008850"
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
    value:"https://bugzilla.suse.com/1012895"
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
    value:"https://bugzilla.suse.com/1013531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013542"
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
    value:"https://bugzilla.suse.com/1015878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021258"
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
    value:"https://bugzilla.suse.com/914939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967716"
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
    value:"https://bugzilla.suse.com/979595"
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
    value:"https://bugzilla.suse.com/989261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992991"
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
    value:"https://bugzilla.suse.com/994618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994759"
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
    value:"https://bugzilla.suse.com/996541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/996557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999943"
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
    value:"https://www.suse.com/security/cve/CVE-2015-1350.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8956.html"
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
    value:"https://www.suse.com/security/cve/CVE-2015-8970.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0823.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10088.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3841.html"
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
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170494-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6172bddf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5:zypper in -t patch
sleclo50sp3-linux-kernel-12992=1

SUSE Manager Proxy 2.1:zypper in -t patch
slemap21-linux-kernel-12992=1

SUSE Manager 2.1:zypper in -t patch sleman21-linux-kernel-12992=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-linux-kernel-12992=1

SUSE Linux Enterprise Server 11-EXTRA:zypper in -t patch
slexsp3-linux-kernel-12992=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-linux-kernel-12992=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-linux-kernel-12992=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-devel");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/21");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-base-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-base-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-devel-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-source-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-syms-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-base-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-devel-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.96.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.96.1")) flag++;


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
