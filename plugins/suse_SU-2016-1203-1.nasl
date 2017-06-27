#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1203-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(90884);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:08 $");

  script_cve_id("CVE-2013-2015", "CVE-2013-7446", "CVE-2015-0272", "CVE-2015-7509", "CVE-2015-7515", "CVE-2015-7550", "CVE-2015-7566", "CVE-2015-7799", "CVE-2015-8215", "CVE-2015-8539", "CVE-2015-8543", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8767", "CVE-2015-8785", "CVE-2015-8812", "CVE-2015-8816", "CVE-2016-0723", "CVE-2016-2069", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549", "CVE-2016-2782", "CVE-2016-2847", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3139", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3955");
  script_bugtraq_id(59512);
  script_osvdb_id(92851, 127518, 128845, 130525, 130648, 131666, 131683, 131685, 131735, 131951, 131952, 132029, 132030, 132031, 132202, 132748, 132811, 133409, 133625, 134512, 134538, 134915, 134916, 134917, 134918, 134919, 134920, 134938, 135143, 135194, 135871, 135872, 135873, 135874, 135875, 135876, 135877, 135878, 135943, 135975, 137359);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2016:1203-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP3 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2013-7446: Use-after-free vulnerability in
    net/unix/af_unix.c in the Linux kernel allowed local
    users to bypass intended AF_UNIX socket permissions or
    cause a denial of service (panic) via crafted epoll_ctl
    calls (bnc#955654).

  - CVE-2015-7509: fs/ext4/namei.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (system crash) via a crafted no-journal
    filesystem, a related issue to CVE-2013-2015
    (bnc#956707).

  - CVE-2015-7515: An out of bounds memory access in the
    aiptek USB driver could be used by physical local
    attackers to crash the kernel (bnc#956708).

  - CVE-2015-7550: The keyctl_read_key function in
    security/keys/keyctl.c in the Linux kernel did not
    properly use a semaphore, which allowed local users to
    cause a denial of service (NULL pointer dereference and
    system crash) or possibly have unspecified other impact
    via a crafted application that leverages a race
    condition between keyctl_revoke and keyctl_read calls
    (bnc#958951).

  - CVE-2015-7566: A malicious USB device could cause kernel
    crashes in the visor device driver (bnc#961512).

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
    that is (1) smaller than the minimum compliant value or
    (2) larger than the MTU of an interface, as demonstrated
    by a Router Advertisement (RA) message that is not
    validated by a daemon, a different vulnerability than
    CVE-2015-0272. NOTE: the scope of CVE-2015-0272 is
    limited to the NetworkManager product (bnc#955354).

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
    in backend (bsc#957988). (bsc#957988 XSA-155).

  - CVE-2015-8551: The PCI backend driver in Xen, when
    running on an x86 system and using Linux as the driver
    domain, allowed local guest administrators to hit BUG
    conditions and cause a denial of service (NULL pointer
    dereference and host OS crash) by leveraging a system
    with access to a passed-through MSI or MSI-X capable
    physical PCI device and a crafted sequence of
    XEN_PCI_OP_* operations, aka 'Linux pciback missing
    sanity checks (bnc#957990).

  - CVE-2015-8552: The PCI backend driver in Xen, when
    running on an x86 system and using Linux as the driver
    domain, allowed local guest administrators to generate a
    continuous stream of WARN messages and cause a denial of
    service (disk consumption) by leveraging a system with
    access to a passed-through MSI or MSI-X capable physical
    PCI device and XEN_PCI_OP_enable_msi operations, aka
    'Linux pciback missing sanity checks (bnc#957990).

  - CVE-2015-8569: The (1) pptp_bind and (2) pptp_connect
    functions in drivers/net/ppp/pptp.c in the Linux kernel
    do not verify an address length, which allowed local
    users to obtain sensitive information from kernel memory
    and bypass the KASLR protection mechanism via a crafted
    application (bnc#959190).

  - CVE-2015-8575: The sco_sock_bind function in
    net/bluetooth/sco.c in the Linux kernel did not verify
    an address length, which allowed local users to obtain
    sensitive information from kernel memory and bypass the
    KASLR protection mechanism via a crafted application
    (bnc#959399).

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

  - CVE-2015-8812: A flaw was found in the CXGB3 kernel
    driver when the network was considered congested. The
    kernel would incorrectly misinterpret the congestion as
    an error condition and incorrectly free/clean up the
    skb. When the device would then send the skb's queued,
    these structures would be referenced and may panic the
    system or allow an attacker to escalate privileges in a
    use-after-free scenario.(bsc#966437).

  - CVE-2015-8816: A malicious USB device could cause kernel
    crashes in the in hub_activate() function (bnc#968010).

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

  - CVE-2016-2143: On zSeries a fork of a large process
    could have caused memory corruption due to incorrect
    page table handling. (bnc#970504, LTC#138810).

  - CVE-2016-2184: A malicious USB device could cause kernel
    crashes in the alsa usb-audio device driver
    (bsc#971125).

  - CVE-2016-2185: A malicious USB device could cause kernel
    crashes in the usb_driver_claim_interface function
    (bnc#971124).

  - CVE-2016-2186: A malicious USB device could cause kernel
    crashes in the powermate device driver (bnc#970958).

  - CVE-2016-2384: A double free on the ALSA umidi object
    was fixed. (bsc#966693).

  - CVE-2016-2543: A missing NULL check at remove_events
    ioctl in the ALSA seq driver was fixed. (bsc#967972).

  - CVE-2016-2544: Fix race at timer setup and close in the
    ALSA seq driver was fixed. (bsc#967973).

  - CVE-2016-2545: A double unlink of active_list in the
    ALSA timer driver was fixed. (bsc#967974).

  - CVE-2016-2546: A race among ALSA timer ioctls was fixed
    (bsc#967975).

  - CVE-2016-2547,CVE-2016-2548: The ALSA slave timer list
    handling was hardened against hangs and races.
    (CVE-2016-2547,CVE-2016-2548,bsc#968011,bsc#968012).

  - CVE-2016-2549: A stall in ALSA hrtimer handling was
    fixed (bsc#968013).

  - CVE-2016-2782: A malicious USB device could cause kernel
    crashes in the visor device driver (bnc#968670).

  - CVE-2016-3137: A malicious USB device could cause kernel
    crashes in the cypress_m8 device driver (bnc#970970).

  - CVE-2016-3139: A malicious USB device could cause kernel
    crashes in the wacom device driver (bnc#970909).

  - CVE-2016-3140: A malicious USB device could cause kernel
    crashes in the digi_acceleport device driver
    (bnc#970892).

  - CVE-2016-3156: A quadratic algorithm could lead to long
    kernel ipv4 hangs when removing a device with a large
    number of addresses. (bsc#971360).

  - CVE-2016-3955: A remote buffer overflow in the usbip
    driver could be used by authenticated attackers to crash
    the kernel. (bsc#975945)

  - CVE-2016-2847: A local user could exhaust kernel memory
    by pushing lots of data into pipes. (bsc#970948).

  - CVE-2016-2188: A malicious USB device could cause kernel
    crashes in the iowarrior device driver (bnc#970956).

  - CVE-2016-3138: A malicious USB device could cause kernel
    crashes in the cdc-acm device driver (bnc#970911).

The following non-security bugs were fixed :

  - af_unix: Guard against other == sk in unix_dgram_sendmsg
    (bsc#973570).

  - blktap: also call blkif_disconnect() when frontend
    switched to closed (bsc#952976).

  - blktap: refine mm tracking (bsc#952976).

  - cachefiles: Avoid deadlocks with fs freezing
    (bsc#935123).

  - cifs: Schedule on hard mount retry (bsc#941514).

  - cpuset: Fix potential deadlock w/ set_mems_allowed
    (bsc#960857, bsc#974646).

  - dcache: use IS_ROOT to decide where dentry is hashed
    (bsc#949752).

  - driver: Vmxnet3: Fix ethtool -S to return correct rx
    queue stats (bsc#950750).

  - drm/i915: Change semantics of hw_contexts_disabled
    (bsc#963276).

  - drm/i915: Evict CS TLBs between batches (bsc#758040).

  - drm/i915: Fix SRC_COPY width on 830/845g (bsc#758040).

  - e1000e: Do not read ICR in Other interrupt (bsc#924919).

  - e1000e: Do not write lsc to ics in msi-x mode
    (bsc#924919).

  - e1000e: Fix msi-x interrupt automask (bsc#924919).

  - e1000e: Remove unreachable code (bsc#924919).

  - ext3: fix data=journal fast mount/umount hang
    (bsc#942082).

  - ext3: NULL dereference in ext3_evict_inode()
    (bsc#942082).

  - firmware: Create directories for external firmware
    (bsc#959312).

  - firmware: Simplify directory creation (bsc#959312).

  - fs: Avoid deadlocks of fsync_bdev() and fs freezing
    (bsc#935123).

  - fs: Fix deadlocks between sync and fs freezing
    (bsc#935123).

  - ftdi_sio: private backport of TIOCMIWAIT (bnc#956375).

  - ipr: Fix incorrect trace indexing (bsc#940913).

  - ipr: Fix invalid array indexing for HRRQ (bsc#940913).

  - ipv6: make fib6 serial number per namespace
    (bsc#965319).

  - ipv6: mld: fix add_grhead skb_over_panic for devs with
    large MTUs (bsc#956852).

  - ipv6: per netns fib6 walkers (bsc#965319).

  - ipv6: per netns FIB garbage collection (bsc#965319).

  - ipv6: replace global gc_args with local variable
    (bsc#965319).

  - jbd: Fix unreclaimed pages after truncate in
    data=journal mode (bsc#961516).

  - kabi: protect struct netns_ipv6 after FIB6 GC series
    (bsc#965319).

  - kbuild: create directory for dir/file.o (bsc#959312).

  - kexec: Fix race between panic() and crash_kexec() called
    directly (bnc#937444).

  - lpfc: Fix null ndlp dereference in target_reset_handler
    (bsc#951392).

  - mld, igmp: Fix reserved tailroom calculation
    (bsc#956852).

  - mm-memcg-print-statistics-from-live-counters-fix
    (bnc#969307).

  - netfilter: xt_recent: fix namespace destroy path
    (bsc#879378).

  - nfs4: treat lock owners as opaque values (bnc#968141).

  - nfs: Fix handling of re-write-before-commit for mmapped
    NFS pages (bsc#964201).

  - nfs: use smaller allocations for 'struct id_map'
    (bsc#965923).

  - nfsv4: Fix two infinite loops in the mount code
    (bsc#954628).

  - nfsv4: Recovery of recalled read delegations is broken
    (bsc#956514).

  - panic/x86: Allow cpus to save registers even if they
    (bnc#940946).

  - panic/x86: Fix re-entrance problem due to panic on
    (bnc#937444).

  - pciback: do not allow MSI-X ops if PCI_COMMAND_MEMORY is
    not set.

  - pciback: for XEN_PCI_OP_disable_msi[|x] only disable if
    device has MSI(X) enabled.

  - pciback: return error on XEN_PCI_OP_enable_msi when
    device has MSI or MSI-X enabled.

  - pciback: return error on XEN_PCI_OP_enable_msix when
    device has MSI or MSI-X enabled.

  - pci: Update VPD size with correct length (bsc#958906).

  - quota: Fix deadlock with suspend and quotas
    (bsc#935123).

  - rdma/ucma: Fix AB-BA deadlock (bsc#963998).

  - README.BRANCH: Switch to LTSS mode

  - Refresh
    patches.xen/xen3-08-x86-ldt-make-modify_ldt-synchronous.
    patch (bsc#959705).

  - Restore kabi after lock-owner change (bnc#968141).

  - s390/pageattr: Do a single TLB flush for
    change_page_attr (bsc#940413).

  - scsi_dh_rdac: always retry MODE SELECT on command lock
    violation (bsc#956949).

  - scsi: mpt2sas: Rearrange the the code so that the
    completion queues are initialized prior to sending the
    request to controller firmware (bsc#967863).

  - skb: Add inline helper for getting the skb end offset
    from head (bsc#956852).

  - sunrcp: restore fair scheduling to priority queues
    (bsc#955308).

  - sunrpc: refactor rpcauth_checkverf error returns
    (bsc#955673).

  - tcp: avoid order-1 allocations on wifi and tx path
    (bsc#956852).

  - tcp: fix skb_availroom() (bsc#956852).

  - tg3: 5715 does not link up when autoneg off
    (bsc#904035).

  - Update
    patches.fixes/mm-exclude-reserved-pages-from-dirtyable-m
    emory-fix.patch (bnc#940017, bnc#949298, bnc#947128).

  - usb: ftdi_sio: fix race condition in TIOCMIWAIT, and
    abort of TIOCMIWAIT when the device is removed
    (bnc#956375).

  - usb: ftdi_sio: fix status line change handling for
    TIOCMIWAIT and TIOCGICOUNT (bnc#956375).

  - usb: ftdi_sio: fix tiocmget and tiocmset return values
    (bnc#956375).

  - usb: ftdi_sio: fix tiocmget indentation (bnc#956375).

  - usb: ftdi_sio: optimise chars_in_buffer (bnc#956375).

  - usb: ftdi_sio: refactor modem-control status retrieval
    (bnc#956375).

  - usb: ftdi_sio: remove unnecessary memset (bnc#956375).

  - usb: ftdi_sio: use ftdi_get_modem_status in
    chars_in_buffer (bnc#956375).

  - usb: ftdi_sio: use generic chars_in_buffer (bnc#956375).

  - usb: serial: export usb_serial_generic_chars_in_buffer
    (bnc#956375).

  - usb: serial: ftdi_sio: Add missing chars_in_buffer
    function (bnc#956375).

  - usbvision fix overflow of interfaces array (bnc#950998).

  - veth: extend device features (bsc#879381).

  - vfs: Provide function to get superblock and wait for it
    to thaw (bsc#935123).

  - vmxnet3: adjust ring sizes when interface is down
    (bsc#950750).

  - vmxnet3: fix building without CONFIG_PCI_MSI
    (bsc#958912).

  - vmxnet3: fix ethtool ring buffer size setting
    (bsc#950750).

  - vmxnet3: fix netpoll race condition (bsc#958912).

  - writeback: Skip writeback for frozen filesystem
    (bsc#935123).

  - x86/evtchn: make use of PHYSDEVOP_map_pirq.

  - x86, kvm: fix kvm's usage of kernel_fpu_begin/end()
    (bsc#961518).

  - x86, kvm: fix maintenance of guest/host xcr0 state
    (bsc#961518).

  - x86, kvm: use kernel_fpu_begin/end() in
    kvm_load/put_guest_fpu() (bsc#961518).

  - x86/mce: Fix return value of mce_chrdev_read() when erst
    is disabled (bsc#934787).

  - xen/panic/x86: Allow cpus to save registers even if they
    (bnc#940946).

  - xen/panic/x86: Fix re-entrance problem due to panic on
    (bnc#937444).

  - xen: x86: mm: drop TLB flush from ptep_set_access_flags
    (bsc#948330).

  - xen: x86: mm: only do a local tlb flush in
    ptep_set_access_flags() (bsc#948330).

  - xfrm: do not segment UFO packets (bsc#946122).

  - xhci: silence TD warning (bnc#939955).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/758040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/781018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/879378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/879381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/946122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/948330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955308"
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
    value:"https://bugzilla.suse.com/955673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956949"
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
    value:"https://bugzilla.suse.com/958906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960857"
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
    value:"https://bugzilla.suse.com/961512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963276"
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
    value:"https://bugzilla.suse.com/963998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-7446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7509.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7515.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7566.html"
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
    value:"https://www.suse.com/security/cve/CVE-2015-8552.html"
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
    value:"https://www.suse.com/security/cve/CVE-2015-8816.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0723.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2069.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2143.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2186.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2384.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2543.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2544.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2545.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2546.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2548.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2549.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2782.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2847.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3137.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3138.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3139.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3140.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3156.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3955.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161203-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b11f173"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5 :

zypper in -t patch sleclo50sp3-kernel-20160414-12537=1

SUSE Manager Proxy 2.1 :

zypper in -t patch slemap21-kernel-20160414-12537=1

SUSE Manager 2.1 :

zypper in -t patch sleman21-kernel-20160414-12537=1

SUSE Linux Enterprise Server 11-SP3-LTSS :

zypper in -t patch slessp3-kernel-20160414-12537=1

SUSE Linux Enterprise Server 11-EXTRA :

zypper in -t patch slexsp3-kernel-20160414-12537=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-kernel-20160414-12537=1

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/04");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-base-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-base-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-devel-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-source-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-syms-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-base-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-devel-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.79.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.79.1")) flag++;


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
