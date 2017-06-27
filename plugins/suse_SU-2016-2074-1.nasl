#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2074-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93289);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2013-2015", "CVE-2013-7446", "CVE-2015-0272", "CVE-2015-3339", "CVE-2015-5307", "CVE-2015-6252", "CVE-2015-6937", "CVE-2015-7509", "CVE-2015-7515", "CVE-2015-7550", "CVE-2015-7566", "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8104", "CVE-2015-8215", "CVE-2015-8539", "CVE-2015-8543", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8767", "CVE-2015-8785", "CVE-2015-8812", "CVE-2015-8816", "CVE-2016-0723", "CVE-2016-2069", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549", "CVE-2016-2782", "CVE-2016-2847", "CVE-2016-3134", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3139", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-4486");
  script_bugtraq_id(59512, 74243);
  script_osvdb_id(92851, 121170, 126403, 127518, 127759, 128845, 129330, 130089, 130090, 130525, 130648, 131666, 131683, 131685, 131735, 131951, 131952, 132202, 132748, 132811, 133409, 133625, 134512, 134538, 134915, 134916, 134917, 134918, 134919, 134920, 134938, 135143, 135194, 135678, 135871, 135872, 135873, 135874, 135875, 135876, 135877, 135878, 135943, 135975, 138093);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2016:2074-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP2 kernel was updated to receive various
security and bug fixes. The following security bugs were fixed :

  - CVE-2016-4486: Fixed 4 byte information leak in
    net/core/rtnetlink.c (bsc#978822).

  - CVE-2016-3134: The netfilter subsystem in the Linux
    kernel did not validate certain offset fields, which
    allowed local users to gain privileges or cause a denial
    of service (heap memory corruption) via an
    IPT_SO_SET_REPLACE setsockopt call (bnc#971126).

  - CVE-2016-2847: fs/pipe.c in the Linux kernel did not
    limit the amount of unread data in pipes, which allowed
    local users to cause a denial of service (memory
    consumption) by creating many pipes with non-default
    sizes (bnc#970948).

  - CVE-2016-2188: The iowarrior_probe function in
    drivers/usb/misc/iowarrior.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a crafted endpoints value in a USB device descriptor
    (bnc#970956).

  - CVE-2016-3138: The acm_probe function in
    drivers/usb/class/cdc-acm.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a USB device without both a control and a data endpoint
    descriptor (bnc#970911).

  - CVE-2016-3137: drivers/usb/serial/cypress_m8.c in the
    Linux kernel allowed physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a USB device without both an
    interrupt-in and an interrupt-out endpoint descriptor,
    related to the cypress_generic_port_probe and
    cypress_open functions (bnc#970970).

  - CVE-2016-3140: The digi_port_init function in
    drivers/usb/serial/digi_acceleport.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970892).

  - CVE-2016-2186: The powermate_probe function in
    drivers/input/misc/powermate.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970958).

  - CVE-2016-2185: The ati_remote2_probe function in
    drivers/input/misc/ati_remote2.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#971124).

  - CVE-2016-3156: The IPv4 implementation in the Linux
    kernel mishandles destruction of device objects, which
    allowed guest OS users to cause a denial of service
    (host OS networking outage) by arranging for a large
    number of IP addresses (bnc#971360).

  - CVE-2016-2184: The create_fixed_stream_quirk function in
    sound/usb/quirks.c in the snd-usb-audio driver in the
    Linux kernel allowed physically proximate attackers to
    cause a denial of service (NULL pointer dereference or
    double free, and system crash) via a crafted endpoints
    value in a USB device descriptor (bnc#971125).

  - CVE-2016-3139: The wacom_probe function in
    drivers/input/tablet/wacom_sys.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970909).

  - CVE-2016-2143: The fork implementation in the Linux
    kernel on s390 platforms mishandled the case of four
    page-table levels, which allowed local users to cause a
    denial of service (system crash) or possibly have
    unspecified other impact via a crafted application,
    related to arch/s390/include/asm/mmu_context.h and
    arch/s390/include/asm/pgalloc.h (bnc#970504).

  - CVE-2016-2782: The treo_attach function in
    drivers/usb/serial/visor.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) or
    possibly have unspecified other impact by inserting a
    USB device that lacks a (1) bulk-in or (2) interrupt-in
    endpoint (bnc#968670).

  - CVE-2015-8816: The hub_activate function in
    drivers/usb/core/hub.c in the Linux kernel did not
    properly maintain a hub-interface data structure, which
    allowed physically proximate attackers to cause a denial
    of service (invalid memory access and system crash) or
    possibly have unspecified other impact by unplugging a
    USB hub device (bnc#968010).

  - CVE-2015-7566: The clie_5_attach function in
    drivers/usb/serial/visor.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) or
    possibly have unspecified other impact by inserting a
    USB device that lacks a bulk-out endpoint (bnc#961512).

  - CVE-2016-2549: sound/core/hrtimer.c in the Linux kernel
    did not prevent recursive callback access, which allowed
    local users to cause a denial of service (deadlock) via
    a crafted ioctl call (bnc#968013).

  - CVE-2016-2547: sound/core/timer.c in the Linux kernel
    employed a locking approach that did not consider slave
    timer instances, which allowed local users to cause a
    denial of service (race condition, use-after-free, and
    system crash) via a crafted ioctl call (bnc#968011).

  - CVE-2016-2548: sound/core/timer.c in the Linux kernel
    retained certain linked lists after a close or stop
    action, which allowed local users to cause a denial of
    service (system crash) via a crafted ioctl call, related
    to the (1) snd_timer_close and (2) _snd_timer_stop
    functions (bnc#968012).

  - CVE-2016-2546: sound/core/timer.c in the Linux kernel
    used an incorrect type of mutex, which allowed local
    users to cause a denial of service (race condition,
    use-after-free, and system crash) via a crafted ioctl
    call (bnc#967975).

  - CVE-2016-2545: The snd_timer_interrupt function in
    sound/core/timer.c in the Linux kernel did not properly
    maintain a certain linked list, which allowed local
    users to cause a denial of service (race condition and
    system crash) via a crafted ioctl call (bnc#967974).

  - CVE-2016-2544: Race condition in the queue_delete
    function in sound/core/seq/seq_queue.c in the Linux
    kernel allowed local users to cause a denial of service
    (use-after-free and system crash) by making an ioctl
    call at a certain time (bnc#967973).

  - CVE-2016-2543: The snd_seq_ioctl_remove_events function
    in sound/core/seq/seq_clientmgr.c in the Linux kernel
    did not verify FIFO assignment before proceeding with
    FIFO clearing, which allowed local users to cause a
    denial of service (NULL pointer dereference and OOPS)
    via a crafted ioctl call (bnc#967972).

  - CVE-2016-2384: Double free vulnerability in the
    snd_usbmidi_create function in sound/usb/midi.c in the
    Linux kernel allowed physically proximate attackers to
    cause a denial of service (panic) or possibly have
    unspecified other impact via vectors involving an
    invalid USB descriptor (bnc#966693).

  - CVE-2015-8812: drivers/infiniband/hw/cxgb3/iwch_cm.c in
    the Linux kernel did not properly identify error
    conditions, which allowed remote attackers to execute
    arbitrary code or cause a denial of service
    (use-after-free) via crafted packets (bnc#966437).

  - CVE-2015-8785: The fuse_fill_write_pages function in
    fs/fuse/file.c in the Linux kernel allowed local users
    to cause a denial of service (infinite loop) via a
    writev system call that triggers a zero length for the
    first segment of an iov (bnc#963765).

  - CVE-2016-2069: Race condition in arch/x86/mm/tlb.c in
    the Linux kernel .4.1 allowed local users to gain
    privileges by triggering access to a paging structure by
    a different CPU (bnc#963767).

  - CVE-2016-0723: Race condition in the tty_ioctl function
    in drivers/tty/tty_io.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory or cause a denial of service (use-after-free and
    system crash) by making a TIOCGETD ioctl call during
    processing of a TIOCSETD ioctl call (bnc#961500).

  - CVE-2013-7446: Use-after-free vulnerability in
    net/unix/af_unix.c in the Linux kernel allowed local
    users to bypass intended AF_UNIX socket permissions or
    cause a denial of service (panic) via crafted epoll_ctl
    calls (bnc#955654).

  - CVE-2015-8767: net/sctp/sm_sideeffect.c in the Linux
    kernel did not properly manage the relationship between
    a lock and a socket, which allowed local users to cause
    a denial of service (deadlock) via a crafted sctp_accept
    call (bnc#961509).

  - CVE-2015-7515: The aiptek_probe function in
    drivers/input/tablet/aiptek.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted USB device that lacks endpoints
    (bnc#956708).

  - CVE-2015-8215: net/ipv6/addrconf.c in the IPv6 stack in
    the Linux kernel did not validate attempted changes to
    the MTU value, which allowed context-dependent attackers
    to cause a denial of service (packet loss) via a value
    that is (1) smaller than the minimum compliant value or
    (2) larger than the MTU of an interface, as demonstrated
    by a Router Advertisement (RA) message that is not
    validated by a daemon, a different vulnerability than
    CVE-2015-0272 (bnc#955354).

  - CVE-2015-7550: The keyctl_read_key function in
    security/keys/keyctl.c in the Linux kernel did not
    properly use a semaphore, which allowed local users to
    cause a denial of service (NULL pointer dereference and
    system crash) or possibly have unspecified other impact
    via a crafted application that leverages a race
    condition between keyctl_revoke and keyctl_read calls
    (bnc#958951).

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

  - CVE-2015-8543: The networking implementation in the
    Linux kernel did not validate protocol identifiers for
    certain protocol families, which allowed local users to
    cause a denial of service (NULL function pointer
    dereference and system crash) or possibly gain
    privileges by leveraging CLONE_NEWUSER support to
    execute a crafted SOCK_RAW application (bnc#958886).

  - CVE-2015-8539: The KEYS subsystem in the Linux kernel
    allowed local users to gain privileges or cause a denial
    of service (BUG) via crafted keyctl commands that
    negatively instantiate a key, related to
    security/keys/encrypted-keys/encrypted.c,
    security/keys/trusted.c, and
    security/keys/user_defined.c (bnc#958463).

  - CVE-2015-7509: fs/ext4/namei.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (system crash) via a crafted no-journal
    filesystem, a related issue to CVE-2013-2015
    (bnc#956709).

  - CVE-2015-7799: The slhc_init function in
    drivers/net/slip/slhc.c in the Linux kernel did not
    ensure that certain slot numbers are valid, which
    allowed local users to cause a denial of service (NULL
    pointer dereference and system crash) via a crafted
    PPPIOCSMAXCID ioctl call (bnc#949936).

  - CVE-2015-8104: The KVM subsystem in the Linux kernel
    allowed guest OS users to cause a denial of service
    (host OS panic or hang) by triggering many #DB (aka
    Debug) exceptions, related to svm.c (bnc#954404).

  - CVE-2015-5307: The KVM subsystem in the Linux kernel
    allowed guest OS users to cause a denial of service
    (host OS panic or hang) by triggering many #AC (aka
    Alignment Check) exceptions, related to svm.c and vmx.c
    (bnc#953527).

  - CVE-2015-7990: Race condition in the rds_sendmsg
    function in net/rds/sendmsg.c in the Linux kernel
    allowed local users to cause a denial of service (NULL
    pointer dereference and system crash) or possibly have
    unspecified other impact by using a socket that was not
    properly bound (bnc#952384).

  - CVE-2015-7872: The key_gc_unused_keys function in
    security/keys/gc.c in the Linux kernel allowed local
    users to cause a denial of service (OOPS) via crafted
    keyctl commands (bnc#951440).

  - CVE-2015-6937: The __rds_conn_create function in
    net/rds/connection.c in the Linux kernel allowed local
    users to cause a denial of service (NULL pointer
    dereference and system crash) or possibly have
    unspecified other impact by using a socket that was not
    properly bound (bnc#945825).

  - CVE-2015-6252: The vhost_dev_ioctl function in
    drivers/vhost/vhost.c in the Linux kernel allowed local
    users to cause a denial of service (memory consumption)
    via a VHOST_SET_LOG_FD ioctl call that triggers
    permanent file-descriptor allocation (bnc#942367).

  - CVE-2015-3339: Race condition in the prepare_binprm
    function in fs/exec.c in the Linux kernel allowed local
    users to gain privileges by executing a setuid program
    at a time instant when a chown to root is in progress,
    and the ownership is changed but the setuid bit is not
    yet stripped (bnc#928130). The following non-security
    bugs were fixed :

  - Fix handling of re-write-before-commit for mmapped NFS
    pages (bsc#964201).

  - Fix lpfc_send_rscn_event allocation size claims
    bnc#935757

  - Fix ntpd clock synchronization in Xen PV domains
    (bnc#816446).

  - Fix vmalloc_fault oops during lazy MMU updates
    (bsc#948562).

  - Make sure XPRT_CONNECTING gets cleared when needed
    (bsc#946309).

  - SCSI: bfa: Fix to handle firmware tskim abort request
    response (bsc#972510).

  - USB: usbip: fix potential out-of-bounds write
    (bnc#975945).

  - af_unix: Guard against other == sk in unix_dgram_sendmsg
    (bsc#973570).

  - dm-snap: avoid deadock on s->lock when a read is split
    (bsc#939826).

  - mm/hugetlb: check for pte NULL pointer in
    __page_check_address() (bsc#977847).

  - nf_conntrack: fix bsc#758540 kabi fix (bsc#946117).

  - privcmd: allow preempting long running user-mode
    originating hypercalls (bnc#861093).

  - s390/cio: collect format 1 channel-path description data
    (bsc#966460, bsc#966662).

  - s390/cio: ensure consistent measurement state
    (bsc#966460, bsc#966662).

  - s390/cio: fix measurement characteristics memleak
    (bsc#966460, bsc#966662).

  - s390/cio: update measurement characteristics
    (bsc#966460, bsc#966662).

  - xfs: Fix lost direct IO write in the last block
    (bsc#949744).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/816446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/861093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/946117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/946309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/948562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954404"
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
    value:"https://bugzilla.suse.com/956708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956709"
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
    value:"https://bugzilla.suse.com/959190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959399"
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
    value:"https://bugzilla.suse.com/963765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966693"
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
    value:"https://bugzilla.suse.com/968670"
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
    value:"https://bugzilla.suse.com/971126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-2015.html"
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
    value:"https://www.suse.com/security/cve/CVE-2015-3339.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5307.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6252.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6937.html"
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
    value:"https://www.suse.com/security/cve/CVE-2015-7872.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7990.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8104.html"
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
    value:"https://www.suse.com/security/cve/CVE-2016-3134.html"
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
    value:"https://www.suse.com/security/cve/CVE-2016-4486.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162074-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2996c2e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-kernel-source-12693=1

SUSE Linux Enterprise Debuginfo 11-SP2:zypper in -t patch
dbgsp2-kernel-source-12693=1

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-base-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-devel-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-source-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-syms-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-base-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-devel-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.7.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.7.40.1")) flag++;


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
