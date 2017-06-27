#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0911-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(90264);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2013-7446", "CVE-2015-7515", "CVE-2015-7550", "CVE-2015-8539", "CVE-2015-8543", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8767", "CVE-2015-8785", "CVE-2015-8812", "CVE-2016-0723", "CVE-2016-2069", "CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549");
  script_osvdb_id(130525, 130648, 131666, 131683, 131685, 131735, 131951, 131952, 132029, 132030, 132031, 132811, 133409, 133625, 134512, 134538, 134915, 134916, 134917, 134918, 134919, 134920);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : kernel (SUSE-SU-2016:0911-1)");
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

Following feature was added to kernel-xen :

  - A improved XEN blkfront module was added, which allows
    more I/O bandwidth. (FATE#320200) It is called
    xen-blkfront in PV, and xen-vbd-upstream in HVM mode.

The following security bugs were fixed :

  - CVE-2013-7446: Use-after-free vulnerability in
    net/unix/af_unix.c in the Linux kernel allowed local
    users to bypass intended AF_UNIX socket permissions or
    cause a denial of service (panic) via crafted epoll_ctl
    calls (bnc#955654).

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

  - CVE-2015-8550: Compiler optimizations in the XEN PV
    backend drivers could have lead to double fetch
    vulnerabilities, causing denial of service or arbitrary
    code execution (depending on the configuration)
    (bsc#957988).

  - CVE-2015-8551, CVE-2015-8552: xen/pciback: For
    XEN_PCI_OP_disable_msi[|x] only disable if device has
    MSI(X) enabled (bsc#957990).

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
    (bnc#959190 bnc#959399).

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
    cause machine crashes or potentially code execution
    (bsc#966437).

  - CVE-2016-0723: Race condition in the tty_ioctl function
    in drivers/tty/tty_io.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory or cause a denial of service (use-after-free and
    system crash) by making a TIOCGETD ioctl call during
    processing of a TIOCSETD ioctl call (bnc#961500).

  - CVE-2016-2069: Race conditions in TLB syncing was fixed
    which could leak to information leaks (bnc#963767).

  - CVE-2016-2384: Removed a double free in the ALSA
    usb-audio driver in the umidi object which could lead to
    crashes (bsc#966693).

  - CVE-2016-2543: Added a missing NULL check at
    remove_events ioctl in ALSA that could lead to crashes.
    (bsc#967972).

  - CVE-2016-2544, CVE-2016-2545, CVE-2016-2546,
    CVE-2016-2547, CVE-2016-2548, CVE-2016-2549: Various
    race conditions in ALSAs timer handling were fixed.
    (bsc#967975, bsc#967974, bsc#967973, bsc#968011,
    bsc#968012, bsc#968013).

The following non-security bugs were fixed :

  - alsa: hda - Add one more node in the EAPD supporting
    candidate list (bsc#963561).

  - alsa: hda - Apply clock gate workaround to Skylake, too
    (bsc#966137).

  - alsa: hda - Fix playback noise with 24/32 bit sample
    size on BXT (bsc#966137).

  - alsa: hda - disable dynamic clock gating on Broxton
    before reset (bsc#966137).

  - Add /etc/modprobe.d/50-xen.conf selecting Xen frontend
    driver implementation (bsc#957986, bsc#956084,
    bsc#961658).

  - Fix handling of re-write-before-commit for mmapped NFS
    pages (bsc#964201).

  - nfsv4: Recovery of recalled read delegations is broken
    (bsc#956514).

  - nvme: default to 4k device page size (bsc#967042).

  - pci: leave MEM and IO decoding disabled during 64-bit
    BAR sizing, too (bsc#951815).

  - Refresh
    patches.xen/xen3-08-x86-ldt-make-modify_ldt-synchronous.
    patch (bsc#959705).

  - Refresh patches.xen/xen-vscsi-large-requests (refine fix
    and also address bsc#966094).

  - sunrpc: restore fair scheduling to priority queues
    (bsc#955308).

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

  - usb: pl2303: clean up line-status handling (bnc#959649).

  - usb: pl2303: only wake up MSR queue on changes
    (bnc#959649).

  - usb: pl2303: remove bogus delta_msr_wait wake up
    (bnc#959649).

  - usb: serial: export usb_serial_generic_chars_in_buffer
    (bnc#956375).

  - Update
    patches.fixes/mm-exclude-reserved-pages-from-dirtyable-m
    emory-fix.patch (bnc#940017, bnc#949298, bnc#947128).

  - xen: Update Xen config files (enable upstream block
    frontend).

  - ec2: Update kabi files and start tracking ec2

  - xen: consolidate and simplify struct xenbus_driver
    instantiation (bsc#961658 fate#320200).

  - blktap: also call blkif_disconnect() when frontend
    switched to closed (bsc#952976).

  - blktap: refine mm tracking (bsc#952976).

  - block: Always check queue limits for cloned requests
    (bsc#933782).

  - block: xen-blkfront: Fix possible NULL ptr dereference
    (bsc#961658 fate#320200).

  - bnx2x: Add new device ids under the Qlogic vendor
    (bsc#964818).

  - bnx2x: Alloc 4k fragment for each rx ring buffer element
    (bsc#953369).

  - bnx2x: fix DMA API usage (bsc#953369).

  - driver core: Add BUS_NOTIFY_REMOVED_DEVICE event
    (bnc#962965).

  - driver: xen-blkfront: move talk_to_blkback to a more
    suitable place (bsc#961658 fate#320200).

  - drivers: xen-blkfront: only talk_to_blkback() when in
    XenbusStateInitialising (bsc#961658 fate#320200).

  - drm/i915: Change semantics of hw_contexts_disabled
    (bsc#963276).

  - drm/i915: Evict CS TLBs between batches (bsc#758040).

  - drm/i915: Fix SRC_COPY width on 830/845g (bsc#758040).

  - e1000e: Do not read ICR in Other interrupt (bsc#924919).

  - e1000e: Do not write lsc to ics in msi-x mode
    (bsc#924919).

  - e1000e: Fix msi-x interrupt automask (bsc#924919).

  - e1000e: Remove unreachable code (bsc#924919).

  - ext3: NULL dereference in ext3_evict_inode()
    (bsc#942082).

  - ext3: fix data=journal fast mount/umount hang
    (bsc#942082).

  - firmware: Create directories for external firmware
    (bsc#959312).

  - firmware: Simplify directory creation (bsc#959312).

  - ftdi_sio: private backport of TIOCMIWAIT (bnc#956375).

  - iommu/vt-d: Do not change dma domain on dma-mask change
    (bsc#955925).

  - jbd: Fix unreclaimed pages after truncate in
    data=journal mode (bsc#961516).

  - kabi/severities: Add exception for
    bnx2x_schedule_sp_rtnl() There is no external, 3rd party
    modules use the symbol and the bnx2x_schedule_sp_rtnl
    symbol is only used in the bnx2x driver. (bsc#953369)

  - kbuild: create directory for dir/file.o (bsc#959312).

  - llist/xen-blkfront: implement safe version of
    llist_for_each_entry (bsc#961658 fate#320200).

  - lpfc: Fix null ndlp dereference in target_reset_handler
    (bsc#951392).

  - mm-memcg-print-statistics-from-live-counters-fix
    (bnc#969307).

  - nvme: Clear BIO_SEG_VALID flag in nvme_bio_split()
    (bsc#954992).

  - pci: Update VPD size with correct length (bsc#958906).

  - pl2303: fix TIOCMIWAIT (bnc#959649).

  - pl2303: introduce private disconnect method
    (bnc#959649).

  - qeth: initialize net_device with carrier off
    (bnc#958000, LTC#136514).

  - s390/cio: collect format 1 channel-path description data
    (bnc#958000, LTC#136434).

  - s390/cio: ensure consistent measurement state
    (bnc#958000, LTC#136434).

  - s390/cio: fix measurement characteristics memleak
    (bnc#958000, LTC#136434).

  - s390/cio: update measurement characteristics
    (bnc#958000, LTC#136434).

  - s390/dasd: fix failfast for disconnected devices
    (bnc#958000, LTC#135138).

  - s390/sclp: Determine HSA size dynamically for zfcpdump
    (bnc#958000, LTC#136143).

  - s390/sclp: Move declarations for sclp_sdias into
    separate header file (bnc#958000, LTC#136143).

  - scsi_dh_rdac: always retry MODE SELECT on command lock
    violation (bsc#956949).

  - supported.conf: Add xen-blkfront.

  - tg3: 5715 does not link up when autoneg off
    (bsc#904035).

  - usb: serial: ftdi_sio: Add missing chars_in_buffer
    function (bnc#956375).

  - vmxnet3: fix building without CONFIG_PCI_MSI
    (bsc#958912).

  - vmxnet3: fix netpoll race condition (bsc#958912).

  - xen, blkfront: factor out flush-related checks from
    do_blkif_request() (bsc#961658 fate#320200).

  - xen-blkfront: Handle discard requests (bsc#961658
    fate#320200).

  - xen-blkfront: If no barrier or flush is supported, use
    invalid operation (bsc#961658 fate#320200).

  - xen-blkfront: Introduce a 'max' module parameter to
    alter the amount of indirect segments (bsc#961658
    fate#320200).

  - xen-blkfront: Silence pfn maybe-uninitialized warning
    (bsc#961658 fate#320200).

  - xen-blkfront: allow building in our Xen environment
    (bsc#961658 fate#320200).

  - xen-blkfront: check for null drvdata in blkback_changed
    (XenbusStateClosing) (bsc#961658 fate#320200).

  - xen-blkfront: do not add indirect pages to list when
    !feature_persistent (bsc#961658 fate#320200).

  - xen-blkfront: drop the use of llist_for_each_entry_safe
    (bsc#961658 fate#320200).

  - xen-blkfront: fix a deadlock while handling discard
    response (bsc#961658 fate#320200).

  - xen-blkfront: fix accounting of reqs when migrating
    (bsc#961658 fate#320200).

  - xen-blkfront: free allocated page (bsc#961658
    fate#320200).

  - xen-blkfront: handle backend CLOSED without CLOSING
    (bsc#961658 fate#320200).

  - xen-blkfront: handle bvecs with partial data (bsc#961658
    fate#320200).

  - xen-blkfront: improve aproximation of required grants
    per request (bsc#961658 fate#320200).

  - xen-blkfront: make blkif_io_lock spinlock per-device
    (bsc#961658 fate#320200).

  - xen-blkfront: plug device number leak in xlblk_init()
    error path (bsc#961658 fate#320200).

  - xen-blkfront: pre-allocate pages for requests
    (bsc#961658 fate#320200).

  - xen-blkfront: remove frame list from blk_shadow
    (bsc#961658 fate#320200).

  - xen-blkfront: remove type check from
    blkfront_setup_discard (bsc#961658 fate#320200).

  - xen-blkfront: restore the non-persistent data path
    (bsc#961658 fate#320200).

  - xen-blkfront: revoke foreign access for grants not
    mapped by the backend (bsc#961658 fate#320200).

  - xen-blkfront: set blk_queue_max_hw_sectors correctly
    (bsc#961658 fate#320200).

  - xen-blkfront: switch from llist to list (bsc#961658
    fate#320200).

  - xen-blkfront: use a different scatterlist for each
    request (bsc#961658 fate#320200).

  - xen-block: implement indirect descriptors (bsc#961658
    fate#320200).

  - xen/blk[front|back]: Enhance discard support with secure
    erasing support (bsc#961658 fate#320200).

  - xen/blk[front|back]: Squash blkif_request_rw and
    blkif_request_discard together (bsc#961658 fate#320200).

  - xen/blkback: Persistent grant maps for xen blk drivers
    (bsc#961658 fate#320200).

  - xen/blkback: persistent-grants fixes (bsc#961658
    fate#320200).

  - xen/blkfront: Fix crash if backend does not follow the
    right states (bsc#961658 fate#320200).

  - xen/blkfront: do not put bdev right after getting it
    (bsc#961658 fate#320200).

  - xen/blkfront: improve protection against issuing
    unsupported REQ_FUA (bsc#961658 fate#320200).

  - xen/blkfront: remove redundant flush_op (bsc#961658
    fate#320200).

  - xen/panic/x86: Allow cpus to save registers even if they
    (bnc#940946).

  - xen/panic/x86: Fix re-entrance problem due to panic on
    (bnc#937444).

  - xen/pvhvm: If xen_platform_pci=0 is set do not blow up
    (v4) (bsc#961658 fate#320200).

  - xen/x86/mm: Add barriers and document
    switch_mm()-vs-flush synchronization (bnc#963767).

  - xen: x86: mm: drop TLB flush from ptep_set_access_flags
    (bsc#948330).

  - xen: x86: mm: only do a local tlb flush in
    ptep_set_access_flags() (bsc#948330).

  - xfs: Skip dirty pages in ->releasepage (bnc#912738,
    bnc#915183).

  - zfcp: fix fc_host port_type with NPIV (bnc#958000,
    LTC#132479).

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
    value:"https://bugzilla.suse.com/904035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/912738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942082"
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
    value:"https://bugzilla.suse.com/951392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954992"
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
    value:"https://bugzilla.suse.com/955837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956084"
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
    value:"https://bugzilla.suse.com/956708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957986"
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
    value:"https://bugzilla.suse.com/958000"
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
    value:"https://bugzilla.suse.com/959649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959705"
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
    value:"https://bugzilla.suse.com/961658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963561"
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
    value:"https://bugzilla.suse.com/964818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966137"
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
    value:"https://bugzilla.suse.com/967042"
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
    value:"https://bugzilla.suse.com/969307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-7446.html"
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
    value:"https://www.suse.com/security/cve/CVE-2016-0723.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2069.html"
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
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160911-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81a9d365"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-kernel-201603-12480=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-kernel-201603-12480=1

SUSE Linux Enterprise Server 11-EXTRA :

zypper in -t patch slexsp3-kernel-201603-12480=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-kernel-201603-12480=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-kernel-201603-12480=1

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"kernel-default-man-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-source-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-syms-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-extra-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-source-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-syms-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-extra-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-source-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-syms-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-trace-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-extra-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-extra-3.0.101-71.1")) flag++;


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
