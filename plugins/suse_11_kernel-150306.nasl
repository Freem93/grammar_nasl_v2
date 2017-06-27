#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82020);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/24 13:22:29 $");

  script_cve_id("CVE-2010-5313", "CVE-2013-7263", "CVE-2014-0181", "CVE-2014-3601", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-3690", "CVE-2014-4608", "CVE-2014-7822", "CVE-2014-7842", "CVE-2014-7970", "CVE-2014-8133", "CVE-2014-8134", "CVE-2014-8160", "CVE-2014-8369", "CVE-2014-8559", "CVE-2014-9090", "CVE-2014-9322", "CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9584", "CVE-2014-9585", "CVE-2015-1593");

  script_name(english:"SuSE 11.3 Security Update : Linux Kernel (SAT Patch Numbers 10412 / 10415 / 10416)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP3 kernel has been updated to receive
various security and bugfixes.

New features enabled :

  - The Ceph and rbd remote network block device drivers are
    now enabled and supported, to serve as client for SUSE
    Enterprise Storage 1.0. (FATE#318328)

  - Support to selected Bay Trail CPUs used in Point of
    Service Hardware was enabled. (FATE#317933)

  - Broadwell Legacy Audio, HDMI Audio and DisplayPort Audio
    support (Audio Driver: HD-A HDMI/DP Audio/HDA
    Analog/DSP) was enabled. (FATE#317347)

The following security bugs have been fixed :

  - An integer overflow in the stack randomization on 64-bit
    systems lead to less effective stack ASLR on those
    systems. (bsc#917839). (CVE-2015-1593)

  - iptables rules could be bypassed if the specific network
    protocol module was not loaded, allowing e.g. SCTP to
    bypass the firewall if the sctp protocol was not
    enabled. (bsc#913059). (CVE-2014-8160)

  - A flaw was found in the way the Linux kernels splice()
    system call validated its parameters. On certain file
    systems, a local, unprivileged user could have used this
    flaw to write past the maximum file size, and thus crash
    the system. (bnc#915322). (CVE-2014-7822)

  - The __switch_to function in arch/x86/kernel/process_64.c
    in the Linux kernel did not ensure that Thread Local
    Storage (TLS) descriptors are loaded before proceeding
    with other steps, which made it easier for local users
    to bypass the ASLR protection mechanism via a crafted
    application that reads a TLS base address. (bnc#911326).
    (CVE-2014-9419)

  - The parse_rock_ridge_inode_internal function in
    fs/isofs/rock.c in the Linux kernel did not validate a
    length value in the Extensions Reference (ER) System Use
    Field, which allowed local users to obtain sensitive
    information from kernel memory via a crafted iso9660
    image. (bnc#912654). (CVE-2014-9584)

  - The vdso_addr function in arch/x86/vdso/vma.c in the
    Linux kernel did not properly choose memory locations
    for the vDSO area, which made it easier for local users
    to bypass the ASLR protection mechanism by guessing a
    location at the end of a PMD. (bnc#912705).
    (CVE-2014-9585)

  - The d_walk function in fs/dcache.c in the Linux kernel
    did not properly maintain the semantics of rename_lock,
    which allowed local users to cause a denial of service
    (deadlock and system hang) via a crafted application.
    (bnc#903640). (CVE-2014-8559)

  - The rock_continue function in fs/isofs/rock.c in the
    Linux kernel did not restrict the number of Rock Ridge
    continuation entries, which allowed local users to cause
    a denial of service (infinite loop, and system crash or
    hang) via a crafted iso9660 image (bsc#911325).
    (CVE-2014-9420)

  - The paravirt_ops_setup function in arch/x86/kernel/kvm.c
    in the Linux kernel used an improper paravirt_enabled
    setting for KVM guest kernels, which made it easier for
    guest OS users to bypass the ASLR protection mechanism
    via a crafted application that reads a 16-bit value
    (bnc#907818 909077 909078). (CVE-2014-8134)

  - The kvm_iommu_map_pages function in virt/kvm/iommu.c in
    the Linux kernel miscalculated the number of pages
    during the handling of a mapping failure, which allowed
    guest OS users to cause a denial of service (host OS
    page unpinning) or possibly have unspecified other
    impact by leveraging guest OS privileges. NOTE: this
    vulnerability exists because of an incorrect fix for
    CVE-2014-3601 (bsc#902675). (CVE-2014-8369)

  - arch/x86/kvm/vmx.c in the KVM subsystem in the Linux
    kernel on Intel processors did not ensure that the value
    in the CR4 control register remains the same after a VM
    entry, which allowed host OS users to kill arbitrary
    processes or cause a denial of service (system
    disruption) by leveraging /dev/kvm access, as
    demonstrated by PR_SET_TSC prctl calls within a modified
    copy of QEMU. (bnc#902232). (CVE-2014-3690)

  - Race condition in arch/x86/kvm/x86.c in the Linux kernel
    allowed guest OS users to cause a denial of service
    (guest OS crash) via a crafted application that performs
    an MMIO transaction or a PIO transaction to trigger a
    guest userspace emulation error report, a similar issue
    to CVE-2010-5313. (bnc#905312). (CVE-2014-7842)

  - The Netlink implementation in the Linux kernel did not
    provide a mechanism for authorizing socket operations
    based on the opener of a socket, which allowed local
    users to bypass intended access restrictions and modify
    network configurations by using a Netlink socket for the
    (1) stdout or (2) stderr of a setuid program.
    (bnc#875051). (CVE-2014-0181)

  - The SCTP implementation in the Linux kernel allowed
    remote attackers to cause a denial of service (memory
    consumption) by triggering a large number of chunks in
    an associations output queue, as demonstrated by ASCONF
    probes, related to net/sctp/inqueue.c and
    net/sctp/sm_statefuns.c. (bnc#902351). (CVE-2014-3688)

  - The pivot_root implementation in fs/namespace.c in the
    Linux kernel did not properly interact with certain
    locations of a chroot directory, which allowed local
    users to cause a denial of service (mount-tree loop) via
    . (dot) values in both arguments to the pivot_root
    system call. (bnc#900644). (CVE-2014-7970)

  - The sctp_assoc_lookup_asconf_ack function in
    net/sctp/associola.c in the SCTP implementation in the
    Linux kernel allowed remote attackers to cause a denial
    of service (panic) via duplicate ASCONF chunks that
    trigger an incorrect uncork within the side-effect
    interpreter. (bnc#902349, bnc#904899). (CVE-2014-3687)

The following non-security bugs have been fixed :

  - ACPI idle: permit sparse C-state sub-state numbers
    (bnc#908550,FATE#317933).

  - ALSA : hda - not use assigned converters for all unused
    pins (FATE#317933).

  - ALSA: hda - Add Device IDs for Intel Wildcat Point-LP
    PCH (FATE#317347).

  - ALSA: hda - Fix onboard audio on Intel H97/Z97 chipsets
    (FATE#317347).

  - ALSA: hda - add PCI IDs for Intel BayTrail
    (FATE#317347).

  - ALSA: hda - add PCI IDs for Intel Braswell
    (FATE#317347).

  - ALSA: hda - add codec ID for Braswell display audio
    codec (FATE#317933).

  - ALSA: hda - add codec ID for Broadwell display audio
    codec (FATE#317933).

  - ALSA: hda - add codec ID for Valleyview2 display codec
    (FATE#317933).

  - ALSA: hda - define is_haswell() to check if a display
    audio codec is Haswell (FATE#317933).

  - ALSA: hda - hdmi: Re-setup pin and infoframe on plug-in
    on all codecs (FATE#317933).

  - ALSA: hda - not choose assigned converters for unused
    pins of Valleyview (FATE#317933).

  - ALSA: hda - rename function not_share_unassigned_cvt()
    (FATE#317933).

  - ALSA: hda - unmute pin amplifier in infoframe setup for
    Haswell (FATE#317933).

  - ALSA: hda - verify pin:converter connection on unsol
    event for HSW and VLV (FATE#317933).

  - ALSA: hda - verify pin:cvt connection on preparing a
    stream for Intel HDMI codec (FATE#317933).

  - ALSA: hda/hdmi - apply Valleyview fix-ups to Cherryview
    display codec (FATE#317933).

  - ALSA: hda/hdmi - apply all Haswell fix-ups to Broadwell
    display codec (FATE#317933).

  - ALSA: hda_intel: Add Device IDs for Intel Sunrise Point
    PCH (FATE#317347).

  - ALSA: hda_intel: Add DeviceIDs for Sunrise Point-LP
    (FATE#317347).

  - Add support for AdvancedSilicon HID multitouch screen
    (2149:36b1) (FATE#317933).

  - Disable switching to bootsplash at oops/panic.
    (bnc#877593)

  - Do not trigger congestion wait on dirty-but-not-writeout
    pages (VM Performance, bnc#909093, bnc#910517).

  - Fix HDIO_DRIVE_* ioctl() regression. (bnc#833588,
    bnc#905799)

  - Fix Module.supported handling for external modules.
    (bnc#905304)

  - Fix zero freq if frequency is requested too quickly in a
    row. (bnc#908572)

  - Fix zero freq if frequency is requested too quickly in a
    row. (bnc#908572)

  - Fixup kABI after
    patches.fixes/writeback-do-not-sync-data-dirtied-after-s
    ync-start.patch. (bnc#833820)

  - Force native backlight for HP POS machines
    (bnc#908551,FATE#317933).

  - HID: use multi input quirk for 22b9:2968 (FATE#317933).

  - IPoIB: Use a private hash table for path lookup in xmit
    path (bsc#907196).

  - Import kabi files from kernel 3.0.101-0.40

  - KEYS: Fix stale key registration at error path.
    (bnc#908163)

  - NFS: Add sequence_priviliged_ops for
    nfs4_proc_sequence(). (bnc#864401)

  - NFS: do not use STABLE writes during writeback.
    (bnc#816099)

  - NFSv4.1 handle DS stateid errors. (bnc#864401)

  - NFSv4.1: Do not decode skipped layoutgets. (bnc#864411)

  - NFSv4.1: Fix a race in the pNFS return-on-close code.
    (bnc#864409)

  - NFSv4.1: Fix an ABBA locking issue with session and
    state serialisation. (bnc#864409)

  - NFSv4.1: We must release the sequence id when we fail to
    get a session slot. (bnc#864401)

  - NFSv4: Do not accept delegated opens when a delegation
    recall is in effect. (bnc#864409)

  - NFSv4: Ensure correct locking when accessing the '^a'
    list. (bnc#864401)

  - NFSv4: Fix another reboot recovery race. (bnc#916982)

  - Preserve kabi checksum of path_is_under().

  - Refresh
    patches.drivers/HID-multitouch-add-support-for-Atmel-212
    c. Fix the non-working touchsreen. (bnc#909740)

  - Revert 'drm/i915: Calculate correct stolen size for
    GEN7+' (bnc#908550,FATE#317933).

  - SUNRPC: Do not allow low priority tasks to pre-empt
    higher priority ones. (bnc#864401)

  - SUNRPC: When changing the queue priority, ensure that we
    change the owner. (bnc#864401)

  - Setting rbd and libceph as supported drivers
    (bsc#917884)

  - audit: efficiency fix 1: only wake up if queue shorter
    than backlog limit. (bnc#908393)

  - audit: efficiency fix 2: request exclusive wait since
    all need same resource. (bnc#908393)

  - audit: fix endless wait in audit_log_start().
    (bnc#908393)

  - audit: make use of remaining sleep time from
    wait_for_auditd. (bnc#908393)

  - audit: refactor hold queue flush. (bnc#908393)

  - audit: reset audit backlog wait time after error
    recovery. (bnc#908393)

  - audit: wait_for_auditd() should use
    TASK_UNINTERRUPTIBLE. (bnc#908393)

  - block: rbd: use NULL instead of 0 (FATE#318328
    bsc#917884).

  - block: replace strict_strtoul() with kstrtoul()
    (FATE#318328 bsc#917884).

  - bonding: propagate LRO disabling down to slaves.
    (bnc#829110 / bnc#891277 / bnc#904053)

  - cciss: fix broken mutex usage in ioctl. (bnc#910013)

  - ceph: Add necessary clean up if invalid reply received
    in handle_reply() (FATE#318328 bsc#917884).

  - ceph: remove bogus extern (FATE#318328 bsc#917884).

  - config: Disable CONFIG_RCU_FAST_NO_HZ (bnc#884817) This
    option has been verified to be racy vs hotplug, and is
    irrelevant to SLE in any case.

  - coredump: ensure the fpu state is flushed for proper
    multi-threaded core dump. (bnc#904671)

  - crush: CHOOSE_LEAF -> CHOOSELEAF throughout (FATE#318328
    bsc#917884).

  - crush: add SET_CHOOSE_TRIES rule step (FATE#318328
    bsc#917884).

  - crush: add note about r in recursive choose (FATE#318328
    bsc#917884).

  - crush: add set_choose_local_[fallback_]tries steps
    (FATE#318328 bsc#917884).

  - crush: apply chooseleaf_tries to firstn mode too
    (FATE#318328 bsc#917884).

  - crush: attempts -> tries (FATE#318328 bsc#917884).

  - crush: clarify numrep vs endpos (FATE#318328
    bsc#917884).

  - crush: eliminate CRUSH_MAX_SET result size limitation
    (FATE#318328 bsc#917884).

  - crush: factor out (trivial) crush_destroy_rule()
    (FATE#318328 bsc#917884).

  - crush: fix crush_choose_firstn comment (FATE#318328
    bsc#917884).

  - crush: fix some comments (FATE#318328 bsc#917884).

  - crush: generalize descend_once (FATE#318328 bsc#917884).

  - crush: new SET_CHOOSE_LEAF_TRIES command (FATE#318328
    bsc#917884).

  - crush: pass parent r value for indep call (FATE#318328
    bsc#917884).

  - crush: pass weight vector size to map function
    (FATE#318328 bsc#917884).

  - crush: reduce scope of some local variables (FATE#318328
    bsc#917884).

  - crush: return CRUSH_ITEM_UNDEF for failed placements
    with indep (FATE#318328 bsc#917884).

  - crush: strip firstn conditionals out of crush_choose,
    rename (FATE#318328 bsc#917884).

  - crush: use breadth-first search for indep mode
    (FATE#318328 bsc#917884).

  - crypto: add missing crypto module aliases (bsc#914423).

  - crypto: include crypto- module prefix in template
    (bsc#914423).

  - crypto: kernel oops at insmod of the z90crypt device
    driver (bnc#909088, LTC#119591).

  - crypto: prefix module autoloading with 'crypto-'
    (bsc#914423).

  - dm raid: add region_size parameter. (bnc#895841)

  - do not do blind d_drop() in nfs_prime_dcache().
    (bnc#908069 / bnc#896484)

  - drm/cirrus: Fix cirrus drm driver for fbdev + qemu
    (bsc#909846,bnc#856760).

  - drm/i915: split PCI IDs out into i915_drm.h v4
    (bnc#908550,FATE#317933).

  - fix dcache exit scaling. (bnc#876594)

  - infiniband: ipoib: Sanitize neighbour handling in
    ipoib_main.c (bsc#907196).

  - iommu/vt-d: Fix an off-by-one bug in __domain_mapping()
    (bsc#908825).

  - ipoib: Convert over to dev_lookup_neigh_skb()
    (bsc#907196).

  - ipoib: Need to do dst_neigh_lookup_skb() outside of
    priv->lock (bsc#907196).

  - ipv6: fix net reference leak in IPv6 conntrack
    reassembly. (bnc#865419)

  - isofs: Fix unchecked printing of ER records.

  - kABI: protect console include in consolemap.

  - kabi fix. (bnc#864404)

  - kabi, mm: prevent endless growth of anon_vma hierarchy.
    (bnc#904242)

  - kernel/audit.c: avoid negative sleep durations.
    (bnc#908393)

  - kernel: 3215 tty close crash (bnc#915209, LTC#120873).

  - kernel: incorrect clock_gettime result (bnc#915209,
    LTC#121184).

  - kvm: Do not expose MONITOR cpuid as available.
    (bnc#887597)

  - kvm: iommu: Add cond_resched to legacy device assignment
    code. (bnc#910159)

  - libceph: CEPH_OSD_FLAG_* enum update (FATE#318328
    bsc#917884).

  - libceph: add ceph_kv{malloc,free}() and switch to them
    (FATE#318328 bsc#917884).

  - libceph: add ceph_pg_pool_by_id() (FATE#318328
    bsc#917884).

  - libceph: add function to ensure notifies are complete
    (FATE#318328 bsc#917884).

  - libceph: add process_one_ticket() helper (FATE#318328
    bsc#917884).

  - libceph: all features fields must be u64 (FATE#318328
    bsc#917884).

  - libceph: block I/O when PAUSE or FULL osd map flags are
    set (FATE#318328 bsc#917884).

  - libceph: call r_unsafe_callback when unsafe reply is
    received (FATE#318328 bsc#917884).

  - libceph: create_singlethread_workqueue() does not return
    ERR_PTRs (FATE#318328 bsc#917884).

  - libceph: do not hard code max auth ticket len
    (FATE#318328 bsc#917884).

  - libceph: dout() is missing a newline (FATE#318328
    bsc#917884).

  - libceph: factor out logic from ceph_osdc_start_request()
    (FATE#318328 bsc#917884).

  - libceph: fix error handling in ceph_osdc_init()
    (FATE#318328 bsc#917884).

  - libceph: fix preallocation check in get_reply()
    (FATE#318328 bsc#917884).

  - libceph: fix safe completion (FATE#318328 bsc#917884).

  - libceph: follow redirect replies from osds (FATE#318328
    bsc#917884).

  - libceph: follow {read,write}_tier fields on osd request
    submission (FATE#318328 bsc#917884).

  - libceph: gracefully handle large reply messages from the
    mon (FATE#318328 bsc#917884).

  - libceph: introduce and start using oid abstraction
    (FATE#318328 bsc#917884).

  - libceph: rename MAX_OBJ_NAME_SIZE to
    CEPH_MAX_OID_NAME_LEN (FATE#318328 bsc#917884).

  - libceph: rename ceph_msg::front_max to front_alloc_len
    (FATE#318328 bsc#917884).

  - libceph: rename ceph_osd_request::r_{oloc,oid} to
    r_base_{oloc,oid} (FATE#318328 bsc#917884).

  - libceph: rename front to front_len in get_reply()
    (FATE#318328 bsc#917884).

  - libceph: replace ceph_calc_ceph_pg() with
    ceph_oloc_oid_to_pg() (FATE#318328 bsc#917884).

  - libceph: resend all writes after the osdmap loses the
    full flag (FATE#318328 bsc#917884).

  - libceph: start using oloc abstraction (FATE#318328
    bsc#917884).

  - libceph: take map_sem for read in handle_reply()
    (FATE#318328 bsc#917884).

  - libceph: update ceph_features.h (FATE#318328
    bsc#917884).

  - libceph: use CEPH_MON_PORT when the specified port is 0
    (FATE#318328 bsc#917884).

  - libiscsi: Added new boot entries in the session sysfs
    (FATE#316723 bsc#914355)

  - mei: ME hardware reset needs to be synchronized.
    (bnc#876086)

  - mei: add 9 series PCH mei device ids. (bnc#876086)

  - mei: add hw start callback. (bnc#876086)

  - mei: cancel stall timers in mei_reset. (bnc#876086)

  - mei: do not have to clean the state on power up.
    (bnc#876086)

  - mei: limit the number of consecutive resets.
    (bnc#876086)

  - mei: me: add Lynx Point Wellsburg work station device
    id. (bnc#876086)

  - mei: me: clear interrupts on the resume path.
    (bnc#876086)

  - mei: me: do not load the driver if the FW does not
    support MEI interface. (bnc#876086)

  - mei: me: fix hardware reset flow. (bnc#876086)

  - mei: me: read H_CSR after asserting reset. (bnc#876086)

  - mm, vmscan: prevent kswapd livelock due to
    pfmemalloc-throttled process being killed (VM
    Functionality bnc#910150).

  - mm: fix BUG in __split_huge_page_pmd. (bnc#906586)

  - mm: fix corner case in anon_vma endless growing
    prevention. (bnc#904242)

  - mm: prevent endless growth of anon_vma hierarchy.
    (bnc#904242)

  - mm: vmscan: count only dirty pages as congested (VM
    Performance, bnc#910517).

  - net, sunrpc: suppress allocation warning in
    rpc_malloc(). (bnc#904659)

  - net: 8021q/bluetooth/bridge/can/ceph: Remove extern from
    function prototypes (FATE#318328 bsc#917884).

  - net: handle more general stacking in dev_disable_lro().
    (bnc#829110 / bnc#891277 / bnc#904053)

  - netfilter: do not drop packet on insert collision.
    (bnc#907611)

  - nf_conntrack: avoid reference leak in
    __ipv6_conntrack_in(). (bnc#865419)

  - nfs_prime_dcache needs fh to be set. (bnc#908069 /
    bnc#896484)

  - nfsd: fix EXDEV checking in rename. (bnc#915791)

  - pnfs: defer release of pages in layoutget. (bnc#864411)

  - proc_sys_revalidate: fix Oops on NULL nameidata.
    (bnc#907551)

  - qlge: fix an '&amp;&amp;' vs '||' bug (bsc#912171).

  - rbd: Fix error recovery in rbd_obj_read_sync()
    (FATE#318328 bsc#917884).

  - rbd: Use min_t() to fix comparison of distinct pointer
    types warning (FATE#318328 bsc#917884).

  - rbd: add 'minor' sysfs rbd device attribute (FATE#318328
    bsc#917884).

  - rbd: add support for single-major device number
    allocation scheme (FATE#318328 bsc#917884).

  - rbd: clean up a few things in the refresh path
    (FATE#318328 bsc#917884).

  - rbd: complete notifies before cleaning up osd_client and
    rbd_dev (FATE#318328 bsc#917884).

  - rbd: do not destroy ceph_opts in rbd_add() (FATE#318328
    bsc#917884).

  - rbd: do not hold ctl_mutex to get/put device
    (FATE#318328 bsc#917884).

  - rbd: drop an unsafe assertion (FATE#318328 bsc#917884).

  - rbd: drop original request earlier for existence check
    (FATE#318328 bsc#917884).

  - rbd: enable extended devt in single-major mode
    (FATE#318328 bsc#917884).

  - rbd: fetch object order before using it (FATE#318328
    bsc#917884).

  - rbd: fix I/O error propagation for reads (FATE#318328
    bsc#917884).

  - rbd: fix a couple warnings (FATE#318328 bsc#917884).

  - rbd: fix buffer size for writes to images with snapshots
    (FATE#318328 bsc#917884).

  - rbd: fix cleanup in rbd_add() (FATE#318328 bsc#917884).

  - rbd: fix error handling from rbd_snap_name()
    (FATE#318328 bsc#917884).

  - rbd: fix error paths in rbd_img_request_fill()
    (FATE#318328 bsc#917884).

  - rbd: fix null dereference in dout (FATE#318328
    bsc#917884).

  - rbd: fix use-after free of rbd_dev->disk (FATE#318328
    bsc#917884).

  - rbd: flush dcache after zeroing page data (FATE#318328
    bsc#917884).

  - rbd: ignore unmapped snapshots that no longer exist
    (FATE#318328 bsc#917884).

  - rbd: introduce rbd_dev_header_unwatch_sync() and switch
    to it (FATE#318328 bsc#917884).

  - rbd: make rbd_obj_notify_ack() synchronous (FATE#318328
    bsc#917884).

  - rbd: protect against concurrent unmaps (FATE#318328
    bsc#917884).

  - rbd: protect against duplicate client creation
    (FATE#318328 bsc#917884).

  - rbd: rbd_device::dev_id is an int, format it as such
    (FATE#318328 bsc#917884).

  - rbd: refactor rbd_init() a bit (FATE#318328 bsc#917884).

  - rbd: send snapshot context with writes (FATE#318328
    bsc#917884).

  - rbd: set removing flag while holding list lock
    (FATE#318328 bsc#917884).

  - rbd: switch to ida for rbd id assignments (FATE#318328
    bsc#917884).

  - rbd: take a little credit (FATE#318328 bsc#917884).

  - rbd: tear down watch request if rbd_dev_device_setup()
    fails (FATE#318328 bsc#917884).

  - rbd: tweak 'loaded' message and module description
    (FATE#318328 bsc#917884).

  - rbd: use reference counts for image requests
    (FATE#318328 bsc#917884).

  - rbd: use rwsem to protect header updates (FATE#318328
    bsc#917884).

  - rbd: use the correct length for format 2 object names
    (FATE#318328 bsc#917884).

  - rpm/kernel-binary.spec.in: Own the modules directory in
    the devel package. (bnc#910322)

  - scsi_dh_alua: add missing hunk in alua_set_params().
    (bnc#846656)

  - scsifront: avoid acquiring same lock twice if ring is
    full.

  - sd: medium access timeout counter fails to reset.
    (bnc#894213)

  - storvsc: ring buffer failures may result in I/O freeze

  - swap: fix shmem swapping when more than 8 areas.
    (bnc#903096)

  - timekeeping: Avoid possible deadlock from
    clock_was_set_delayed (bsc#771619).

  - tty: Fix memory leak in virtual console when enable
    unicode translation. (bnc#916515)

  - udf: Check component length before reading it.

  - udf: Check path length when reading symlink.

  - udf: Verify i_size when loading inode.

  - udf: Verify symlink size before loading it.

  - udp: Add MIB counters for rcvbuferrors. (bnc#909565)

  - usb: xhci: rework root port wake bits if controller is
    not allowed to wakeup (bsc#909264).

  - virtio_net: drop dst reference before transmitting a
    packet. (bnc#882470)

  - vt: push the tty_lock down into the map handling.
    (bnc#915826)

  - workqueue: Make rescuer thread process more works.
    (bnc#900279)

  - x86, xsave: remove thread_has_fpu() bug check in
    __sanitize_i387_state(). (bnc#904671)

  - x86-64/MCE: flip CPU and bank numbers in log message.

  - x86/UV: Fix NULL pointer dereference in
    uv_flush_tlb_others() if the '^a' boot option is used
    (bsc#909092).

  - x86/UV: Fix conditional in gru_exit() (bsc#909095).

  - x86/early quirk: use gen6 stolen detection for VLV
    (bnc#908550,FATE#317933).

  - x86/gpu: Print the Intel graphics stolen memory range.
    (bnc#908550)

  - x86/hpet: Make boot_hpet_disable extern
    (bnc#908550,FATE#317933).

  - x86/intel: Add quirk to disable HPET for the Baytrail
    platform (bnc#908550,FATE#317933).

  - x86/uv: Fix UV2 BAU legacy mode (bsc#909092).

  - x86/uv: Fix the UV BAU destination timeout period
    (bsc#909092).

  - x86/uv: Implement UV BAU runtime enable and disable
    control via /proc/sgi_uv/ (bsc#909092).

  - x86/uv: Update the UV3 TLB shootdown logic (bsc#909092).

  - x86/uv: Work around UV2 BAU hangs (bsc#909092).

  - x86: UV BAU: Avoid NULL pointer reference in
    ptc_seq_show (bsc#911181).

  - x86: UV BAU: Increase maximum CPUs per socket/hub
    (bsc#911181).

  - x86: add early quirk for reserving Intel graphics stolen
    memory v5 (bnc#908550,FATE#317933).

  - x86: irq: Check for valid irq descriptor in
    check_irq_vectors_for_cpu_disable. (bnc#914726)

  - xen-privcmd-hcall-preemption: Fix EFLAGS.IF access.

  - xfs: re-enable non-blocking behaviour in xfs_map_blocks.
    (bnc#900279)

  - xfs: recheck buffer pinned status after push trylock
    failure. (bnc#907338)

  - xfs: remove log force from xfs_buf_trylock().
    (bnc#907338)

  - xhci: fix incorrect type in assignment in
    handle_device_notification() (bsc#910321).

  - zcrypt: Number of supported ap domains is not
    retrievable (bnc#915209, LTC#120788)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=771619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=846656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=856760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=875051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=877593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=882470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=884817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=891277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=894213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=895841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=896484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=900279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=900644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=902232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=902349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=902351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=902675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=903096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=903640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=904053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=904242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=904659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=904671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=905304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=905312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=905799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=906586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=907196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=907338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=907551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=907611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=907818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=908069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=908163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=908393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=908550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=908551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=908572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=908825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=909077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=909078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=909088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=909092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=909093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=909095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=909264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=909565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=909740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=909846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=910013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=910150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=910159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=910321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=910322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=910517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=911181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=911325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=911326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=912171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=912705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=913059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=914355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=914423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=914726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=915209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=915322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=915335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=915791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=915826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=916515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=916982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=917839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=917884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=920250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-5313.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7263.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0181.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3601.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3687.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3688.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3690.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4608.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7822.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7842.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7970.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8133.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8134.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8369.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8559.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9322.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9584.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-1593.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 10412 / 10415 / 10416 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-bigsmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-bigsmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-base-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-extra-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-source-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-syms-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-trace-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.5_04_3.0.101_0.47.50-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.5_04_3.0.101_0.47.50-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-source-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-syms-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.5_04_3.0.101_0.47.50-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-base-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-source-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-syms-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-base-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.5_04_3.0.101_0.47.50-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.5_04_3.0.101_0.47.50-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"kernel-default-man-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-bigsmp-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-bigsmp-base-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.5_04_3.0.101_0.47.50-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
