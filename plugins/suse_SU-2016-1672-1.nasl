#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1672-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93164);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2015-7566", "CVE-2015-8816", "CVE-2016-0758", "CVE-2016-1583", "CVE-2016-2053", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2187", "CVE-2016-2188", "CVE-2016-2782", "CVE-2016-2847", "CVE-2016-3134", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3139", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4805", "CVE-2016-4913", "CVE-2016-5244");
  script_osvdb_id(132748, 133550, 134938, 135143, 135194, 135678, 135871, 135872, 135873, 135874, 135875, 135876, 135877, 135878, 135943, 135975, 137841, 137963, 138086, 138093, 138176, 138383, 138431, 138444, 138451, 138785, 139498, 139987);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2016:1672-1)");
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

Notable changes in this kernel :

  - It is now possible to mount a NFS export on the
    exporting host directly.

The following security bugs were fixed :

  - CVE-2016-5244: A kernel information leak in
    rds_inc_info_copy was fixed that could leak kernel stack
    memory to userspace (bsc#983213).

  - CVE-2016-1583: Prevent the usage of mmap when the lower
    file system does not allow it. This could have lead to
    local privilege escalation when ecryptfs-utils was
    installed and /sbin/mount.ecryptfs_private was setuid
    (bsc#983143).

  - CVE-2016-4913: The get_rock_ridge_filename function in
    fs/isofs/rock.c in the Linux kernel mishandles NM (aka
    alternate name) entries containing \0 characters, which
    allowed local users to obtain sensitive information from
    kernel memory or possibly have unspecified other impact
    via a crafted isofs filesystem (bnc#980725).

  - CVE-2016-4580: The x25_negotiate_facilities function in
    net/x25/x25_facilities.c in the Linux kernel did not
    properly initialize a certain data structure, which
    allowed attackers to obtain sensitive information from
    kernel stack memory via an X.25 Call Request
    (bnc#981267).

  - CVE-2016-4805: Use-after-free vulnerability in
    drivers/net/ppp/ppp_generic.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption and system crash, or spinlock) or possibly
    have unspecified other impact by removing a network
    namespace, related to the ppp_register_net_channel and
    ppp_unregister_channel functions (bnc#980371).

  - CVE-2016-0758: Tags with indefinite length could have
    corrupted pointers in asn1_find_indefinite_length
    (bsc#979867).

  - CVE-2016-2187: The gtco_probe function in
    drivers/input/tablet/gtco.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a crafted endpoints value in a USB device descriptor
    (bnc#971944).

  - CVE-2016-4482: The proc_connectinfo function in
    drivers/usb/core/devio.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via a crafted USBDEVFS_CONNECTINFO ioctl call
    (bnc#978401).

  - CVE-2016-2053: The asn1_ber_decoder function in
    lib/asn1_decoder.c in the Linux kernel allowed attackers
    to cause a denial of service (panic) via an ASN.1 BER
    file that lacks a public key, leading to mishandling by
    the public_key_verify_signature function in
    crypto/asymmetric_keys/public_key.c (bnc#963762).

  - CVE-2016-4565: The InfiniBand (aka IB) stack in the
    Linux kernel incorrectly relies on the write system
    call, which allowed local users to cause a denial of
    service (kernel memory write operation) or possibly have
    unspecified other impact via a uAPI interface
    (bnc#979548).

  - CVE-2016-4485: The llc_cmsg_rcv function in
    net/llc/af_llc.c in the Linux kernel did not initialize
    a certain data structure, which allowed attackers to
    obtain sensitive information from kernel stack memory by
    reading a message (bnc#978821).

  - CVE-2016-4578: sound/core/timer.c in the Linux kernel
    did not initialize certain r1 data structures, which
    allowed local users to obtain sensitive information from
    kernel stack memory via crafted use of the ALSA timer
    interface, related to the (1) snd_timer_user_ccallback
    and (2) snd_timer_user_tinterrupt functions
    (bnc#979879).

  - CVE-2016-4569: The snd_timer_user_params function in
    sound/core/timer.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via crafted use of the ALSA timer interface
    (bnc#979213).

  - CVE-2016-4486: The rtnl_fill_link_ifmap function in
    net/core/rtnetlink.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory by reading a Netlink message (bnc#978822).

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
    kernel on s390 platforms mishandles the case of four
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
    USB device that lacked a bulk-out endpoint (bnc#961512).

The following non-security bugs were fixed :

  - acpi / PCI: Account for ARI in _PRT lookups
    (bsc#968566).

  - af_unix: Guard against other == sk in unix_dgram_sendmsg
    (bsc#973570).

  - alsa: hrtimer: Handle start/stop more properly
    (bsc#973378).

  - alsa: oxygen: add Xonar DGX support (bsc#982691).

  - alsa: pcm: Fix potential deadlock in OSS emulation
    (bsc#968018).

  - alsa: rawmidi: Fix race at copying and updating the
    position (bsc#968018).

  - alsa: rawmidi: Make snd_rawmidi_transmit() race-free
    (bsc#968018).

  - alsa: seq: Fix double port list deletion (bsc#968018).

  - alsa: seq: Fix incorrect sanity check at
    snd_seq_oss_synth_cleanup() (bsc#968018).

  - alsa: seq: Fix leak of pool buffer at concurrent writes
    (bsc#968018).

  - alsa: seq: Fix lockdep warnings due to double mutex
    locks (bsc#968018).

  - alsa: seq: Fix race at closing in virmidi driver
    (bsc#968018).

  - alsa: seq: Fix yet another races among ALSA timer
    accesses (bsc#968018).

  - alsa: timer: Call notifier in the same spinlock
    (bsc#973378).

  - alsa: timer: Code cleanup (bsc#968018).

  - alsa: timer: Fix leftover link at closing (bsc#968018).

  - alsa: timer: Fix link corruption due to double start or
    stop (bsc#968018).

  - alsa: timer: Fix race between stop and interrupt
    (bsc#968018).

  - alsa: timer: Fix wrong instance passed to slave
    callbacks (bsc#968018).

  - alsa: timer: Protect the whole snd_timer_close() with
    open race (bsc#973378).

  - alsa: timer: Sync timer deletion at closing the system
    timer (bsc#973378).

  - alsa: timer: Use mod_timer() for rearming the system
    timer (bsc#973378).

  - cgroups: do not attach task to subsystem if migration
    failed (bnc#979274).

  - cgroups: more safe tasklist locking in
    cgroup_attach_proc (bnc#979274).

  - cpuset: Fix potential deadlock w/ set_mems_allowed
    (bsc#960857, bsc#974646).

  - dasd: fix hanging system after LCU changes (bnc#968500,
    LTC#136671).

  - dcache: use IS_ROOT to decide where dentry is hashed
    (bsc#949752).

  - Delete
    patches.drivers/nvme-0165-Split-header-file-into-user-vi
    sible-and-kernel-.p atch. SLE11-SP4 does not have uapi
    headers so move everything back to the original header
    (bnc#981231)

  - Driver: Vmxnet3: set CHECKSUM_UNNECESSARY for IPv6
    packets (bsc#976739).

  - enic: set netdev->vlan_features (bsc#966245).

  - fcoe: fix reset of fip selection time (bsc#974787).

  - Fix cifs_uniqueid_to_ino_t() function for s390x
    (bsc#944309)

  - fs, seqfile: always allow oom killer (bnc#968687).

  - fs/seq_file: fallback to vmalloc allocation
    (bnc#968687).

  - fs, seq_file: fallback to vmalloc instead of oom kill
    processes (bnc#968687).

  - hid-elo: kill not flush the work (bnc#982532).

  - hpsa: fix issues with multilun devices (bsc#959381).

  - hv: Assign correct ->can_queue value in hv_storvsc
    (bnc#969391)

  - ibmvscsi: Remove unsupported host config MAD
    (bsc#973556).

  - Import kabi files from kernel 3.0.101-71

  - iommu/vt-d: Improve fault handler error messages
    (bsc#975772).

  - iommu/vt-d: Ratelimit fault handler (bsc#975772).

  - ipc,sem: fix use after free on IPC_RMID after a task
    using same semaphore set exits (bsc#967914).

  - ipv4/fib: do not warn when primary address is missing if
    in_dev is dead (bsc#971360).

  - ipv4: fix ineffective source address selection
    (bsc#980788).

  - ipv6: make fib6 serial number per namespace
    (bsc#965319).

  - ipv6: mld: fix add_grhead skb_over_panic for devs with
    large MTUs (bsc#956852).

  - ipv6: per netns fib6 walkers (bsc#965319).

  - ipv6: per netns FIB garbage collection (bsc#965319).

  - ipv6: replace global gc_args with local variable
    (bsc#965319).

  - ipvs: count pre-established TCP states as active
    (bsc#970114).

  - isofs: Revert 'get_rock_ridge_filename(): handle
    malformed NM entries' This reverts commit
    cb6ce3ec7a964e56da9ba9cd3c9f0e708b5c3b2c. It should have
    never landed in the tree (we already have the patch via
    c63531c60ff that came through CVE branch), but I messed
    up the merge.

  - kabi, fs/seq_file: fallback to vmalloc allocation
    (bnc#968687).

  - kabi: protect struct netns_ipv6 after FIB6 GC series
    (bsc#965319).

  - KVM: x86: fix maintenance of guest/host xcr0 state
    (bsc#961518).

  - llist: Add llist_next().

  - make vfree() safe to call from interrupt contexts .

  - memcg: do not hang on OOM when killed by userspace OOM
    access to memory reserves (bnc#969571).

  - mld, igmp: Fix reserved tailroom calculation
    (bsc#956852).

  - mm/hugetlb.c: correct missing private flag clearing (VM
    Functionality, bnc#971446).

  - mm/hugetlb: fix backport of upstream commit 07443a85ad
    (VM Functionality, bnc#971446).

  - MM: increase safety margin provided by PF_LESS_THROTTLE
    (bsc#956491).

  - mm/vmscan.c: avoid throttling reclaim for loop-back nfsd
    threads (bsc#956491).

  - net/core: dev_mc_sync_multiple calls wrong helper
    (bsc#971433).

  - net/core: __hw_addr_create_ex does not initialize
    sync_cnt (bsc#971433).

  - net/core: __hw_addr_sync_one / _multiple broken
    (bsc#971433).

  - net/core: __hw_addr_unsync_one 'from' address not marked
    synced (bsc#971433).

  - NFS4: treat lock owners as opaque values (bnc#968141).

  - NFS: avoid deadlocks with loop-back mounted NFS
    filesystems (bsc#956491).

  - NFS: avoid waiting at all in nfs_release_page when
    congested (bsc#956491).

  - NFSd4: return nfserr_symlink on v4 OPEN of non-regular
    file (bsc#973237).

  - NFSd: do not fail unchecked creates of non-special files
    (bsc#973237).

  - NFS: Do not attempt to decode missing directory entries
    (bsc#980931).

  - nfs: fix memory corruption rooted in get_ih_name pointer
    math (bsc#984107).

  - NFS: reduce access cache shrinker locking (bnc#866130).

  - NFS: use smaller allocations for 'struct idmap'
    (bsc#965923).

  - NFSv4: Ensure that we do not drop a state owner more
    than once (bsc#979595).

  - nfsv4: OPEN must handle the NFS4ERR_IO return code
    correctly (bsc#979595).

  - nvme: fix max_segments integer truncation (bsc#676471).

  - NVMe: Unify controller probe and resume (bsc#979347).

  - ocfs2: do not set fs read-only if rec[0] is empty while
    committing truncate (bnc#971947).

  - ocfs2: extend enough credits for freeing one truncate
    record while replaying truncate records (bnc#971947).

  - ocfs2: extend transaction for
    ocfs2_remove_rightmost_path() and
    ocfs2_update_edge_lengths() before to avoid
    inconsistency between inode and et (bnc#971947).

  - pciback: check PF instead of VF for PCI_COMMAND_MEMORY
    (bsc#957990).

  - pciback: Save the number of MSI-X entries to be copied
    later (bsc#957988).

  - PCI: Move pci_ari_enabled() to global header
    (bsc#968566).

  - RDMA/ucma: Fix AB-BA deadlock (bsc#963998).

  - Restore kabi after lock-owner change (bnc#968141).

  - rpm/modprobe-xen.conf: Revert comment change to allow
    parallel install (bsc#957986). This reverts commit
    855c7ce885fd412ce2a25ccc12a46e565c83f235.

  - s390/dasd: prevent incorrect length error under z/VM
    after PAV changes (bnc#968500, LTC#136670).

  - s390/pageattr: Do a single TLB flush for
    change_page_attr (bsc#940413).

  - s390/pci: add extra padding to function measurement
    block (bnc#968500, LTC#139445).

  - s390/pci_dma: fix DMA table corruption with > 4 TB main
    memory (bnc#968500, LTC#139401).

  - s390/pci_dma: handle dma table failures (bnc#968500,
    LTC#139442).

  - s390/pci_dma: improve debugging of errors during dma map
    (bnc#968500, LTC#139442).

  - s390/pci_dma: unify label of invalid translation table
    entries (bnc#968500, LTC#139442).

  - s390/pci: enforce fmb page boundary rule (bnc#968500,
    LTC#139445).

  - s390/pci: extract software counters from fmb
    (bnc#968500, LTC#139445).

  - s390/pci: remove pdev pointer from arch data
    (bnc#968500, LTC#139444).

  - s390/spinlock: avoid yield to non existent cpu
    (bnc#968500, LTC#141106).

  - scsi_dh_alua: Do not block request queue if workqueue is
    active (bsc#960458).

  - SCSI: Increase REPORT_LUNS timeout (bsc#971989).

  - SCSI mpt2sas: Rearrange the the code so that the
    completion queues are initialized prior to sending the
    request to controller firmware (bsc#967863).

  - skb: Add inline helper for getting the skb end offset
    from head (bsc#956852).

  - tcp: avoid order-1 allocations on wifi and tx path
    (bsc#956852).

  - tcp: fix skb_availroom() (bsc#956852).

  - Tidy series.conf, p5 Only one last patch which can be
    moved easily. There are some more x86-related things
    left at the end but moving them won't be that trivial.

  - Update
    patches.drivers/nvme-0265-fix-max_segments-integer-trunc
    ation.patch (bsc#979419). Fix reference.

  - Update
    patches.fixes/bnx2x-Alloc-4k-fragment-for-each-rx-ring-b
    uffer-elem.patch (bsc#953369 bsc#975358).

  - Update PCI VPD size patch to upstream: - PCI: Determine
    actual VPD size on first access (bsc#971729). - PCI:
    Update VPD definitions (bsc#971729).

  - USB: usbip: fix potential out-of-bounds write
    (bnc#975945).

  - veth: do not modify ip_summed (bsc#969149).

  - vgaarb: Add more context to error messages (bsc#976868).

  - virtio_scsi: Implement eh_timed_out callback
    (bsc#936530).

  - vmxnet3: set carrier state properly on probe
    (bsc#972363).

  - vmxnet3: set netdev parant device before calling
    netdev_info (bsc#972363).

  - x86, kvm: fix kvm's usage of kernel_fpu_begin/end()
    (bsc#961518).

  - x86, kvm: use kernel_fpu_begin/end() in
    kvm_load/put_guest_fpu() (bsc#961518).

  - xfrm: do not segment UFO packets (bsc#946122).

  - xfs: fix sgid inheritance for subdirectories inheriting
    default acls [V3] (bsc#965860).

  - xhci: Workaround to get Intel xHCI reset working more
    reliably (bnc#898592).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/676471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/866130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/898592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/946122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956852"
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
    value:"https://bugzilla.suse.com/959381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970114"
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
    value:"https://bugzilla.suse.com/971433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973556"
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
    value:"https://bugzilla.suse.com/974787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7566.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8816.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0758.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1583.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2053.html"
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
    value:"https://www.suse.com/security/cve/CVE-2016-2187.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2188.html"
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
    value:"https://www.suse.com/security/cve/CVE-2016-4482.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4485.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4486.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4565.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4578.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4580.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4913.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5244.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161672-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?817b5419"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-kernel-source-12631=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-kernel-source-12631=1

SUSE Linux Enterprise Server 11-EXTRA :

zypper in -t patch slexsp3-kernel-source-12631=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-kernel-source-12631=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"kernel-default-man-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-base-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-devel-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-source-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-syms-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-base-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-devel-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-base-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-77.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-77.1")) flag++;


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
