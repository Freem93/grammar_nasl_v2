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
  script_id(68954);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:46:55 $");

  script_cve_id("CVE-2013-0160", "CVE-2013-1774", "CVE-2013-1979", "CVE-2013-3076", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3227", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235");

  script_name(english:"SuSE 11.3 Security Update : Linux kernel (SAT Patch Numbers 7991 / 7992 / 7994)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 3 kernel has been updated to
3.0.82 and to fix various bugs and security issues.

The following security issues have been fixed :

  - The chase_port function in drivers/usb/serial/io_ti.c in
    the Linux kernel allowed local users to cause a denial
    of service (NULL pointer dereference and system crash)
    via an attempted /dev/ttyUSB read or write operation on
    a disconnected Edgeport USB serial converter.
    (CVE-2013-1774)

  - Timing side channel on attacks were possible on
    /dev/ptmx that could allow local attackers to predict
    keypresses like e.g. passwords. This has been fixed
    again by updating accessed/modified time on the pty
    devices in resolution of 8 seconds, so that idle time
    detection can still work. (CVE-2013-0160)

  - The vcc_recvmsg function in net/atm/common.c in the
    Linux kernel did not initialize a certain length
    variable, which allowed local users to obtain sensitive
    information from kernel stack memory via a crafted
    recvmsg or recvfrom system call. (CVE-2013-3222)

  - The ax25_recvmsg function in net/ax25/af_ax25.c in the
    Linux kernel did not initialize a certain data
    structure, which allowed local users to obtain sensitive
    information from kernel stack memory via a crafted
    recvmsg or recvfrom system call. (CVE-2013-3223)

  - The bt_sock_recvmsg function in
    net/bluetooth/af_bluetooth.c in the Linux kernel did not
    properly initialize a certain length variable, which
    allowed local users to obtain sensitive information from
    kernel stack memory via a crafted recvmsg or recvfrom
    system call. (CVE-2013-3224)

  - The rfcomm_sock_recvmsg function in
    net/bluetooth/rfcomm/sock.c in the Linux kernel did not
    initialize a certain length variable, which allowed
    local users to obtain sensitive information from kernel
    stack memory via a crafted recvmsg or recvfrom system
    call. (CVE-2013-3225)

  - The caif_seqpkt_recvmsg function in
    net/caif/caif_socket.c in the Linux kernel did not
    initialize a certain length variable, which allowed
    local users to obtain sensitive information from kernel
    stack memory via a crafted recvmsg or recvfrom system
    call. (CVE-2013-3227)

  - The irda_recvmsg_dgram function in net/irda/af_irda.c in
    the Linux kernel did not initialize a certain length
    variable, which allowed local users to obtain sensitive
    information from kernel stack memory via a crafted
    recvmsg or recvfrom system call. (CVE-2013-3228)

  - The iucv_sock_recvmsg function in net/iucv/af_iucv.c in
    the Linux kernel did not initialize a certain length
    variable, which allowed local users to obtain sensitive
    information from kernel stack memory via a crafted
    recvmsg or recvfrom system call. (CVE-2013-3229)

  - The llc_ui_recvmsg function in net/llc/af_llc.c in the
    Linux kernel did not initialize a certain length
    variable, which allowed local users to obtain sensitive
    information from kernel stack memory via a crafted
    recvmsg or recvfrom system call. (CVE-2013-3231)

  - The nr_recvmsg function in net/netrom/af_netrom.c in the
    Linux kernel did not initialize a certain data
    structure, which allowed local users to obtain sensitive
    information from kernel stack memory via a crafted
    recvmsg or recvfrom system call. (CVE-2013-3232)

  - The rose_recvmsg function in net/rose/af_rose.c in the
    Linux kernel did not initialize a certain data
    structure, which allowed local users to obtain sensitive
    information from kernel stack memory via a crafted
    recvmsg or recvfrom system call. (CVE-2013-3234)

  - net/tipc/socket.c in the Linux kernel did not initialize
    a certain data structure and a certain length variable,
    which allowed local users to obtain sensitive
    information from kernel stack memory via a crafted
    recvmsg or recvfrom system call. (CVE-2013-3235)

  - The crypto API in the Linux kernel did not initialize
    certain length variables, which allowed local users to
    obtain sensitive information from kernel stack memory
    via a crafted recvmsg or recvfrom system call, related
    to the hash_recvmsg function in crypto/algif_hash.c and
    the skcipher_recvmsg function in
    crypto/algif_skcipher.c. (CVE-2013-3076)

  - The scm_set_cred function in include/net/scm.h in the
    Linux kernel used incorrect uid and gid values during
    credentials passing, which allowed local users to gain
    privileges via a crafted application. (CVE-2013-1979)

  - A kernel information leak via tkill/tgkill was fixed.
    The following non-security bugs have been fixed :

S/390 :

  - af_iucv: Missing man page (bnc#825037, LTC#94825).

  - iucv: fix kernel panic at reboot (bnc#825037,
    LTC#93803).

  - kernel: lost IPIs on CPU hotplug (bnc#825037,
    LTC#94784).

  - dasd: Add missing descriptions for dasd timeout messages
    (bnc#825037, LTC#94762).

  - dasd: Fix hanging device after resume with internal
    error 13 (bnc#825037, LTC#94554).

  - cio: Suppress 2nd path verification during resume
    (bnc#825037, LTC#94554).

  - vmcp: Missing man page (bnc#825037, LTC#94453).

  - kernel: 3215 console crash (bnc#825037, LTC#94302).

  - netiucv: Hold rtnl between name allocation and device
    registration. (bnc#824159)

  - s390/ftrace: fix mcount adjustment (bnc#809895). 
HyperV :

  - Drivers: hv: Fix a bug in get_vp_index().

  - hyperv: Fix a compiler warning in netvsc_send().

  - Tools: hv: Fix a checkpatch warning.

  - tools: hv: skip iso9660 mounts in hv_vss_daemon.

  - tools: hv: use FIFREEZE/FITHAW in hv_vss_daemon.

  - tools: hv: use getmntent in hv_vss_daemon.

  - Tools: hv: Fix a checkpatch warning.

  - tools: hv: fix checks for origin of netlink message in
    hv_vss_daemon.

  - Tools: hv: fix warnings in hv_vss_daemon.

  - x86, hyperv: Handle Xen emulation of Hyper-V more
    gracefully.

  - hyperv: Fix a kernel warning from
    netvsc_linkstatus_callback().

  - Drivers: hv: balloon: make local functions static.

  - tools: hv: daemon should check type of received Netlink
    msg.

  - tools: hv: daemon setsockopt should use options macros.

  - tools: hv: daemon should subscribe only to CN_KVP_IDX
    group.

  - driver: hv: remove cast for kmalloc return value.

  - hyperv: use 3.4 as LIC version string (bnc#822431).
    BTRFS :

  - btrfs: flush delayed inodes if we are short on space.
    (bnc#801427)

  - btrfs: rework shrink_delalloc. (bnc#801427)

  - btrfs: fix our overcommit math. (bnc#801427)

  - btrfs: delay block group item insertion. (bnc#801427)

  - btrfs: remove bytes argument from do_chunk_alloc.
    (bnc#801427)

  - btrfs: run delayed refs first when out of space.
    (bnc#801427)

  - btrfs: do not commit instead of overcommitting.
    (bnc#801427)

  - btrfs: do not take inode delalloc mutex if we are a free
    space inode. (bnc#801427)

  - btrfs: fix chunk allocation error handling. (bnc#801427)

  - btrfs: remove extent mapping if we fail to add chunk.
    (bnc#801427)

  - btrfs: do not overcommit if we do not have enough space
    for global rsv. (bnc#801427)

  - btrfs: rework the overcommit logic to be based on the
    total size. (bnc#801427)

  - btrfs: steal from global reserve if we are cleaning up
    orphans. (bnc#801427)

  - btrfs: clear chunk_alloc flag on retryable failure.
    (bnc#801427)

  - btrfs: use reserved space for creating a snapshot.
    (bnc#801427)

  - btrfs: cleanup to make the function
    btrfs_delalloc_reserve_metadata more logic. (bnc#801427)

  - btrfs: fix space leak when we fail to reserve metadata
    space. (bnc#801427)

  - btrfs: fix space accounting for unlink and rename.
    (bnc#801427)

  - btrfs: allocate new chunks if the space is not enough
    for global rsv. (bnc#801427)

  - btrfs: various abort cleanups. (bnc#812526 / bnc#801427)

  - btrfs: simplify unlink reservations (bnc#801427). XFS :

  - xfs: Move allocation stack switch up to xfs_bmapi.
    (bnc#815356)

  - xfs: introduce XFS_BMAPI_STACK_SWITCH. (bnc#815356)

  - xfs: zero allocation_args on the kernel stack.
    (bnc#815356)

  - xfs: fix debug_object WARN at xfs_alloc_vextent().
    (bnc#815356)

  - xfs: do not defer metadata allocation to the workqueue.
    (bnc#815356)

  - xfs: introduce an allocation workqueue. (bnc#815356)

  - xfs: fix race while discarding buffers [V4] (bnc#815356
    (comment 36)).

  - xfs: Serialize file-extending direct IO. (bnc#818371)

  - xfs: Do not allocate new buffers on every call to
    _xfs_buf_find. (bnc#763968)

  - xfs: fix buffer lookup race on allocation failure
    (bnc#763968). ALSA :

  - Fix VT1708 jack detection on SLEPOS machines.
    (bnc#813922)

  - ALSA: hda - Avoid choose same converter for unused pins.
    (bnc#826186)

  - ALSA: hda - Cache the MUX selection for generic HDMI.
    (bnc#826186)

  - ALSA: hda - Haswell converter power state D0 verify.
    (bnc#826186)

  - ALSA: hda - Do not take unresponsive D3 transition too
    serious. (bnc#823597)

  - ALSA: hda - Introduce bit flags to
    snd_hda_codec_read/write(). (bnc#823597)

  - ALSA: hda - Check CORB overflow. (bnc#823597)

  - ALSA: hda - Check validity of CORB/RIRB WP reads.
    (bnc#823597)

  - ALSA: hda - Fix system panic when DMA > 40 bits for
    Nvidia audio controllers. (bnc#818465)

  - ALSA: hda - Add hint for suppressing lower cap for IDT
    codecs. (bnc#812332)

  - ALSA: hda - Enable mic-mute LED on more HP laptops
    (bnc#821859). Direct Rendering Manager (DRM) :

  - drm/i915: Add wait_for in init_ring_common. (bnc#813604)

  - drm/i915: Mark the ringbuffers as being in the GTT
    domain. (bnc#813604)

  - drm/edid: Do not print messages regarding stereo or
    csync by default. (bnc#821235)

  - drm/i915: force full modeset if the connector is in DPMS
    OFF mode. (bnc#809975)

  - drm/i915/sdvo: Use &amp;intel_sdvo->ddc instead of
    intel_sdvo->i2c for DDC. (bnc#808855)

  - drm/mm: fix dump table BUG. (bnc#808837)

  - drm/i915: Clear the stolen fb before enabling
    (bnc#808015). XEN :

  - xen/netback: Update references. (bnc#823342)

  - xen: Check for insane amounts of requests on the ring.

  - Update Xen patches to 3.0.82.

  - netback: do not disconnect frontend when seeing oversize
    packet.

  - netfront: reduce gso_max_size to account for max TCP
    header.

  - netfront: fix kABI after 'reduce gso_max_size to account
    for max TCP header'. Other :

  - x86, efi: retry ExitBootServices() on failure.
    (bnc#823386)

  - x86/efi: Fix dummy variable buffer allocation.
    (bnc#822080)

  - ext4: avoid hang when mounting non-journal filesystems
    with orphan list. (bnc#817377)

  - mm: compaction: Scan PFN caching KABI workaround (Fix
    KABI breakage (bnc#825657)).

  - autofs4 - fix get_next_positive_subdir(). (bnc#819523)

  - ocfs2: Add bits_wanted while calculating credits in
    ocfs2_calc_extend_credits. (bnc#822077)

  - writeback: Avoid needless scanning of b_dirty list.
    (bnc#819018)

  - writeback: Do not sort b_io list only because of block
    device inode. (bnc#819018)

  - re-enable io tracing. (bnc#785901)

  - pciehp: Corrected the old mismatching DMI strings.

  - SUNRPC: Prevent an rpc_task wakeup race. (bnc#825591)

  - tg3: Prevent system hang during repeated EEH errors.
    (bnc#822066)

  - scsi_dh_alua: multipath failover fails with error 15.
    (bnc#825696)

  - Do not switch camera on HP EB 8780. (bnc#797090)

  - Do not switch webcam for HP EB 8580w. (bnc#797090)

  - mm: fixup compilation error due to an asm write through
    a const pointer. (bnc#823795)

  - do not switch cam port on HP EliteBook 840. (bnc#822164)

  - net/sunrpc: xpt_auth_cache should be ignored when
    expired. (bnc#803320)

  - sunrpc/cache: ensure items removed from cache do not
    have pending upcalls. (bnc#803320)

  - sunrpc/cache: remove races with queuing an upcall.
    (bnc#803320)

  - sunrpc/cache: use cache_fresh_unlocked consistently and
    correctly. (bnc#803320)

  - KVM: x86: emulate movdqa. (bnc#821070)

  - KVM: x86: emulator: add support for vector alignment.
    (bnc#821070)

  - KVM: x86: emulator: expand decode flags to 64 bits.
    (bnc#821070)

  - xhci - correct comp_mode_recovery_timer on return from
    hibernate. (bnc#808136)

  - md/raid10 enough fixes. (bnc#773837)

  - lib/Makefile: Fix oid_registry build dependency.
    (bnc#823223)

  - Update config files: disable IP_PNP. (bnc#822825)

  - Fix kABI breakage for addition of
    snd_hda_bus.no_response_fallback. (bnc#823597)

  - Disable efi pstore by default. (bnc#804482 / bnc#820172)

  - md: Fix problem with GET_BITMAP_FILE returning wrong
    status. (bnc#812974)

  - bnx2x: Fix bridged GSO for 57710/57711 chips.
    (bnc#819610)

  - USB: xHCI: override bogus bulk wMaxPacketSize values.
    (bnc#823082)

  - BTUSB: Add MediaTek bluetooth MT76x0E support.
    (bnc#797727 / bnc#822340)

  - qlge: Update version to 1.00.00.32. (bnc#819195)

  - qlge: Fix ethtool autoneg advertising. (bnc#819195)

  - qlge: Fix receive path to drop error frames.
    (bnc#819195)

  - qlge: remove NETIF_F_TSO6 flag. (bnc#819195)

  - remove init of dev->perm_addr in drivers. (bnc#819195)

  - drivers/net: fix up function prototypes after __dev*
    removals. (bnc#819195)

  - qlge: remove __dev* attributes. (bnc#819195)

  - drivers: ethernet: qlogic: qlge_dbg.c: Fixed a coding
    style issue. (bnc#819195)

  - cxgb4: Force uninitialized state if FW_ON_ADAPTER is <
    FW_VERSION and we are the MASTER_PF. (bnc#809130)

  - USB: UHCI: fix for suspend of virtual HP controller.
    (bnc#817035)

  - timer_list: Convert timer list to be a proper seq_file.
    (bnc#818047)

  - timer_list: Split timer_list_show_tickdevices.
    (bnc#818047)

  - sched: Fix /proc/sched_debug failure on very very large
    systems. (bnc#818047)

  - sched: Fix /proc/sched_stat failure on very very large
    systems. (bnc#818047)

  - reiserfs: fix spurious multiple-fill in
    reiserfs_readdir_dentry. (bnc#822722)

  - libfc: do not exch_done() on invalid sequence ptr.
    (bnc#810722)

  - netfilter: ip6t_LOG: fix logging of packet mark.
    (bnc#821930)

  - virtio_net: introduce VIRTIO_NET_HDR_F_DATA_VALID.
    (bnc#819655)

  - HWPOISON: fix misjudgement of page_action() for errors
    on mlocked pages (Memory failure RAS (bnc#821799)).

  - HWPOISON: check dirty flag to match against clean page
    (Memory failure RAS (bnc#821799)).

  - HWPOISON: change order of error_states elements (Memory
    failure RAS (bnc#821799)).

  - mm: hwpoison: fix action_result() to print out
    dirty/clean (Memory failure RAS (bnc#821799)).

  - mm: mmu_notifier: re-fix freed page still mapped in
    secondary MMU. (bnc#821052)

  - Do not switch webcams in some HP ProBooks to XHCI.
    (bnc#805804)

  - Do not switch BT on HP ProBook 4340. (bnc#812281)

  - mm: memory_dev_init make sure nmi watchdog does not
    trigger while registering memory sections. (bnc#804609,
    bnc#820434)

  - mm: compaction: Restart compaction from near where it
    left off

  - mm: compaction: cache if a pageblock was scanned and no
    pages were isolated

  - mm: compaction: clear PG_migrate_skip based on
    compaction and reclaim activity

  - mm: compaction: Scan PFN caching KABI workaround

  - mm: page_allocator: Remove first_pass guard

  - mm: vmscan: do not stall on writeback during memory
    compaction Cache compaction restart points for faster
    compaction cycles (bnc#816451)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=785901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=805804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=810722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=812281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=812332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=812526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=812974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821930"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1979.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3076.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3222.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3223.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3224.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3225.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3227.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3228.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3229.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3231.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3232.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3234.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3235.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 7991 / 7992 / 7994 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-base-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-extra-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-extra-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-source-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-syms-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-trace-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-extra-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-base-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-extra-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-source-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-syms-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-trace-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-extra-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.2_04_3.0.82_0.7-0.9.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-base-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-source-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-syms-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-base-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-base-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"kernel-default-man-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-base-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.82-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.2_04_3.0.82_0.7-0.9.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
