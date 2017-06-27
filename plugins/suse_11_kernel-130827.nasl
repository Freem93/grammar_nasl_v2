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
  script_id(70039);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/10 17:43:14 $");

  script_cve_id("CVE-2013-1059", "CVE-2013-1774", "CVE-2013-1819", "CVE-2013-1929", "CVE-2013-2148", "CVE-2013-2164", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2851", "CVE-2013-4162", "CVE-2013-4163");

  script_name(english:"SuSE 11.2 Security Update : Linux kernel (SAT Patch Numbers 8263 / 8265 / 8273)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 2 kernel has been updated to
version 3.0.93 and includes various bug and security fixes.

The following security bugs have been fixed :

  - The fill_event_metadata function in
    fs/notify/fanotify/fanotify_user.c in the Linux kernel
    did not initialize a certain structure member, which
    allowed local users to obtain sensitive information from
    kernel memory via a read operation on the fanotify
    descriptor. (CVE-2013-2148)

  - The key_notify_policy_flush function in net/key/af_key.c
    in the Linux kernel did not initialize a certain
    structure member, which allowed local users to obtain
    sensitive information from kernel heap memory by reading
    a broadcast message from the notify_policy interface of
    an IPSec key_socket. (CVE-2013-2237)

  - The ip6_sk_dst_check function in net/ipv6/ip6_output.c
    in the Linux kernel allowed local users to cause a
    denial of service (system crash) by using an AF_INET6
    socket for a connection to an IPv4 interface.
    (CVE-2013-2232)

  - The (1) key_notify_sa_flush and (2)
    key_notify_policy_flush functions in net/key/af_key.c in
    the Linux kernel did not initialize certain structure
    members, which allowed local users to obtain sensitive
    information from kernel heap memory by reading a
    broadcast message from the notify interface of an IPSec
    key_socket. (CVE-2013-2234)

  - The udp_v6_push_pending_frames function in
    net/ipv6/udp.c in the IPv6 implementation in the Linux
    kernel made an incorrect function call for pending data,
    which allowed local users to cause a denial of service
    (BUG and system crash) via a crafted application that
    uses the UDP_CORK option in a setsockopt system call.
    (CVE-2013-4162)

  - net/ceph/auth_none.c in the Linux kernel allowed remote
    attackers to cause a denial of service (NULL pointer
    dereference and system crash) or possibly have
    unspecified other impact via an auth_reply message that
    triggers an attempted build_request operation.
    (CVE-2013-1059)

  - The mmc_ioctl_cdrom_read_data function in
    drivers/cdrom/cdrom.c in the Linux kernel allowed local
    users to obtain sensitive information from kernel memory
    via a read operation on a malfunctioning CD-ROM drive.
    (CVE-2013-2164)

  - Format string vulnerability in the register_disk
    function in block/genhd.c in the Linux kernel allowed
    local users to gain privileges by leveraging root access
    and writing format string specifiers to
    /sys/module/md_mod/parameters/new_array in order to
    create a crafted /dev/md device name. (CVE-2013-2851)

  - The ip6_append_data_mtu function in
    net/ipv6/ip6_output.c in the IPv6 implementation in the
    Linux kernel did not properly maintain information about
    whether the IPV6_MTU setsockopt option had been
    specified, which allowed local users to cause a denial
    of service (BUG and system crash) via a crafted
    application that uses the UDP_CORK option in a
    setsockopt system call. (CVE-2013-4163)

  - Heap-based buffer overflow in the tg3_read_vpd function
    in drivers/net/ethernet/broadcom/tg3.c in the Linux
    kernel allowed physically proximate attackers to cause a
    denial of service (system crash) or possibly execute
    arbitrary code via crafted firmware that specifies a
    long string in the Vital Product Data (VPD) data
    structure. (CVE-2013-1929)

  - The _xfs_buf_find function in fs/xfs/xfs_buf.c in the
    Linux kernel did not validate block numbers, which
    allowed local users to cause a denial of service (NULL
    pointer dereference and system crash) or possibly have
    unspecified other impact by leveraging the ability to
    mount an XFS filesystem containing a metadata inode with
    an invalid extent map. (CVE-2013-1819)

  - The chase_port function in drivers/usb/serial/io_ti.c in
    the Linux kernel allowed local users to cause a denial
    of service (NULL pointer dereference and system crash)
    via an attempted /dev/ttyUSB read or write operation on
    a disconnected Edgeport USB serial converter.
    (CVE-2013-1774)

Also the following bugs have been fixed :

BTRFS :

  - btrfs: merge contiguous regions when loading free space
    cache

  - btrfs: fix how we deal with the orphan block rsv

  - btrfs: fix wrong check during log recovery

  - btrfs: change how we indicate we are adding csums

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

  - btrfs: simplify unlink reservations (bnc#801427). 
OTHER :

  - x86: Add workaround to NMI iret woes. (bnc#831949)

  - x86: Do not schedule while still in NMI context.
    (bnc#831949)

  - bnx2x: Avoid sending multiple statistics queries.
    (bnc#814336)

  - bnx2x: protect different statistics flows. (bnc#814336)

  - futex: Take hugepages into account when generating
    futex_key.

  - drivers/hv: util: Fix a bug in version negotiation code
    for util services. (bnc#828714)

  - printk: Add NMI ringbuffer. (bnc#831949)

  - printk: extract ringbuffer handling from vprintk.
    (bnc#831949)

  - printk: NMI safe printk. (bnc#831949)

  - printk: Make NMI ringbuffer size independent on
    log_buf_len. (bnc#831949)

  - printk: Do not call console_unlock from nmi context.
    (bnc#831949)

  - printk: Do not use printk_cpu from finish_printk.
    (bnc#831949)

  - mlx4_en: Adding 40gb speed report for ethtool.
    (bnc#831410)

  - reiserfs: Fixed double unlock in reiserfs_setattr
    failure path.

  - reiserfs: delay reiserfs lock until journal
    initialization. (bnc#815320)

  - reiserfs: do not lock journal_init(). (bnc#815320)

  - reiserfs: locking, handle nested locks properly.
    (bnc#815320)

  - reiserfs: locking, push write lock out of xattr code.
    (bnc#815320)

  - reiserfs: locking, release lock around quota operations.
    (bnc#815320)

  - NFS: support 'nosharetransport' option (bnc#807502,
    bnc#828192, FATE#315593).

  - dm mpath: add retain_attached_hw_handler feature.
    (bnc#760407)

  - scsi_dh: add scsi_dh_attached_handler_name. (bnc#760407)

  - bonding: disallow change of MAC if fail_over_mac
    enabled. (bnc#827376)

  - bonding: propagate unicast lists down to slaves.
    (bnc#773255 / bnc#827372)

  - bonding: emit address change event also in bond_release.
    (bnc#773255 / bnc#827372)

  - bonding: emit event when bonding changes MAC.
    (bnc#773255 / bnc#827372)

  - SUNRPC: Ensure we release the socket write lock if the
    rpc_task exits early. (bnc#830901)

  - ext4: force read-only unless rw=1 module option is used
    (fate#314864).

  - HID: fix unused rsize usage. (bnc#783475)

  - HID: fix data access in implement(). (bnc#783475)

  - xfs: fix deadlock in xfs_rtfree_extent with kernel v3.x.
    (bnc#829622)

  - r8169: allow multicast packets on sub-8168f chipset.
    (bnc#805371)

  - r8169: support new chips of RTL8111F. (bnc#805371)

  - r8169: define the early size for 8111evl. (bnc#805371)

  - r8169: fix the reset setting for 8111evl. (bnc#805371)

  - r8169: add MODULE_FIRMWARE for the firmware of 8111evl.
    (bnc#805371)

  - r8169: fix sticky accepts packet bits in RxConfig.
    (bnc#805371)

  - r8169: adjust the RxConfig settings. (bnc#805371)

  - r8169: support RTL8111E-VL. (bnc#805371)

  - r8169: add ERI functions. (bnc#805371)

  - r8169: modify the flow of the hw reset. (bnc#805371)

  - r8169: adjust some registers. (bnc#805371)

  - r8169: check firmware content sooner. (bnc#805371)

  - r8169: support new firmware format. (bnc#805371)

  - r8169: explicit firmware format check. (bnc#805371)

  - r8169: move the firmware down into the device private
    data. (bnc#805371)

  - mm: link_mem_sections make sure nmi watchdog does not
    trigger while linking memory sections. (bnc#820434)

  - kernel: lost IPIs on CPU hotplug (bnc#825048,
    LTC#94784).

  - iwlwifi: use correct supported firmware for 6035 and
    6000g2. (bnc#825887)

  - watchdog: Update watchdog_thresh atomically.
    (bnc#829357)

  - watchdog: update watchdog_tresh properly. (bnc#829357)

  - watchdog:
    watchdog-make-disable-enable-hotplug-and-preempt-save.pa
    tch. (bnc#829357)

  - include/1/smp.h: define __smp_call_function_single for
    !CONFIG_SMP. (bnc#829357)

  - lpfc: Return correct error code on bsg_timeout.
    (bnc#816043)

  - dm-multipath: Drop table when retrying ioctl.
    (bnc#808940)

  - scsi: Do not retry invalid function error. (bnc#809122)

  - scsi: Always retry internal target error. (bnc#745640,
    bnc#825227)

  - ibmvfc: Driver version 1.0.1. (bnc#825142)

  - ibmvfc: Fix for offlining devices during error recovery.
    (bnc#825142)

  - ibmvfc: Properly set cancel flags when cancelling abort.
    (bnc#825142)

  - ibmvfc: Send cancel when link is down. (bnc#825142)

  - ibmvfc: Support FAST_IO_FAIL in EH handlers.
    (bnc#825142)

  - ibmvfc: Suppress ABTS if target gone. (bnc#825142)

  - fs/dcache.c: add cond_resched() to
    shrink_dcache_parent(). (bnc#829082)

  - kmsg_dump: do not run on non-error paths by default.
    (bnc#820172)

  - mm: honor min_free_kbytes set by user. (bnc#826960)

  - hyperv: Fix a kernel warning from
    netvsc_linkstatus_callback(). (bnc#828574)

  - RT: Fix up hardening patch to not gripe when avg >
    available, which lockless access makes possible and
    happens in -rt kernels running a cpubound ltp realtime
    testcase. Just keep the output sane in that case.

  - md/raid10: Fix two bug affecting RAID10 reshape (-).

  - Allow NFSv4 to run execute-only files. (bnc#765523)

  - fs/ocfs2/namei.c: remove unnecessary ERROR when removing
    non-empty directory. (bnc#819363)

  - block: Reserve only one queue tag for sync IO if only 3
    tags are available. (bnc#806396)

  - drm/i915: Add wait_for in init_ring_common. (bnc#813604)

  - drm/i915: Mark the ringbuffers as being in the GTT
    domain. (bnc#813604)

  - ext4: avoid hang when mounting non-journal filesystems
    with orphan list. (bnc#817377)

  - autofs4 - fix get_next_positive_subdir(). (bnc#819523)

  - ocfs2: Add bits_wanted while calculating credits in
    ocfs2_calc_extend_credits. (bnc#822077)

  - re-enable io tracing. (bnc#785901)

  - SUNRPC: Prevent an rpc_task wakeup race. (bnc#825591)

  - tg3: Prevent system hang during repeated EEH errors.
    (bnc#822066)

  - backends: Check for insane amounts of requests on the
    ring.

  - Update Xen patches to 3.0.82.

  - netiucv: Hold rtnl between name allocation and device
    registration. (bnc#824159)

  - drm/edid: Do not print messages regarding stereo or
    csync by default. (bnc#821235)

  - net/sunrpc: xpt_auth_cache should be ignored when
    expired. (bnc#803320)

  - sunrpc/cache: ensure items removed from cache do not
    have pending upcalls. (bnc#803320)

  - sunrpc/cache: remove races with queuing an upcall.
    (bnc#803320)

  - sunrpc/cache: use cache_fresh_unlocked consistently and
    correctly. (bnc#803320)

  - md/raid10 'enough' fixes. (bnc#773837)

  - Update config files: disable IP_PNP. (bnc#822825)

  - Disable efi pstore by default. (bnc#804482 / bnc#820172)

  - md: Fix problem with GET_BITMAP_FILE returning wrong
    status. (bnc#812974 / bnc#823497)

  - USB: xHCI: override bogus bulk wMaxPacketSize values.
    (bnc#823082)

  - ALSA: hda - Fix system panic when DMA > 40 bits for
    Nvidia audio controllers. (bnc#818465)

  - USB: UHCI: fix for suspend of virtual HP controller.
    (bnc#817035)

  - mm: mmu_notifier: re-fix freed page still mapped in
    secondary MMU. (bnc#821052)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=783475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=785901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789010"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=805371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809122"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816043"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819523"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821235"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822575"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825227"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=830901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1059.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1819.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1929.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2148.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2164.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2232.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2234.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2237.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2851.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4162.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4163.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8263 / 8265 / 8273 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-extra-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-extra-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-source-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-extra-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-extra-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-default-4.1.5_02_3.0.93_0.5-0.5.39")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-pae-4.1.5_02_3.0.93_0.5-0.5.39")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-trace-4.1.5_02_3.0.93_0.5-0.5.39")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-extra-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-source-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-syms-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-extra-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-extra-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.5_02_3.0.93_0.5-0.5.39")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.5_02_3.0.93_0.5-0.5.39")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-source-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-syms-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-default-4.1.5_02_3.0.93_0.5-0.5.39")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-pae-4.1.5_02_3.0.93_0.5-0.5.39")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-trace-4.1.5_02_3.0.93_0.5-0.5.39")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-man-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.93-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.5_02_3.0.93_0.5-0.5.39")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.5_02_3.0.93_0.5-0.5.39")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
