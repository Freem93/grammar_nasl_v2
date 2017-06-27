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
  script_id(66912);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:46:55 $");

  script_cve_id("CVE-2013-0160", "CVE-2013-1979", "CVE-2013-3076", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3227", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235");

  script_name(english:"SuSE 11.2 Security Update : Linux kernel (SAT Patch Numbers 7811 / 7813 / 7814)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 2 kernel has been updated to
Linux kernel 3.0.80 which fixes various bugs and security issues.

The following security issues have been fixed :

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
    The following bugs have been fixed :

  - reiserfs: fix spurious multiple-fill in
    reiserfs_readdir_dentry. (bnc#822722)

  - libfc: do not exch_done() on invalid sequence ptr.
    (bnc#810722)

  - netfilter: ip6t_LOG: fix logging of packet mark.
    (bnc#821930)

  - hyperv: use 3.4 as LIC version string. (bnc#822431)

  - virtio_net: introduce VIRTIO_NET_HDR_F_DATA_VALID.
    (bnc#819655)

  - xen/netback: do not disconnect frontend when seeing
    oversize packet.

  - xen/netfront: reduce gso_max_size to account for max TCP
    header.

  - xen/netfront: fix kABI after 'reduce gso_max_size to
    account for max TCP header'.

  - xfs: Fix kABI due to change in xfs_buf. (bnc#815356)

  - xfs: fix race while discarding buffers [V4] (bnc#815356
    (comment 36)).

  - xfs: Serialize file-extending direct IO. (bnc#818371)

  - xhci: Do not switch webcams in some HP ProBooks to XHCI.
    (bnc#805804)

  - bluetooth: Do not switch BT on HP ProBook 4340.
    (bnc#812281)

  - s390/ftrace: fix mcount adjustment. (bnc#809895)

  - mm: memory_dev_init make sure nmi watchdog does not
    trigger while registering memory sections. (bnc#804609,
    bnc#820434)

  - patches.fixes/xfs-backward-alloc-fix.diff: xfs: Avoid
    pathological backwards allocation. (bnc#805945)

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
    compaction cycles. (bnc#816451)

  - qlge: fix dma map leak when the last chunk is not
    allocated. (bnc#819519)

  - SUNRPC: Get rid of the redundant xprt->shutdown bit
    field. (bnc#800907)

  - SUNRPC: Ensure that we grab the XPRT_LOCK before calling
    xprt_alloc_slot. (bnc#800907)

  - SUNRPC: Fix a UDP transport regression. (bnc#800907)

  - SUNRPC: Allow caller of rpc_sleep_on() to select
    priority levels. (bnc#800907)

  - SUNRPC: Replace xprt->resend and xprt->sending with a
    priority queue. (bnc#800907)

  - SUNRPC: Fix potential races in xprt_lock_write_next().
    (bnc#800907)

  - md: cannot re-add disks after recovery. (bnc#808647)

  - fs/xattr.c:getxattr(): improve handling of allocation
    failures. (bnc#818053)

  - fs/xattr.c:listxattr(): fall back to vmalloc() if
    kmalloc() failed. (bnc#818053)

  - fs/xattr.c:setxattr(): improve handling of allocation
    failures. (bnc#818053)

  - fs/xattr.c: suppress page allocation failure warnings
    from sys_listxattr(). (bnc#818053)

  - virtio-blk: Call revalidate_disk() upon online disk
    resize. (bnc#817339)

  - usb-storage: CY7C68300A chips do not support Cypress
    ATACB. (bnc#819295)

  - patches.kernel.org/patch-3.0.60-61: Update references
    (add bnc#810580).

  - usb: Using correct way to clear usb3.0 devices remote
    wakeup feature. (bnc#818516)

  - xhci: Fix TD size for isochronous URBs. (bnc#818514)

  - ALSA: hda - fixup D3 pin and right channel mute on
    Haswell HDMI audio. (bnc#818798)

  - ALSA: hda - Apply pin-enablement workaround to all
    Haswell HDMI codecs. (bnc#818798)

  - xfs: fallback to vmalloc for large buffers in
    xfs_attrmulti_attr_get. (bnc#818053)

  - xfs: fallback to vmalloc for large buffers in
    xfs_attrlist_by_handle. (bnc#818053)

  - xfs: xfs: fallback to vmalloc for large buffers in
    xfs_compat_attrlist_by_handle. (bnc#818053)

  - xHCI: store rings type.

  - xhci: Fix hang on back-to-back Set TR Deq Ptr commands.

  - xHCI: check enqueue pointer advance into dequeue seg.

  - xHCI: store rings last segment and segment numbers.

  - xHCI: Allocate 2 segments for transfer ring.

  - xHCI: count free TRBs on transfer ring.

  - xHCI: factor out segments allocation and free function.

  - xHCI: update sg tablesize.

  - xHCI: set cycle state when allocate rings.

  - xhci: Reserve one command for USB3 LPM disable.

  - xHCI: dynamic ring expansion.

  - xhci: Do not warn on empty ring for suspended devices.

  - md/raid1: Do not release reference to device while
    handling read error. (bnc#809122, bnc#814719)

  - rpm/mkspec: Stop generating the get_release_number.sh
    file.

  - rpm/kernel-spec-macros: Properly handle KOTD release
    numbers with .g suffix.

  - rpm/kernel-spec-macros: Drop the %release_num macro We
    no longer put the -rcX tag into the release string.

  - rpm/kernel-*.spec.in, rpm/mkspec: Do not force the
    '<RELEASE>' string in specfiles.

  - mm/mmap: check for RLIMIT_AS before unmapping.
    (bnc#818327)

  - mm: Fix add_page_wait_queue() to work for PG_Locked bit
    waiters. (bnc#792584)

  - mm: Fix add_page_wait_queue() to work for PG_Locked bit
    waiters. (bnc#792584)

  - bonding: only use primary address for ARP. (bnc#815444)

  - bonding: remove entries for master_ip and vlan_ip and
    query devices instead. (bnc#815444)

  - mm: speedup in __early_pfn_to_nid. (bnc#810624)

  - TTY: fix atime/mtime regression. (bnc#815745)

  - sd_dif: problem with verify of type 1 protection
    information (PI). (bnc#817010)

  - sched: harden rq rt usage accounting. (bnc#769685,
    bnc#788590)

  - rcu: Avoid spurious RCU CPU stall warnings. (bnc#816586)

  - rcu: Dump local stack if cannot dump all CPUs stacks.
    (bnc#816586)

  - rcu: Fix detection of abruptly-ending stall.
    (bnc#816586)

  - rcu: Suppress NMI backtraces when stall ends before
    dump. (bnc#816586)

  - Update Xen patches to 3.0.74.

  - btrfs: do not re-enter when allocating a chunk.

  - btrfs: save us a read_lock.

  - btrfs: Check CAP_DAC_READ_SEARCH for
    BTRFS_IOC_INO_PATHS.

  - btrfs: remove unused fs_info from btrfs_decode_error().

  - btrfs: handle null fs_info in btrfs_panic().

  - btrfs: fix varargs in __btrfs_std_error.

  - btrfs: fix the race between bio and btrfs_stop_workers.

  - btrfs: fix NULL pointer after aborting a transaction.

  - btrfs: fix infinite loop when we abort on mount.

  - xfs: Do not allocate new buffers on every call to
    _xfs_buf_find. (bnc#763968)

  - xfs: fix buffer lookup race on allocation failure.
    (bnc#763968)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=788590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804154"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=805945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=810580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=810624"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821930"
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
    value:"http://support.novell.com/security/cve/CVE-2013-0160.html"
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
    value:"Apply SAT patch number 7811 / 7813 / 7814 as appropriate."
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/18");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-extra-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-extra-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-source-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-extra-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-extra-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-extra-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-source-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-syms-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-extra-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-extra-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.5_02_3.0.80_0.5-0.5.5")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.5_02_3.0.80_0.5-0.5.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-source-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-syms-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-man-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.80-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.5_02_3.0.80_0.5-0.5.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.5_02_3.0.80_0.5-0.5.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
