#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:1832-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83603);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2009-4020", "CVE-2009-4067", "CVE-2010-3880", "CVE-2010-4249", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-2203", "CVE-2011-2213", "CVE-2011-2484", "CVE-2011-2492", "CVE-2011-2494", "CVE-2011-2525", "CVE-2011-2534", "CVE-2011-2699", "CVE-2011-2928", "CVE-2011-3209", "CVE-2011-3363", "CVE-2011-4077", "CVE-2011-4110", "CVE-2011-4132", "CVE-2011-4324", "CVE-2011-4330", "CVE-2012-2136", "CVE-2012-3510", "CVE-2012-4444", "CVE-2012-4530", "CVE-2012-6537", "CVE-2012-6539", "CVE-2012-6540", "CVE-2012-6541", "CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2012-6547", "CVE-2012-6549", "CVE-2013-0160", "CVE-2013-0268", "CVE-2013-0871", "CVE-2013-0914", "CVE-2013-1827", "CVE-2013-1928", "CVE-2013-2141", "CVE-2013-2147", "CVE-2013-2164", "CVE-2013-2206", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235");
  script_bugtraq_id(44665, 45037, 46919, 46921, 48236, 48333, 48383, 48441, 48641, 48687, 48802, 49256, 49626, 50311, 50314, 50370, 50663, 50750, 50755, 50798, 53721, 55144, 55878, 56891, 57176, 57838, 57986, 58383, 58409, 58426, 58906, 58977, 58985, 58986, 58987, 58989, 58990, 58991, 58992, 58993, 58996, 59377, 59380, 59381, 59383, 59389, 59390, 59393, 59394, 59397, 60254, 60280, 60375, 60715, 60874, 60893, 60953);
  script_osvdb_id(60795, 69527, 73293, 73295, 73296, 73297, 73451, 73459, 73460, 74653, 74657, 74678, 74823, 75580, 75714, 76641, 76796, 77092, 77355, 77450, 77625, 77658, 77683, 82459, 86575, 86926, 88364, 89143, 90003, 90301, 90958, 90959, 90961, 90963, 90964, 90965, 90967, 90969, 90970, 90971, 91271, 92021, 92656, 92657, 92660, 92661, 92663, 92664, 92666, 92667, 92669, 93907, 94027, 94033, 94456, 94698, 94793, 94853);

  script_name(english:"SUSE SLES10 Security Update : kernel (SUSE-SU-2013:1832-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise Server 10 SP3 LTSS kernel received a roll up
update to fix lots of moderate security issues and several bugs.

The Following security issues have been fixed :

CVE-2012-4530: The load_script function in fs/binfmt_script.c in the
Linux kernel did not properly handle recursion, which allowed local
users to obtain sensitive information from kernel stack memory via a
crafted application.

CVE-2011-2494: kernel/taskstats.c in the Linux kernel
allowed local users to obtain sensitive I/O statistics by
sending taskstats commands to a netlink socket, as
demonstrated by discovering the length of another users
password.

CVE-2013-2234: The (1) key_notify_sa_flush and (2)
key_notify_policy_flush functions in net/key/af_key.c in the
Linux kernel did not initialize certain structure members,
which allowed local users to obtain sensitive information
from kernel heap memory by reading a broadcast message from
the notify interface of an IPSec key_socket.

CVE-2013-2237: The key_notify_policy_flush function in
net/key/af_key.c in the Linux kernel did not initialize a
certain structure member, which allowed local users to
obtain sensitive information from kernel heap memory by
reading a broadcast message from the notify_policy interface
of an IPSec key_socket.

CVE-2013-2147: The HP Smart Array controller disk-array
driver and Compaq SMART2 controller disk-array driver in the
Linux kernel did not initialize certain data structures,
which allowed local users to obtain sensitive information
from kernel memory via (1) a crafted IDAGETPCIINFO command
for a /dev/ida device, related to the ida_locked_ioctl
function in drivers/block/cpqarray.c or (2) a crafted
CCISS_PASSTHRU32 command for a /dev/cciss device, related to
the cciss_ioctl32_passthru function in
drivers/block/cciss.c.

CVE-2013-2141: The do_tkill function in kernel/signal.c in
the Linux kernel did not initialize a certain data
structure, which allowed local users to obtain sensitive
information from kernel memory via a crafted application
that makes a (1) tkill or (2) tgkill system call.

CVE-2013-0160: The Linux kernel allowed local users to
obtain sensitive information about keystroke timing by using
the inotify API on the /dev/ptmx device.

CVE-2012-6537: net/xfrm/xfrm_user.c in the Linux kernel did
not initialize certain structures, which allowed local users
to obtain sensitive information from kernel memory by
leveraging the CAP_NET_ADMIN capability.

CVE-2013-3222: The vcc_recvmsg function in net/atm/common.c
in the Linux kernel did not initialize a certain length
variable, which allowed local users to obtain sensitive
information from kernel stack memory via a crafted recvmsg
or recvfrom system call.

CVE-2013-3223: The ax25_recvmsg function in
net/ax25/af_ax25.c in the Linux kernel did not initialize a
certain data structure, which allowed local users to obtain
sensitive information from kernel stack memory via a crafted
recvmsg or recvfrom system call.

CVE-2013-3224: The bt_sock_recvmsg function in
net/bluetooth/af_bluetooth.c in the Linux kernel did not
properly initialize a certain length variable, which allowed
local users to obtain sensitive information from kernel
stack memory via a crafted recvmsg or recvfrom system call.

CVE-2013-3228: The irda_recvmsg_dgram function in
net/irda/af_irda.c in the Linux kernel did not initialize a
certain length variable, which allowed local users to obtain
sensitive information from kernel stack memory via a crafted
recvmsg or recvfrom system call.

CVE-2013-3229: The iucv_sock_recvmsg function in
net/iucv/af_iucv.c in the Linux kernel did not initialize a
certain length variable, which allowed local users to obtain
sensitive information from kernel stack memory via a crafted
recvmsg or recvfrom system call.

CVE-2013-3231: The llc_ui_recvmsg function in
net/llc/af_llc.c in the Linux kernel did not initialize a
certain length variable, which allowed local users to obtain
sensitive information from kernel stack memory via a crafted
recvmsg or recvfrom system call.

CVE-2013-3232: The nr_recvmsg function in
net/netrom/af_netrom.c in the Linux kernel did not
initialize a certain data structure, which allowed local
users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call.

CVE-2013-3234: The rose_recvmsg function in
net/rose/af_rose.c in the Linux kernel did not initialize a
certain data structure, which allowed local users to obtain
sensitive information from kernel stack memory via a crafted
recvmsg or recvfrom system call.

CVE-2013-3235: net/tipc/socket.c in the Linux kernel did not
initialize a certain data structure and a certain length
variable, which allowed local users to obtain sensitive
information from kernel stack memory via a crafted recvmsg
or recvfrom system call.

CVE-2013-1827: net/dccp/ccid.h in the Linux kernel allowed
local users to gain privileges or cause a denial of service
(NULL pointer dereference and system crash) by leveraging
the CAP_NET_ADMIN capability for a certain (1) sender or (2)
receiver getsockopt call.

CVE-2012-6549: The isofs_export_encode_fh function in
fs/isofs/export.c in the Linux kernel did not initialize a
certain structure member, which allowed local users to
obtain sensitive information from kernel heap memory via a
crafted application.

CVE-2012-6547: The __tun_chr_ioctl function in
drivers/net/tun.c in the Linux kernel did not initialize a
certain structure, which allowed local users to obtain
sensitive information from kernel stack memory via a crafted
application.

CVE-2012-6546: The ATM implementation in the Linux kernel
did not initialize certain structures, which allowed local
users to obtain sensitive information from kernel stack
memory via a crafted application.

CVE-2012-6544: The Bluetooth protocol stack in the Linux
kernel did not properly initialize certain structures, which
allowed local users to obtain sensitive information from
kernel stack memory via a crafted application that targets
the (1) L2CAP or (2) HCI implementation.

CVE-2012-6545: The Bluetooth RFCOMM implementation in the
Linux kernel did not properly initialize certain structures,
which allowed local users to obtain sensitive information
from kernel memory via a crafted application.

CVE-2012-6542: The llc_ui_getname function in
net/llc/af_llc.c in the Linux kernel had an incorrect return
value in certain circumstances, which allowed local users to
obtain sensitive information from kernel stack memory via a
crafted application that leverages an uninitialized pointer
argument.

CVE-2012-6541: The ccid3_hc_tx_getsockopt function in
net/dccp/ccids/ccid3.c in the Linux kernel did not
initialize a certain structure, which allowed local users to
obtain sensitive information from kernel stack memory via a
crafted application.

CVE-2012-6540: The do_ip_vs_get_ctl function in
net/netfilter/ipvs/ip_vs_ctl.c in the Linux kernel did not
initialize a certain structure for IP_VS_SO_GET_TIMEOUT
commands, which allowed local users to obtain sensitive
information from kernel stack memory via a crafted
application.

CVE-2013-0914: The flush_signal_handlers function in
kernel/signal.c in the Linux kernel preserved the value of
the sa_restorer field across an exec operation, which made
it easier for local users to bypass the ASLR protection
mechanism via a crafted application containing a sigaction
system call.

CVE-2011-2492: The bluetooth subsystem in the Linux kernel
did not properly initialize certain data structures, which
allowed local users to obtain potentially sensitive
information from kernel memory via a crafted getsockopt
system call, related to (1) the l2cap_sock_getsockopt_old
function in net/bluetooth/l2cap_sock.c and (2) the
rfcomm_sock_getsockopt_old function in
net/bluetooth/rfcomm/sock.c.

CVE-2013-2206: The sctp_sf_do_5_2_4_dupcook function in
net/sctp/sm_statefuns.c in the SCTP implementation in the
Linux kernel did not properly handle associations during the
processing of a duplicate COOKIE ECHO chunk, which allowed
remote attackers to cause a denial of service (NULL pointer
dereference and system crash) or possibly have unspecified
other impact via crafted SCTP traffic.

CVE-2012-6539: The dev_ifconf function in net/socket.c in
the Linux kernel did not initialize a certain structure,
which allowed local users to obtain sensitive information
from kernel stack memory via a crafted application.

CVE-2013-2232: The ip6_sk_dst_check function in
net/ipv6/ip6_output.c in the Linux kernel allowed local
users to cause a denial of service (system crash) by using
an AF_INET6 socket for a connection to an IPv4 interface.

CVE-2013-2164: The mmc_ioctl_cdrom_read_data function in
drivers/cdrom/cdrom.c in the Linux kernel allowed local
users to obtain sensitive information from kernel memory via
a read operation on a malfunctioning CD-ROM drive.

CVE-2012-4444: The ip6_frag_queue function in
net/ipv6/reassembly.c in the Linux kernel allowed remote
attackers to bypass intended network restrictions via
overlapping IPv6 fragments.

CVE-2013-1928: The do_video_set_spu_palette function in
fs/compat_ioctl.c in the Linux kernel on unspecified
architectures lacked a certain error check, which might have
allowed local users to obtain sensitive information from
kernel stack memory via a crafted VIDEO_SET_SPU_PALETTE
ioctl call on a /dev/dvb device.

CVE-2013-0871: Race condition in the ptrace functionality in
the Linux kernel allowed local users to gain privileges via
a PTRACE_SETREGS ptrace system call in a crafted
application, as demonstrated by ptrace_death.

CVE-2013-0268: The msr_open function in
arch/x86/kernel/msr.c in the Linux kernel allowed local
users to bypass intended capability restrictions by
executing a crafted application as root, as demonstrated by
msr32.c.

CVE-2012-3510: Use-after-free vulnerability in the
xacct_add_tsk function in kernel/tsacct.c in the Linux
kernel allowed local users to obtain potentially sensitive
information from kernel memory or cause a denial of service
(system crash) via a taskstats TASKSTATS_CMD_ATTR_PID
command.

CVE-2011-4110: The user_update function in
security/keys/user_defined.c in the Linux kernel allowed
local users to cause a denial of service (NULL pointer
dereference and kernel oops) via vectors related to a
user-defined key and 'updating a negative key into a fully
instantiated key.'

CVE-2012-2136: The sock_alloc_send_pskb function in
net/core/sock.c in the Linux kernel did not properly
validate a certain length value, which allowed local users
to cause a denial of service (heap-based buffer overflow and
system crash) or possibly gain privileges by leveraging
access to a TUN/TAP device.

CVE-2009-4020: Stack-based buffer overflow in the hfs
subsystem in the Linux kernel allowed remote attackers to
have an unspecified impact via a crafted Hierarchical File
System (HFS) filesystem, related to the hfs_readdir function
in fs/hfs/dir.c.

CVE-2011-2928: The befs_follow_link function in
fs/befs/linuxvfs.c in the Linux kernel did not validate the
length attribute of long symlinks, which allowed local users
to cause a denial of service (incorrect pointer dereference
and OOPS) by accessing a long symlink on a malformed Be
filesystem.

CVE-2011-4077: Buffer overflow in the xfs_readlink function
in fs/xfs/xfs_vnodeops.c in XFS in the Linux kernel, when
CONFIG_XFS_DEBUG is disabled, allowed local users to cause a
denial of service (memory corruption and crash) and possibly
execute arbitrary code via an XFS image containing a
symbolic link with a long pathname.

CVE-2011-4324: The encode_share_access function in
fs/nfs/nfs4xdr.c in the Linux kernel allowed local users to
cause a denial of service (BUG and system crash) by using
the mknod system call with a pathname on an NFSv4
filesystem.

CVE-2011-4330: Stack-based buffer overflow in the
hfs_mac2asc function in fs/hfs/trans.c in the Linux kernel
allowed local users to cause a denial of service (crash) and
possibly execute arbitrary code via an HFS image with a
crafted len field.

CVE-2011-1172: net/ipv6/netfilter/ip6_tables.c in the IPv6
implementation in the Linux kernel did not place the
expected 0 character at the end of string data in the values
of certain structure members, which allowed local users to
obtain potentially sensitive information from kernel memory
by leveraging the CAP_NET_ADMIN capability to issue a
crafted request, and then reading the argument to the
resulting modprobe process.

CVE-2011-2525: The qdisc_notify function in
net/sched/sch_api.c in the Linux kernel did not prevent
tc_fill_qdisc function calls referencing builtin (aka
CQ_F_BUILTIN) Qdisc structures, which allowed local users to
cause a denial of service (NULL pointer dereference and
OOPS) or possibly have unspecified other impact via a
crafted call.

CVE-2011-2699: The IPv6 implementation in the Linux kernel
did not generate Fragment Identification values separately
for each destination, which made it easier for remote
attackers to cause a denial of service (disrupted
networking) by predicting these values and sending crafted
packets.

CVE-2011-1171: net/ipv4/netfilter/ip_tables.c in the IPv4
implementation in the Linux kernel did not place the
expected 0 character at the end of string data in the values
of certain structure members, which allowed local users to
obtain potentially sensitive information from kernel memory
by leveraging the CAP_NET_ADMIN capability to issue a
crafted request, and then reading the argument to the
resulting modprobe process.

CVE-2011-1170: net/ipv4/netfilter/arp_tables.c in the IPv4
implementation in the Linux kernel did not place the
expected 0 character at the end of string data in the values
of certain structure members, which allowed local users to
obtain potentially sensitive information from kernel memory
by leveraging the CAP_NET_ADMIN capability to issue a
crafted request, and then reading the argument to the
resulting modprobe process.

CVE-2011-3209: The div_long_long_rem implementation in
include/asm-x86/div64.h in the Linux kernel on the x86
platform allowed local users to cause a denial of service
(Divide Error Fault and panic) via a clock_gettime system
call.

CVE-2011-2213: The inet_diag_bc_audit function in
net/ipv4/inet_diag.c in the Linux kernel did not properly
audit INET_DIAG bytecode, which allowed local users to cause
a denial of service (kernel infinite loop) via crafted
INET_DIAG_REQ_BYTECODE instructions in a netlink message, as
demonstrated by an INET_DIAG_BC_JMP instruction with a zero
yes value, a different vulnerability than CVE-2010-3880.

CVE-2011-2534: Buffer overflow in the clusterip_proc_write
function in net/ipv4/netfilter/ipt_CLUSTERIP.c in the Linux
kernel might have allowed local users to cause a denial of
service or have unspecified other impact via a crafted write
operation, related to string data that lacks a terminating 0
character.

CVE-2011-2699: The IPv6 implementation in the Linux kernel
did not generate Fragment Identification values separately
for each destination, which made it easier for remote
attackers to cause a denial of service (disrupted
networking) by predicting these values and sending crafted
packets.

CVE-2011-2203: The hfs_find_init function in the Linux
kernel allowed local users to cause a denial of service
(NULL pointer dereference and Oops) by mounting an HFS file
system with a malformed MDB extent record.

CVE-2009-4067: A USB string descriptor overflow in the
auerwald USB driver was fixed, which could be used by
physically proximate attackers to cause a kernel crash.

CVE-2011-3363: The setup_cifs_sb function in
fs/cifs/connect.c in the Linux kernel did not properly
handle DFS referrals, which allowed remote CIFS servers to
cause a denial of service (system crash) by placing a
referral at the root of a share.

CVE-2011-2484: The add_del_listener function in
kernel/taskstats.c in the Linux kernel did not prevent
multiple registrations of exit handlers, which allowed local
users to cause a denial of service (memory and CPU
consumption), and bypass the OOM Killer, via a crafted
application.

CVE-2011-4132: The cleanup_journal_tail function in the
Journaling Block Device (JBD) functionality in the Linux
kernel allowed local users to cause a denial of service
(assertion error and kernel oops) via an ext3 or ext4 image
with an 'invalid log first block value.'

CVE-2010-4249: The wait_for_unix_gc function in
net/unix/garbage.c in the Linux kernel before
2.6.37-rc3-next-20101125 does not properly select times for
garbage collection of inflight sockets, which allows local
users to cause a denial of service (system hang) via crafted
use of the socketpair and sendmsg system calls for
SOCK_SEQPACKET sockets.

The following bugs have been fixed :

patches.fixes/allow-executables-larger-than-2GB.patch: Allow
executables larger than 2GB (bnc#836856).

cio: prevent kernel panic after unexpected I/O interrupt
(bnc#649868,LTC#67975).

  - cio: Add timeouts for internal IO
    (bnc#701550,LTC#72691). kernel: first time swap use
    results in heavy swapping (bnc#701550,LTC#73132).

    qla2xxx: Do not be so verbose on underrun detected

    patches.arch/i386-run-tsc-calibration-5-times.patch: Fix
    the patch, the logic was wrong (bnc#537165, bnc#826551).

    xfs: Do not reclaim new inodes in xfs_sync_inodes()
    (bnc#770980 bnc#811752).

    kbuild: Fix gcc -x syntax (bnc#773831).

    e1000e: stop cleaning when we reach tx_ring->next_to_use
    (bnc#762825).

    Fix race condition about network device name allocation
    (bnc#747576).

    kdump: bootmem map over crash reserved region
    (bnc#749168, bnc#722400, bnc#742881).

    tcp: fix race condition leading to premature termination
    of sockets in FIN_WAIT2 state and connection being reset
    (bnc#745760)

    tcp: drop SYN+FIN messages (bnc#765102).

    net/linkwatch: Handle jiffies wrap-around (bnc#740131).

    patches.fixes/vm-dirty-bytes: Provide
    /proc/sys/vm/dirty_{background_,}bytes for tuning
    (bnc#727597).

    ipmi: Fix deadlock in start_next_msg() (bnc#730749).

    cpu-hotplug: release workqueue_mutex properly on CPU
    hot-remove (bnc#733407).

    libiscsi: handle init task failures (bnc#721351).

    NFS/sunrpc: do not use a credential with extra groups
    (bnc#725878).

    x86_64: fix reboot hang when 'reboot=b' is passed to the
    kernel (bnc#721267).

    nf_nat: do not add NAT extension for confirmed
    conntracks (bnc#709213).

    xfs: fix memory reclaim recursion deadlock on locked
    inode buffer (bnc#699355 bnc#699354 bnc#721830).

    ipmi: do not grab locks in run-to-completion mode
    (bnc#717421).

    cciss: do not attempt to read from a write-only register
    (bnc#683101).

    qla2xxx: Disable MSI-X initialization (bnc#693513).

    Allow balance_dirty_pages to help other filesystems
    (bnc#709369).

  - nfs: fix congestion control (bnc#709369).

  - NFS: Separate metadata and page cache revalidation
    mechanisms (bnc#709369). knfsd: nfsd4: fix laundromat
    shutdown race (bnc#752556).

    x87: Do not synchronize TSCs across cores if they
    already should be synchronized by HW (bnc#615418
    bnc#609220).

    reiserfs: Fix int overflow while calculating free space
    (bnc#795075).

    af_unix: limit recursion level (bnc#656153).

    bcm43xx: netlink deadlock fix (bnc#850241).

    jbd: Issue cache flush after checkpointing (bnc#731770).

    cfq: Fix infinite loop in cfq_preempt_queue()
    (bnc#724692).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=2edd49abdf9ae71916d1b5acb9177a75
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84146da5"
  );
  # http://download.suse.com/patch/finder/?keywords=ab3d3594ee8b8099b9bc0f2a2095b6b6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63bff963"
  );
  # http://download.suse.com/patch/finder/?keywords=ffdbcc106c0e9486ae78943c42345dbd
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c83cccb2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4067.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4249.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1170.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1171.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1172.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2203.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2213.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2492.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2525.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2534.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2699.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2928.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3209.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3363.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4132.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4324.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4330.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2136.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3510.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4530.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6539.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6540.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6541.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6542.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6544.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6545.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6546.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6549.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0268.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0871.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0914.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1827.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1928.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2141.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2147.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2164.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2206.html"
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
    attribute:"see_also",
    value:"https://bugzilla.novell.com/537165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/609220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/615418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/649868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/656153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/681180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/681181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/681185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/683101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/693513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/699354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/699355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/699709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/700879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/701550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/702014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/702037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/703153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/703156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/706375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/707288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/709213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/709369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/713430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/717421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/718028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/721267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/721351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/721830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/722400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/724692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/725878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/726064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/726600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/727597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/730118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/730749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/731673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/731770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/732613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/733407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/734056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/735612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/740131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/742881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/745760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/747576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/749168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/752556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/760902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/762825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/765102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/765320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/770980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/773831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/776888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/786013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/789831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/795075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/797175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/802642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/804154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/808827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/809889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/809891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/809892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/809893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/809894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/809898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/809899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/809900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/809901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/809903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/811354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/811752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/813735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/815745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/816668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/823260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/823267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/824295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/826102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/826551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/827749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/827750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/828119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/836856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/850241"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20131832-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9303456"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kdumppae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vmipae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^3$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-kdumppae-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-vmi-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-vmipae-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-xenpae-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"kernel-default-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"kernel-source-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"kernel-syms-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-debug-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-smp-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-xen-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-kdumppae-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.113.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.113.1")) flag++;


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
