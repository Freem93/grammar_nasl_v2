#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0536-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83618);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2011-2492", "CVE-2011-2494", "CVE-2012-6537", "CVE-2012-6539", "CVE-2012-6540", "CVE-2012-6541", "CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2012-6547", "CVE-2012-6549", "CVE-2013-0343", "CVE-2013-0914", "CVE-2013-1827", "CVE-2013-2141", "CVE-2013-2164", "CVE-2013-2206", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2888", "CVE-2013-2893", "CVE-2013-2897", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235", "CVE-2013-4162", "CVE-2013-4387", "CVE-2013-4470", "CVE-2013-4483", "CVE-2013-4588", "CVE-2013-6383", "CVE-2014-1444", "CVE-2014-1445", "CVE-2014-1446");
  script_bugtraq_id(48441, 50314, 58383, 58409, 58426, 58795, 58977, 58985, 58986, 58987, 58989, 58990, 58991, 58992, 58993, 58996, 59377, 59380, 59381, 59383, 59389, 59390, 59393, 59394, 59397, 60254, 60375, 60715, 60874, 60893, 60953, 61411, 62043, 62044, 62050, 62696, 63359, 63445, 63744, 63888, 64952, 64953, 64954);
  script_osvdb_id(73459, 73460, 76796, 90811, 90958, 90959, 90961, 90963, 90964, 90965, 90967, 90969, 90970, 90971, 91271, 92656, 92657, 92660, 92661, 92663, 92664, 92666, 92667, 92669, 93907, 94033, 94456, 94698, 94793, 94853, 95614, 96767, 96770, 96774, 97888, 98941, 99161, 99999, 100292, 102446, 102498, 102499);

  script_name(english:"SUSE SLES10 Security Update : kernel (SUSE-SU-2014:0536-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise Server 10 Service Pack 4 LTSS kernel has
been updated to fix various security issues and several bugs.

The following security issues have been addressed :

CVE-2011-2492: The bluetooth subsystem in the Linux kernel before
3.0-rc4 does not properly initialize certain data structures, which
allows local users to obtain potentially sensitive information from
kernel memory via a crafted getsockopt system call, related to (1) the
l2cap_sock_getsockopt_old function in net/bluetooth/l2cap_sock.c and
(2) the rfcomm_sock_getsockopt_old function in
net/bluetooth/rfcomm/sock.c. (bnc#702014)

CVE-2011-2494: kernel/taskstats.c in the Linux kernel before
3.1 allows local users to obtain sensitive I/O statistics by
sending taskstats commands to a netlink socket, as
demonstrated by discovering the length of another user's
password. (bnc#703156)

CVE-2012-6537: net/xfrm/xfrm_user.c in the Linux kernel
before 3.6 does not initialize certain structures, which
allows local users to obtain sensitive information from
kernel memory by leveraging the CAP_NET_ADMIN capability.
(bnc#809889)

CVE-2012-6539: The dev_ifconf function in net/socket.c in
the Linux kernel before 3.6 does not initialize a certain
structure, which allows local users to obtain sensitive
information from kernel stack memory via a crafted
application. (bnc#809891)

CVE-2012-6540: The do_ip_vs_get_ctl function in
net/netfilter/ipvs/ip_vs_ctl.c in the Linux kernel before
3.6 does not initialize a certain structure for
IP_VS_SO_GET_TIMEOUT commands, which allows local users to
obtain sensitive information from kernel stack memory via a
crafted application. (bnc#809892)

CVE-2012-6541: The ccid3_hc_tx_getsockopt function in
net/dccp/ccids/ccid3.c in the Linux kernel before 3.6 does
not initialize a certain structure, which allows local users
to obtain sensitive information from kernel stack memory via
a crafted application. (bnc#809893)

CVE-2012-6542: The llc_ui_getname function in
net/llc/af_llc.c in the Linux kernel before 3.6 has an
incorrect return value in certain circumstances, which
allows local users to obtain sensitive information from
kernel stack memory via a crafted application that leverages
an uninitialized pointer argument. (bnc#809894)

CVE-2012-6544: The Bluetooth protocol stack in the Linux
kernel before 3.6 does not properly initialize certain
structures, which allows local users to obtain sensitive
information from kernel stack memory via a crafted
application that targets the (1) L2CAP or (2) HCI
implementation. (bnc#809898)

CVE-2012-6545: The Bluetooth RFCOMM implementation in the
Linux kernel before 3.6 does not properly initialize certain
structures, which allows local users to obtain sensitive
information from kernel memory via a crafted application.
(bnc#809899)

CVE-2012-6546: The ATM implementation in the Linux kernel
before 3.6 does not initialize certain structures, which
allows local users to obtain sensitive information from
kernel stack memory via a crafted application. (bnc#809900)

CVE-2012-6547: The __tun_chr_ioctl function in
drivers/net/tun.c in the Linux kernel before 3.6 does not
initialize a certain structure, which allows local users to
obtain sensitive information from kernel stack memory via a
crafted application. (bnc#809901)

CVE-2012-6549: The isofs_export_encode_fh function in
fs/isofs/export.c in the Linux kernel before 3.6 does not
initialize a certain structure member, which allows local
users to obtain sensitive information from kernel heap
memory via a crafted application. (bnc#809903)

CVE-2013-0343: The ipv6_create_tempaddr function in
net/ipv6/addrconf.c in the Linux kernel through 3.8 does not
properly handle problems with the generation of IPv6
temporary addresses, which allows remote attackers to cause
a denial of service (excessive retries and
address-generation outage), and consequently obtain
sensitive information, via ICMPv6 Router Advertisement (RA)
messages. (bnc#805226)

CVE-2013-0914: The flush_signal_handlers function in
kernel/signal.c in the Linux kernel before 3.8.4 preserves
the value of the sa_restorer field across an exec operation,
which makes it easier for local users to bypass the ASLR
protection mechanism via a crafted application containing a
sigaction system call. (bnc#808827)

CVE-2013-1827: net/dccp/ccid.h in the Linux kernel before
3.5.4 allows local users to gain privileges or cause a
denial of service (NULL pointer dereference and system
crash) by leveraging the CAP_NET_ADMIN capability for a
certain (1) sender or (2) receiver getsockopt call.
(bnc#811354)

CVE-2013-2141: The do_tkill function in kernel/signal.c in
the Linux kernel before 3.8.9 does not initialize a certain
data structure, which allows local users to obtain sensitive
information from kernel memory via a crafted application
that makes a (1) tkill or (2) tgkill system call.
(bnc#823267)

CVE-2013-2164: The mmc_ioctl_cdrom_read_data function in
drivers/cdrom/cdrom.c in the Linux kernel through 3.10
allows local users to obtain sensitive information from
kernel memory via a read operation on a malfunctioning
CD-ROM drive. (bnc#824295)

CVE-2013-2206: The sctp_sf_do_5_2_4_dupcook function in
net/sctp/sm_statefuns.c in the SCTP implementation in the
Linux kernel before 3.8.5 does not properly handle
associations during the processing of a duplicate COOKIE
ECHO chunk, which allows remote attackers to cause a denial
of service (NULL pointer dereference and system crash) or
possibly have unspecified other impact via crafted SCTP
traffic. (bnc#826102)

CVE-2013-2232: The ip6_sk_dst_check function in
net/ipv6/ip6_output.c in the Linux kernel before 3.10 allows
local users to cause a denial of service (system crash) by
using an AF_INET6 socket for a connection to an IPv4
interface. (bnc#827750)

CVE-2013-2234: The (1) key_notify_sa_flush and (2)
key_notify_policy_flush functions in net/key/af_key.c in the
Linux kernel before 3.10 do not initialize certain structure
members, which allows local users to obtain sensitive
information from kernel heap memory by reading a broadcast
message from the notify interface of an IPSec key_socket.
(bnc#827749)

CVE-2013-2237: The key_notify_policy_flush function in
net/key/af_key.c in the Linux kernel before 3.9 does not
initialize a certain structure member, which allows local
users to obtain sensitive information from kernel heap
memory by reading a broadcast message from the notify_policy
interface of an IPSec key_socket. (bnc#828119)

CVE-2013-2888: Multiple array index errors in
drivers/hid/hid-core.c in the Human Interface Device (HID)
subsystem in the Linux kernel through 3.11 allow physically
proximate attackers to execute arbitrary code or cause a
denial of service (heap memory corruption) via a crafted
device that provides an invalid Report ID. (bnc#835839)

CVE-2013-2893: The Human Interface Device (HID) subsystem in
the Linux kernel through 3.11, when CONFIG_LOGITECH_FF,
CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF is enabled,
allows physically proximate attackers to cause a denial of
service (heap-based out-of-bounds write) via a crafted
device, related to (1) drivers/hid/hid-lgff.c, (2)
drivers/hid/hid-lg3ff.c, and (3) drivers/hid/hid-lg4ff.c.
(bnc#835839)

CVE-2013-2897: Multiple array index errors in
drivers/hid/hid-multitouch.c in the Human Interface Device
(HID) subsystem in the Linux kernel through 3.11, when
CONFIG_HID_MULTITOUCH is enabled, allow physically proximate
attackers to cause a denial of service (heap memory
corruption, or NULL pointer dereference and OOPS) via a
crafted device. (bnc#835839)

CVE-2013-3222: The vcc_recvmsg function in net/atm/common.c
in the Linux kernel before 3.9-rc7 does not initialize a
certain length variable, which allows local users to obtain
sensitive information from kernel stack memory via a crafted
recvmsg or recvfrom system call. (bnc#816668)

CVE-2013-3223: The ax25_recvmsg function in
net/ax25/af_ax25.c in the Linux kernel before 3.9-rc7 does
not initialize a certain data structure, which allows local
users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call.
(bnc#816668)

CVE-2013-3224: The bt_sock_recvmsg function in
net/bluetooth/af_bluetooth.c in the Linux kernel before
3.9-rc7 does not properly initialize a certain length
variable, which allows local users to obtain sensitive
information from kernel stack memory via a crafted recvmsg
or recvfrom system call. (bnc#816668)

CVE-2013-3228: The irda_recvmsg_dgram function in
net/irda/af_irda.c in the Linux kernel before 3.9-rc7 does
not initialize a certain length variable, which allows local
users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call.
(bnc#816668)

CVE-2013-3229: The iucv_sock_recvmsg function in
net/iucv/af_iucv.c in the Linux kernel before 3.9-rc7 does
not initialize a certain length variable, which allows local
users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call.
(bnc#816668)

CVE-2013-3231: The llc_ui_recvmsg function in
net/llc/af_llc.c in the Linux kernel before 3.9-rc7 does not
initialize a certain length variable, which allows local
users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call.
(bnc#816668)

CVE-2013-3232: The nr_recvmsg function in
net/netrom/af_netrom.c in the Linux kernel before 3.9-rc7
does not initialize a certain data structure, which allows
local users to obtain sensitive information from kernel
stack memory via a crafted recvmsg or recvfrom system call.
(bnc#816668)

CVE-2013-3234: The rose_recvmsg function in
net/rose/af_rose.c in the Linux kernel before 3.9-rc7 does
not initialize a certain data structure, which allows local
users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call.
(bnc#816668)

CVE-2013-3235: net/tipc/socket.c in the Linux kernel before
3.9-rc7 does not initialize a certain data structure and a
certain length variable, which allows local users to obtain
sensitive information from kernel stack memory via a crafted
recvmsg or recvfrom system call. (bnc#816668)

CVE-2013-4162: The udp_v6_push_pending_frames function in
net/ipv6/udp.c in the IPv6 implementation in the Linux
kernel through 3.10.3 makes an incorrect function call for
pending data, which allows local users to cause a denial of
service (BUG and system crash) via a crafted application
that uses the UDP_CORK option in a setsockopt system call.
(bnc#831058)

CVE-2013-4387: net/ipv6/ip6_output.c in the Linux kernel
through 3.11.4 does not properly determine the need for UDP
Fragmentation Offload (UFO) processing of small packets
after the UFO queueing of a large packet, which allows
remote attackers to cause a denial of service (memory
corruption and system crash) or possibly have unspecified
other impact via network traffic that triggers a large
response packet. (bnc#843430)

CVE-2013-4470: The Linux kernel before 3.12, when UDP
Fragmentation Offload (UFO) is enabled, does not properly
initialize certain data structures, which allows local users
to cause a denial of service (memory corruption and system
crash) or possibly gain privileges via a crafted application
that uses the UDP_CORK option in a setsockopt system call
and sends both short and long packets, related to the
ip_ufo_append_data function in net/ipv4/ip_output.c and the
ip6_ufo_append_data function in net/ipv6/ip6_output.c.
(bnc#847672)

CVE-2013-4483: The ipc_rcu_putref function in ipc/util.c in
the Linux kernel before 3.10 does not properly manage a
reference count, which allows local users to cause a denial
of service (memory consumption or system crash) via a
crafted application. (bnc#848321)

CVE-2013-4588: Multiple stack-based buffer overflows in
net/netfilter/ipvs/ip_vs_ctl.c in the Linux kernel before
2.6.33, when CONFIG_IP_VS is used, allow local users to gain
privileges by leveraging the CAP_NET_ADMIN capability for
(1) a getsockopt system call, related to the
do_ip_vs_get_ctl function, or (2) a setsockopt system call,
related to the do_ip_vs_set_ctl function. (bnc#851095)

CVE-2013-6383: The aac_compat_ioctl function in
drivers/scsi/aacraid/linit.c in the Linux kernel before
3.11.8 does not require the CAP_SYS_RAWIO capability, which
allows local users to bypass intended access restrictions
via a crafted ioctl call. (bnc#852558)

CVE-2014-1444: The fst_get_iface function in
drivers/net/wan/farsync.c in the Linux kernel before 3.11.7
does not properly initialize a certain data structure, which
allows local users to obtain sensitive information from
kernel memory by leveraging the CAP_NET_ADMIN capability for
an SIOCWANDEV ioctl call. (bnc#858869)

CVE-2014-1445: The wanxl_ioctl function in
drivers/net/wan/wanxl.c in the Linux kernel before 3.11.7
does not properly initialize a certain data structure, which
allows local users to obtain sensitive information from
kernel memory via an ioctl call. (bnc#858870)

CVE-2014-1446: The yam_ioctl function in
drivers/net/hamradio/yam.c in the Linux kernel before 3.12.8
does not initialize a certain structure member, which allows
local users to obtain sensitive information from kernel
memory by leveraging the CAP_NET_ADMIN capability for an
SIOCYAMGCFG ioctl call. (bnc#858872)

Also the following non-security bugs have been fixed :

  - kernel: Remove newline from execve audit log
    (bnc#827855).

  - kernel: sclp console hangs (bnc#830344, LTC#95711).

  - kernel: fix flush_tlb_kernel_range (bnc#825052,
    LTC#94745). kernel: lost IPIs on CPU hotplug
    (bnc#825052, LTC#94784).

    sctp: deal with multiple COOKIE_ECHO chunks
    (bnc#826102).

  - net: Uninline kfree_skb and allow NULL argument
    (bnc#853501).

  - netback: don't disconnect frontend when seeing oversize
    packet. netfront: reduce gso_max_size to account for max
    TCP header.

    fs/dcache: Avoid race in d_splice_alias and vfs_rmdir
    (bnc#845028).

  - fs/proc: proc_task_lookup() fix memory pinning
    (bnc#827362 bnc#849765).

  - blkdev_max_block: make private to fs/buffer.c
    (bnc#820338).

  - vfs: avoid 'attempt to access beyond end of device'
    warnings (bnc#820338).

  - vfs: fix O_DIRECT read past end of block device
    (bnc#820338).

  - cifs: don't use CIFSGetSrvInodeNumber in
    is_path_accessible (bnc#832603).

  - xfs: Fix kABI breakage caused by AIL list transformation
    (bnc#806219).

  - xfs: Replace custom AIL linked-list code with struct
    list_head (bnc#806219).

  - reiserfs: fix problems with chowning setuid file w/
    xattrs (bnc#790920).

  - reiserfs: fix spurious multiple-fill in
    reiserfs_readdir_dentry (bnc#822722). jbd: Fix forever
    sleeping process in do_get_write_access() (bnc#827983).

    HID: check for NULL field when setting values
    (bnc#835839).

  - HID: provide a helper for validating hid reports
    (bnc#835839).

  - bcm43xx: netlink deadlock fix (bnc#850241).

  - bnx2: Close device if tx_timeout reset fails
    (bnc#857597).

  - xfrm: invalidate dst on policy insertion/deletion
    (bnc#842239).

  - xfrm: prevent ipcomp scratch buffer race condition
    (bnc#842239).

  - lpfc: Update to 8.2.0.106 (bnc#798050).

  - Make lpfc task management timeout configurable
    (bnc#798050).

  - dpt_i2o: Remove DPTI_STATE_IOCTL (bnc#798050).

  - dpt_i2o: return SCSI_MLQUEUE_HOST_BUSY when in reset
    (bnc#798050).

  - advansys: Remove 'last_reset' references (bnc#798050).

  - tmscsim: Move 'last_reset' into host structure
    (bnc#798050). dc395: Move 'last_reset' into internal
    host structure (bnc#798050).

    scsi: remove check for 'resetting' (bnc#798050).

  - scsi: Allow error handling timeout to be specified
    (bnc#798050).

  - scsi: Eliminate error handler overload of the SCSI
    serial number (bnc#798050).

  - scsi: Reduce sequential pointer derefs in scsi_error.c
    and reduce size as well (bnc#798050).

  - scsi: Reduce error recovery time by reducing use of TURs
    (bnc#798050).

  - scsi: fix eh wakeup (scsi_schedule_eh vs
    scsi_restart_operations)

  - scsi: cleanup setting task state in scsi_error_handler()
    (bnc#798050).

  - scsi: Add 'eh_deadline' to limit SCSI EH runtime
    (bnc#798050).

  - scsi: Fixup compilation warning (bnc#798050).

  - scsi: fc class: fix scanning when devs are offline
    (bnc#798050).

  - scsi: Warn on invalid command completion (bnc#798050).

  - scsi: Retry failfast commands after EH (bnc#798050).

  - scsi: kABI fixes (bnc#798050).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=bd99d2fcd47fefd9c76757c1e9e1cccb
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2aa0bd1"
  );
  # http://download.suse.com/patch/finder/?keywords=d046a694b83b003f9bb6b21b6c0e8e6f
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?978cc4de"
  );
  # http://download.suse.com/patch/finder/?keywords=e59a3c9997ba1bed5bbf01d34d34a3d7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d3e6e8e"
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
    value:"http://support.novell.com/security/cve/CVE-2013-0343.html"
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
    value:"http://support.novell.com/security/cve/CVE-2013-2141.html"
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
    value:"http://support.novell.com/security/cve/CVE-2013-2888.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2893.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2897.html"
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
    value:"http://support.novell.com/security/cve/CVE-2013-4162.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4387.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4470.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4588.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1445.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/702014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/703156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/790920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/798050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/805226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/806219"
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
    value:"https://bugzilla.novell.com/816668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/820338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/822722"
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
    value:"https://bugzilla.novell.com/825052"
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
    value:"https://bugzilla.novell.com/827362"
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
    value:"https://bugzilla.novell.com/827855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/827983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/828119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/830344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/831058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/832603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/835839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/842239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/843430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/845028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/847672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/848321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/850241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/851095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/852558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/857597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/858869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/858870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/858872"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140536-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df916a1b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/16");
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
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-bigsmp-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-kdumppae-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-vmi-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-vmipae-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-xenpae-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"kernel-default-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"kernel-source-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"kernel-syms-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-debug-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-smp-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-xen-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-kdumppae-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.105.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.105.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
