#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0287-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83611);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/11/02 15:20:57 $");

  script_cve_id("CVE-2011-1083", "CVE-2011-3593", "CVE-2012-1601", "CVE-2012-2137", "CVE-2012-2372", "CVE-2012-2745", "CVE-2012-3375", "CVE-2012-3412", "CVE-2012-3430", "CVE-2012-3511", "CVE-2012-4444", "CVE-2012-4530", "CVE-2012-4565", "CVE-2012-6537", "CVE-2012-6538", "CVE-2012-6539", "CVE-2012-6540", "CVE-2012-6541", "CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2012-6547", "CVE-2012-6548", "CVE-2012-6549", "CVE-2013-0160", "CVE-2013-0216", "CVE-2013-0231", "CVE-2013-0268", "CVE-2013-0310", "CVE-2013-0343", "CVE-2013-0349", "CVE-2013-0871", "CVE-2013-0914", "CVE-2013-1767", "CVE-2013-1773", "CVE-2013-1774", "CVE-2013-1792", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1827", "CVE-2013-1928", "CVE-2013-1943", "CVE-2013-2015", "CVE-2013-2141", "CVE-2013-2147", "CVE-2013-2164", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2634", "CVE-2013-2851", "CVE-2013-2852", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2897", "CVE-2013-2929", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235", "CVE-2013-4345", "CVE-2013-4470", "CVE-2013-4483", "CVE-2013-4511", "CVE-2013-4587", "CVE-2013-4588", "CVE-2013-4591", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6378", "CVE-2013-6383", "CVE-2014-1444", "CVE-2014-1445", "CVE-2014-1446");
  script_bugtraq_id(46630, 50767, 53488, 54062, 54063, 54283, 54365, 54702, 54763, 55151, 55878, 56346, 56891, 57176, 57740, 57743, 57838, 57986, 58052, 58112, 58177, 58200, 58202, 58368, 58383, 58409, 58426, 58597, 58604, 58605, 58607, 58795, 58906, 58977, 58978, 58985, 58986, 58987, 58989, 58990, 58991, 58992, 58993, 58994, 58996, 59377, 59380, 59381, 59383, 59385, 59389, 59390, 59393, 59394, 59397, 59512, 60254, 60280, 60375, 60409, 60410, 60466, 60874, 60893, 60953, 62042, 62043, 62044, 62049, 62050, 62740, 63359, 63445, 63512, 63744, 63791, 63886, 63888, 64111, 64270, 64291, 64328, 64952, 64953, 64954);
  script_osvdb_id(71265, 77294, 81811, 83056, 83104, 83666, 83687, 84420, 84904, 85606, 86575, 88048, 88364, 89143, 89902, 89903, 90003, 90301, 90475, 90553, 90665, 90675, 90678, 90811, 90951, 90958, 90959, 90961, 90962, 90963, 90964, 90965, 90967, 90969, 90970, 90971, 91271, 91561, 91562, 91563, 91566, 92021, 92656, 92657, 92660, 92661, 92663, 92664, 92666, 92667, 92669, 92851, 93907, 94027, 94033, 94034, 94035, 94133, 94698, 94793, 94853, 96766, 96767, 96770, 96774, 96775, 98017, 98941, 99161, 99674, 99675, 99999, 100003, 100292, 100294, 100508, 100984, 100985, 100986, 102446, 102498, 102499);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2014:0287-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is a SUSE Linux Enterprise Server 11 SP1 LTSS roll up update to
fix a lot of security issues and non-security bugs.

The following security bugs have been fixed :

CVE-2011-3593: A certain Red Hat patch to the vlan_hwaccel_do_receive
function in net/8021q/vlan_core.c in the Linux kernel 2.6.32 on Red
Hat Enterprise Linux (RHEL) 6 allows remote attackers to cause a
denial of service (system crash) via priority-tagged VLAN frames.
(bnc#735347)

CVE-2012-1601: The KVM implementation in the Linux kernel
before 3.3.6 allows host OS users to cause a denial of
service (NULL pointer dereference and host OS crash) by
making a KVM_CREATE_IRQCHIP ioctl call after a virtual CPU
already exists. (bnc#754898)

CVE-2012-2137: Buffer overflow in virt/kvm/irq_comm.c in the
KVM subsystem in the Linux kernel before 3.2.24 allows local
users to cause a denial of service (crash) and possibly
execute arbitrary code via vectors related to Message
Signaled Interrupts (MSI), irq routing entries, and an
incorrect check by the setup_routing_entry function before
invoking the kvm_set_irq function. (bnc#767612)

CVE-2012-2372: The rds_ib_xmit function in net/rds/ib_send.c
in the Reliable Datagram Sockets (RDS) protocol
implementation in the Linux kernel 3.7.4 and earlier allows
local users to cause a denial of service (BUG_ON and kernel
panic) by establishing an RDS connection with the source IP
address equal to the IPoIB interfaces own IP address, as
demonstrated by rds-ping. (bnc#767610)

CVE-2012-2745: The copy_creds function in kernel/cred.c in
the Linux kernel before 3.3.2 provides an invalid
replacement session keyring to a child process, which allows
local users to cause a denial of service (panic) via a
crafted application that uses the fork system call.
(bnc#770695)

CVE-2012-3375: The epoll_ctl system call in fs/eventpoll.c
in the Linux kernel before 3.2.24 does not properly handle
ELOOP errors in EPOLL_CTL_ADD operations, which allows local
users to cause a denial of service (file-descriptor
consumption and system crash) via a crafted application that
attempts to create a circular epoll dependency. NOTE: this
vulnerability exists because of an incorrect fix for
CVE-2011-1083. (bnc#769896)

CVE-2012-3412: The sfc (aka Solarflare Solarstorm) driver in
the Linux kernel before 3.2.30 allows remote attackers to
cause a denial of service (DMA descriptor consumption and
network-controller outage) via crafted TCP packets that
trigger a small MSS value. (bnc#774523)

CVE-2012-3430: The rds_recvmsg function in net/rds/recv.c in
the Linux kernel before 3.0.44 does not initialize a certain
structure member, which allows local users to obtain
potentially sensitive information from kernel stack memory
via a (1) recvfrom or (2) recvmsg system call on an RDS
socket. (bnc#773383)

CVE-2012-3511: Multiple race conditions in the
madvise_remove function in mm/madvise.c in the Linux kernel
before 3.4.5 allow local users to cause a denial of service
(use-after-free and system crash) via vectors involving a
(1) munmap or (2) close system call. (bnc#776885)

CVE-2012-4444: The ip6_frag_queue function in
net/ipv6/reassembly.c in the Linux kernel before 2.6.36
allows remote attackers to bypass intended network
restrictions via overlapping IPv6 fragments. (bnc#789831)

CVE-2012-4530: The load_script function in
fs/binfmt_script.c in the Linux kernel before 3.7.2 does not
properly handle recursion, which allows local users to
obtain sensitive information from kernel stack memory via a
crafted application. (bnc#786013)

CVE-2012-4565: The tcp_illinois_info function in
net/ipv4/tcp_illinois.c in the Linux kernel before 3.4.19,
when the net.ipv4.tcp_congestion_control illinois setting is
enabled, allows local users to cause a denial of service
(divide-by-zero error and OOPS) by reading TCP stats.
(bnc#787576)

CVE-2012-6537: net/xfrm/xfrm_user.c in the Linux kernel
before 3.6 does not initialize certain structures, which
allows local users to obtain sensitive information from
kernel memory by leveraging the CAP_NET_ADMIN capability.
(bnc#809889)

CVE-2012-6538: The copy_to_user_auth function in
net/xfrm/xfrm_user.c in the Linux kernel before 3.6 uses an
incorrect C library function for copying a string, which
allows local users to obtain sensitive information from
kernel heap memory by leveraging the CAP_NET_ADMIN
capability. (bnc#809889)

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

CVE-2012-6548: The udf_encode_fh function in fs/udf/namei.c
in the Linux kernel before 3.6 does not initialize a certain
structure member, which allows local users to obtain
sensitive information from kernel heap memory via a crafted
application. (bnc#809902)

CVE-2012-6549: The isofs_export_encode_fh function in
fs/isofs/export.c in the Linux kernel before 3.6 does not
initialize a certain structure member, which allows local
users to obtain sensitive information from kernel heap
memory via a crafted application. (bnc#809903)

CVE-2013-0160: The Linux kernel through 3.7.9 allows local
users to obtain sensitive information about keystroke timing
by using the inotify API on the /dev/ptmx device.
(bnc#797175)

CVE-2013-0216: The Xen netback functionality in the Linux
kernel before 3.7.8 allows guest OS users to cause a denial
of service (loop) by triggering ring pointer corruption.
(bnc#800280)(XSA-39)

CVE-2013-0231: The pciback_enable_msi function in the PCI
backend driver
(drivers/xen/pciback/conf_space_capability_msi.c) in Xen for
the Linux kernel 2.6.18 and 3.8 allows guest OS users with
PCI device access to cause a denial of service via a large
number of kernel log messages. NOTE: some of these details
are obtained from third-party information.
(bnc#801178)(XSA-43)

CVE-2013-0268: The msr_open function in
arch/x86/kernel/msr.c in the Linux kernel before 3.7.6
allows local users to bypass intended capability
restrictions by executing a crafted application as root, as
demonstrated by msr32.c. (bnc#802642)

CVE-2013-0310: The cipso_v4_validate function in
net/ipv4/cipso_ipv4.c in the Linux kernel before 3.4.8
allows local users to cause a denial of service (NULL
pointer dereference and system crash) or possibly have
unspecified other impact via an IPOPT_CIPSO IP_OPTIONS
setsockopt system call. (bnc#804653)

CVE-2013-0343: The ipv6_create_tempaddr function in
net/ipv6/addrconf.c in the Linux kernel through 3.8 does not
properly handle problems with the generation of IPv6
temporary addresses, which allows remote attackers to cause
a denial of service (excessive retries and
address-generation outage), and consequently obtain
sensitive information, via ICMPv6 Router Advertisement (RA)
messages. (bnc#805226)

CVE-2013-0349: The hidp_setup_hid function in
net/bluetooth/hidp/core.c in the Linux kernel before 3.7.6
does not properly copy a certain name field, which allows
local users to obtain sensitive information from kernel
memory by setting a long name and making an HIDPCONNADD
ioctl call. (bnc#805227)

CVE-2013-0871: Race condition in the ptrace functionality in
the Linux kernel before 3.7.5 allows local users to gain
privileges via a PTRACE_SETREGS ptrace system call in a
crafted application, as demonstrated by ptrace_death.
(bnc#804154)

CVE-2013-0914: The flush_signal_handlers function in
kernel/signal.c in the Linux kernel before 3.8.4 preserves
the value of the sa_restorer field across an exec operation,
which makes it easier for local users to bypass the ASLR
protection mechanism via a crafted application containing a
sigaction system call. (bnc#808827)

CVE-2013-1767: Use-after-free vulnerability in the
shmem_remount_fs function in mm/shmem.c in the Linux kernel
before 3.7.10 allows local users to gain privileges or cause
a denial of service (system crash) by remounting a tmpfs
filesystem without specifying a required mpol (aka
mempolicy) mount option. (bnc#806138)

CVE-2013-1773: Buffer overflow in the VFAT filesystem
implementation in the Linux kernel before 3.3 allows local
users to gain privileges or cause a denial of service
(system crash) via a VFAT write operation on a filesystem
with the utf8 mount option, which is not properly handled
during UTF-8 to UTF-16 conversion. (bnc#806977)

CVE-2013-1774: The chase_port function in
drivers/usb/serial/io_ti.c in the Linux kernel before 3.7.4
allows local users to cause a denial of service (NULL
pointer dereference and system crash) via an attempted
/dev/ttyUSB read or write operation on a disconnected
Edgeport USB serial converter. (bnc#806976)

CVE-2013-1792: Race condition in the install_user_keyrings
function in security/keys/process_keys.c in the Linux kernel
before 3.8.3 allows local users to cause a denial of service
(NULL pointer dereference and system crash) via crafted
keyctl system calls that trigger keyring operations in
simultaneous threads. (bnc#808358)

CVE-2013-1796: The kvm_set_msr_common function in
arch/x86/kvm/x86.c in the Linux kernel through 3.8.4 does
not ensure a required time_page alignment during an
MSR_KVM_SYSTEM_TIME operation, which allows guest OS users
to cause a denial of service (buffer overflow and host OS
memory corruption) or possibly have unspecified other impact
via a crafted application. (bnc#806980)

CVE-2013-1797: Use-after-free vulnerability in
arch/x86/kvm/x86.c in the Linux kernel through 3.8.4 allows
guest OS users to cause a denial of service (host OS memory
corruption) or possibly have unspecified other impact via a
crafted application that triggers use of a guest physical
address (GPA) in (1) movable or (2) removable memory during
an MSR_KVM_SYSTEM_TIME kvm_set_msr_common operation.
(bnc#806980)

CVE-2013-1798: The ioapic_read_indirect function in
virt/kvm/ioapic.c in the Linux kernel through 3.8.4 does not
properly handle a certain combination of invalid
IOAPIC_REG_SELECT and IOAPIC_REG_WINDOW operations, which
allows guest OS users to obtain sensitive information from
host OS memory or cause a denial of service (host OS OOPS)
via a crafted application. (bnc#806980)

CVE-2013-1827: net/dccp/ccid.h in the Linux kernel before
3.5.4 allows local users to gain privileges or cause a
denial of service (NULL pointer dereference and system
crash) by leveraging the CAP_NET_ADMIN capability for a
certain (1) sender or (2) receiver getsockopt call.
(bnc#811354)

CVE-2013-1928: The do_video_set_spu_palette function in
fs/compat_ioctl.c in the Linux kernel before 3.6.5 on
unspecified architectures lacks a certain error check, which
might allow local users to obtain sensitive information from
kernel stack memory via a crafted VIDEO_SET_SPU_PALETTE
ioctl call on a /dev/dvb device. (bnc#813735)

CVE-2013-1943: The KVM subsystem in the Linux kernel before
3.0 does not check whether kernel addresses are specified
during allocation of memory slots for use in a guests
physical address space, which allows local users to gain
privileges or obtain sensitive information from kernel
memory via a crafted application, related to
arch/x86/kvm/paging_tmpl.h and virt/kvm/kvm_main.c.
(bnc#828012)

CVE-2013-2015: The ext4_orphan_del function in
fs/ext4/namei.c in the Linux kernel before 3.7.3 does not
properly handle orphan-list entries for non-journal
filesystems, which allows physically proximate attackers to
cause a denial of service (system hang) via a crafted
filesystem on removable media, as demonstrated by the
e2fsprogs tests/f_orphan_extents_inode/image.gz test.
(bnc#817377)

CVE-2013-2141: The do_tkill function in kernel/signal.c in
the Linux kernel before 3.8.9 does not initialize a certain
data structure, which allows local users to obtain sensitive
information from kernel memory via a crafted application
that makes a (1) tkill or (2) tgkill system call.
(bnc#823267)

CVE-2013-2147: The HP Smart Array controller disk-array
driver and Compaq SMART2 controller disk-array driver in the
Linux kernel through 3.9.4 do not initialize certain data
structures, which allows local users to obtain sensitive
information from kernel memory via (1) a crafted
IDAGETPCIINFO command for a /dev/ida device, related to the
ida_locked_ioctl function in drivers/block/cpqarray.c or (2)
a crafted CCISS_PASSTHRU32 command for a /dev/cciss device,
related to the cciss_ioctl32_passthru function in
drivers/block/cciss.c. (bnc#823260)

CVE-2013-2164: The mmc_ioctl_cdrom_read_data function in
drivers/cdrom/cdrom.c in the Linux kernel through 3.10
allows local users to obtain sensitive information from
kernel memory via a read operation on a malfunctioning
CD-ROM drive. (bnc#824295)

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

CVE-2013-2634: net/dcb/dcbnl.c in the Linux kernel before
3.8.4 does not initialize certain structures, which allows
local users to obtain sensitive information from kernel
stack memory via a crafted application. (bnc#810473)

CVE-2013-2851: Format string vulnerability in the
register_disk function in block/genhd.c in the Linux kernel
through 3.9.4 allows local users to gain privileges by
leveraging root access and writing format string specifiers
to /sys/module/md_mod/parameters/new_array in order to
create a crafted /dev/md device name. (bnc#822575)

CVE-2013-2852: Format string vulnerability in the
b43_request_firmware function in
drivers/net/wireless/b43/main.c in the Broadcom B43 wireless
driver in the Linux kernel through 3.9.4 allows local users
to gain privileges by leveraging root access and including
format string specifiers in an fwpostfix modprobe parameter,
leading to improper construction of an error message.
(bnc#822579)

CVE-2013-2888: Multiple array index errors in
drivers/hid/hid-core.c in the Human Interface Device (HID)
subsystem in the Linux kernel through 3.11 allow physically
proximate attackers to execute arbitrary code or cause a
denial of service (heap memory corruption) via a crafted
device that provides an invalid Report ID. (bnc#835839)

CVE-2013-2889: drivers/hid/hid-zpff.c in the Human Interface
Device (HID) subsystem in the Linux kernel through 3.11,
when CONFIG_HID_ZEROPLUS is enabled, allows physically
proximate attackers to cause a denial of service (heap-based
out-of-bounds write) via a crafted device. (bnc#835839)

CVE-2013-2892: drivers/hid/hid-pl.c in the Human Interface
Device (HID) subsystem in the Linux kernel through 3.11,
when CONFIG_HID_PANTHERLORD is enabled, allows physically
proximate attackers to cause a denial of service (heap-based
out-of-bounds write) via a crafted device. (bnc#835839)

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

CVE-2013-2929: The Linux kernel before 3.12.2 does not
properly use the get_dumpable function, which allows local
users to bypass intended ptrace restrictions or obtain
sensitive information from IA64 scratch registers via a
crafted application, related to kernel/ptrace.c and
arch/ia64/include/asm/processor.h. (bnc#847652)

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

CVE-2013-3225: The rfcomm_sock_recvmsg function in
net/bluetooth/rfcomm/sock.c in the Linux kernel before
3.9-rc7 does not initialize a certain length variable, which
allows local users to obtain sensitive information from
kernel stack memory via a crafted recvmsg or recvfrom system
call. (bnc#816668)

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

CVE-2013-4345: Off-by-one error in the get_prng_bytes
function in crypto/ansi_cprng.c in the Linux kernel through
3.11.4 makes it easier for context-dependent attackers to
defeat cryptographic protection mechanisms via multiple
requests for small amounts of data, leading to improper
management of the state of the consumed data. (bnc#840226)

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

CVE-2013-4511: Multiple integer overflows in Alchemy LCD
frame-buffer drivers in the Linux kernel before 3.12 allow
local users to create a read-write memory mapping for the
entirety of kernel memory, and consequently gain privileges,
via crafted mmap operations, related to the (1)
au1100fb_fb_mmap function in drivers/video/au1100fb.c and
the (2) au1200fb_fb_mmap function in
drivers/video/au1200fb.c. (bnc#849021)

CVE-2013-4587: Array index error in the
kvm_vm_ioctl_create_vcpu function in virt/kvm/kvm_main.c in
the KVM subsystem in the Linux kernel through 3.12.5 allows
local users to gain privileges via a large id value.
(bnc#853050)

CVE-2013-4588: Multiple stack-based buffer overflows in
net/netfilter/ipvs/ip_vs_ctl.c in the Linux kernel before
2.6.33, when CONFIG_IP_VS is used, allow local users to gain
privileges by leveraging the CAP_NET_ADMIN capability for
(1) a getsockopt system call, related to the
do_ip_vs_get_ctl function, or (2) a setsockopt system call,
related to the do_ip_vs_set_ctl function. (bnc#851095)

CVE-2013-4591: Buffer overflow in the
__nfs4_get_acl_uncached function in fs/nfs/nfs4proc.c in the
Linux kernel before 3.7.2 allows local users to cause a
denial of service (memory corruption and system crash) or
possibly have unspecified other impact via a getxattr system
call for the system.nfs4_acl extended attribute of a
pathname on an NFSv4 filesystem. (bnc#851103)

CVE-2013-6367: The apic_get_tmcct function in
arch/x86/kvm/lapic.c in the KVM subsystem in the Linux
kernel through 3.12.5 allows guest OS users to cause a
denial of service (divide-by-zero error and host OS crash)
via crafted modifications of the TMICT value. (bnc#853051)

CVE-2013-6368: The KVM subsystem in the Linux kernel through
3.12.5 allows local users to gain privileges or cause a
denial of service (system crash) via a VAPIC synchronization
operation involving a page-end address. (bnc#853052)

CVE-2013-6378: The lbs_debugfs_write function in
drivers/net/wireless/libertas/debugfs.c in the Linux kernel
through 3.12.1 allows local users to cause a denial of
service (OOPS) by leveraging root privileges for a
zero-length write operation. (bnc#852559)

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

  - x86: Clear HPET configuration registers on startup
    (bnc#748896).

  - sched: fix divide by zero in task_utime() (bnc#761774).

  - sched: Fix pick_next_highest_task_rt() for cgroups
    (bnc#760596).

  - mm: hugetlbfs: Close race during teardown of hugetlbfs
    shared page tables.

  - mm: hugetlbfs: Correctly detect if page tables have just
    been shared. (Fix bad PMD message displayed while using
    hugetlbfs (bnc#762366)).

  - cpumask: Partition_sched_domains takes array of
    cpumask_var_t (bnc#812364).

  - cpumask: Simplify sched_rt.c (bnc#812364).

  - kabi: protect bind_conflict callback in struct
    inet_connection_sock_af_ops (bnc#823618).

  - memcg: fix init_section_page_cgroup pfn alignment
    (bnc#835481).

  - tty: fix up atime/mtime mess, take three (bnc#797175).

  - tty: fix atime/mtime regression (bnc#815745).

  - ptrace: ptrace_resume() should not wake up !TASK_TRACED
    thread (bnc#804154).

  - kbuild: Fix gcc -x syntax (bnc#773831).

  - ftrace: Disable function tracing during suspend/resume
    and hibernation, again (bnc#768668). proc: fix
    pagemap_read() error case (bnc#787573).

    net: Upgrade device features irrespective of mask
    (bnc#715250).

  - tcp: bind() fix autoselection to share ports
    (bnc#823618).

  - tcp: bind() use stronger condition for bind_conflict
    (bnc#823618).

  - tcp: ipv6: bind() use stronger condition for
    bind_conflict (bnc#823618).

  - netfilter: use RCU safe kfree for conntrack extensions
    (bnc#827416).

  - netfilter: prevent race condition breaking net reference
    counting (bnc#835094).

  - netfilter: send ICMPv6 message on fragment reassembly
    timeout (bnc#773577).

  - netfilter: fix sending ICMPv6 on netfilter reassembly
    timeout (bnc#773577).

  - tcp_cubic: limit delayed_ack ratio to prevent divide
    error (bnc#810045). bonding: in balance-rr mode, set
    curr_active_slave only if it is up (bnc#789648).

    scsi: Add 'eh_deadline' to limit SCSI EH runtime
    (bnc#798050).

  - scsi: Allow error handling timeout to be specified
    (bnc#798050).

  - scsi: Fixup compilation warning (bnc#798050).

  - scsi: Retry failfast commands after EH (bnc#798050).

  - scsi: Warn on invalid command completion (bnc#798050).

  - scsi: Always retry internal target error (bnc#745640,
    bnc#825227).

  - scsi: kABI fixes (bnc#798050).

  - scsi: remove check for 'resetting' (bnc#798050).

  - scsi: Eliminate error handler overload of the SCSI
    serial number (bnc#798050).

  - scsi: Reduce error recovery time by reducing use of TURs
    (bnc#798050).

  - scsi: Reduce sequential pointer derefs in scsi_error.c
    and reduce size as well (bnc#798050).

  - scsi: cleanup setting task state in scsi_error_handler()
    (bnc#798050).

  - scsi: fix eh wakeup (scsi_schedule_eh vs
    scsi_restart_operations) (bnc#798050). scsi: fix id
    computation in scsi_eh_target_reset() (bnc#798050).

    advansys: Remove 'last_reset' references (bnc#798050).

  - dc395: Move 'last_reset' into internal host structure
    (bnc#798050).

  - dpt_i2o: Remove DPTI_STATE_IOCTL (bnc#798050).

  - dpt_i2o: return SCSI_MLQUEUE_HOST_BUSY when in reset
    (bnc#798050).

  - fc class: fix scanning when devs are offline
    (bnc#798050). tmscsim: Move 'last_reset' into host
    structure (bnc#798050).

    st: Store page order before driver buffer allocation
    (bnc#769644).

  - st: Increase success probability in driver buffer
    allocation (bnc#769644). st: work around broken
    __bio_add_page logic (bnc#769644).

    avoid race by ignoring flush_time in cache_check
    (bnc#814363).

    writeback: remove the internal 5% low bound on
    dirty_ratio

  - writeback: skip balance_dirty_pages() for in-memory fs
    (Do not dirty throttle ram-based filesystems
    (bnc#840858)). writeback: Do not sync data dirtied after
    sync start (bnc#833820).

    blkdev_max_block: make private to fs/buffer.c
    (bnc#820338).

  - vfs: avoid 'attempt to access beyond end of device'
    warnings (bnc#820338). vfs: fix O_DIRECT read past end
    of block device (bnc#820338).

    lib/radix-tree.c: make radix_tree_node_alloc() work
    correctly within interrupt (bnc#763463).

    xfs: allow writeback from kswapd (bnc#826707).

  - xfs: skip writeback from reclaim context (bnc#826707).

  - xfs: Serialize file-extending direct IO (bnc#818371).

  - xfs: Avoid pathological backwards allocation
    (bnc#805945). xfs: fix inode lookup race (bnc#763463).

    cifs: clarify the meaning of tcpStatus == CifsGood
    (bnc#776024).

    cifs: do not allow cifs_reconnect to exit with NULL
    socket pointer (bnc#776024).

    ocfs2: Add a missing journal credit in
    ocfs2_link_credits() -v2 (bnc#773320).

    usb: Fix deadlock in hid_reset when Dell iDRAC is reset
    (bnc#814716).

    usb: xhci: Fix command completion after a drop endpoint
    (bnc#807320).

    netiucv: Hold rtnl between name allocation and device
    registration (bnc#824159).

    rwsem: Test for no active locks in __rwsem_do_wake undo
    code (bnc#813276).

    nfs: NFSv3/v2: Fix data corruption with NFS short reads
    (bnc#818337).

  - nfs: Allow sec=none mounts in certain cases
    (bnc#795354).

  - nfs: Make nfsiod a multi-thread queue (bnc#815352).

  - nfs: increase number of permitted callback connections
    (bnc#771706).

  - nfs: Fix Oops in nfs_lookup_revalidate (bnc#780008).

  - nfs: do not allow TASK_KILLABLE sleeps to block the
    freezer (bnc#775182). nfs: Avoid race in d_splice_alias
    and vfs_rmdir (bnc#845028).

    svcrpc: take lock on turning entry NEGATIVE in
    cache_check (bnc#803320).

  - svcrpc: ensure cache_check caller sees updated entry
    (bnc#803320).

  - sunrpc/cache: remove races with queuing an upcall
    (bnc#803320).

  - sunrpc/cache: use cache_fresh_unlocked consistently and
    correctly (bnc#803320).

  - sunrpc/cache: ensure items removed from cache do not
    have pending upcalls (bnc#803320).

  - sunrpc/cache: do not schedule update on cache item that
    has been replaced (bnc#803320). sunrpc/cache: fix test
    in try_to_negate (bnc#803320).

    xenbus: fix overflow check in xenbus_dev_write().

  - x86: do not corrupt %eip when returning from a signal
    handler.

  - scsiback/usbback: move cond_resched() invocations to
    proper place. netback: fix netbk_count_requests().

    dm: add dm_deleting_md function (bnc#785016).

  - dm: bind new table before destroying old (bnc#785016).

  - dm: keep old table until after resume succeeded
    (bnc#785016). dm: rename dm_get_table to
    dm_get_live_table (bnc#785016).

    drm/edid: Fix up partially corrupted headers
    (bnc#780004).

    drm/edid: Retry EDID fetch up to four times
    (bnc#780004).

    i2c-algo-bit: Fix spurious SCL timeouts under heavy load
    (bnc#780004).

    hpilo: remove pci_disable_device (bnc#752544).

    mptsas: handle 'Initializing Command Required' ASCQ
    (bnc#782178).

    mpt2sas: Fix race on shutdown (bnc#856917).

    ipmi: decrease the IPMI message transaction time in
    interrupt mode (bnc#763654).

  - ipmi: simplify locking (bnc#763654). ipmi: use a tasklet
    for handling received messages (bnc#763654).

    bnx2x: bug fix when loading after SAN boot (bnc#714906).

    bnx2x: previous driver unload revised (bnc#714906).

    ixgbe: Address fact that RSC was not setting GSO size
    for incoming frames (bnc#776144).

    ixgbe: pull PSRTYPE configuration into a separate
    function (bnc#780572 bnc#773640 bnc#776144).

    e1000e: clear REQ and GNT in EECD (82571 && 82572)
    (bnc#762099).

    hpsa: do not attempt to read from a write-only register
    (bnc#777473).

    aio: Fixup kABI for the aio-implement-request-batching
    patch (bnc#772849).

  - aio: bump i_count instead of using igrab (bnc#772849).
    aio: implement request batching (bnc#772849).

    Driver core: Do not remove kobjects in device_shutdown
    (bnc#771992).

    resources: fix call to alignf() in allocate_resource()
    (bnc#744955).

  - resources: when allocate_resource() fails, leave
    resource untouched (bnc#744955).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.novell.com/patch/finder/?keywords=36a4c03a7a6e23326bdc75867718c3f5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?499ef588"
  );
  # http://download.novell.com/patch/finder/?keywords=78a90ce26186ad3c08d3168f7c56498f
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6524481b"
  );
  # http://download.novell.com/patch/finder/?keywords=92db776383896ad395b93d570e1b0440
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3b1d361"
  );
  # http://download.novell.com/patch/finder/?keywords=c00b87e84b1ec845f992a53432644809
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3327c148"
  );
  # http://download.novell.com/patch/finder/?keywords=cebd648c35a6ff05d60a592debc063f7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85cb8767"
  );
  # http://download.novell.com/patch/finder/?keywords=f67e971841459d6799882fcccab88393
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7458efe4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3593.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1601.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2137.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2372.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3375.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3511.html"
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
    value:"http://support.novell.com/security/cve/CVE-2012-4565.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6538.html"
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
    value:"http://support.novell.com/security/cve/CVE-2012-6548.html"
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
    value:"http://support.novell.com/security/cve/CVE-2013-0216.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0231.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0268.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0310.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0343.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0349.html"
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
    value:"http://support.novell.com/security/cve/CVE-2013-1767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1773.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1792.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1796.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1797.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1798.html"
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
    value:"http://support.novell.com/security/cve/CVE-2013-1943.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2015.html"
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
    value:"http://support.novell.com/security/cve/CVE-2013-2634.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2851.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2852.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2888.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2889.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2892.html"
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
    value:"http://support.novell.com/security/cve/CVE-2013-2929.html"
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
    value:"http://support.novell.com/security/cve/CVE-2013-4345.html"
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
    value:"http://support.novell.com/security/cve/CVE-2013-4511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4587.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4588.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4591.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6367.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6368.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6378.html"
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
    value:"https://bugzilla.novell.com/714906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/715250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/735347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/744955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/745640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/748896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/752544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/754898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/760596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/761774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/762099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/762366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/763463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/763654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/767610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/767612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/768668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/769644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/769896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/770695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/771706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/771992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/772849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/773320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/773383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/773577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/773640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/773831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/774523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/775182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/776024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/776144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/776885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/777473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/780004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/780008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/780572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/782178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/785016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/786013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/787573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/787576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/789648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/789831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/795354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/797175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/798050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/800280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/801178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/802642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/803320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/804154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/804653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/805226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/805227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/805945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/806138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/806976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/806977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/806980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/807320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/808358"
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
    value:"https://bugzilla.novell.com/809902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/809903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/810045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/810473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/811354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/812364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/813276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/813735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/814363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/814716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/815352"
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
    value:"https://bugzilla.novell.com/817377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/818337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/818371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/820338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/822575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/822579"
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
    value:"https://bugzilla.novell.com/823618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/824159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/824295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/825227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/826707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/827416"
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
    value:"https://bugzilla.novell.com/828012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/828119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/833820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/835094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/835481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/835839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/840226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/840858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/845028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/847652"
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
    value:"https://bugzilla.novell.com/849021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/851095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/851103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/852558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/852559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/856917"
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
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140287-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c7c0d67"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP1 LTSS :

zypper in -t patch slessp1-kernel-8847 slessp1-kernel-8848
slessp1-kernel-8849

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:btrfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:btrfs-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:btrfs-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ext4dev-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ext4dev-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ext4dev-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ext4dev-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hyper-v-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hyper-v-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hyper-v-kmp-trace");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^1$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"btrfs-kmp-xen-0_2.6.32.59_0.9-0.3.151")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"ext4dev-kmp-xen-0_2.6.32.59_0.9-7.9.118")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"hyper-v-kmp-default-0_2.6.32.59_0.9-0.18.37")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"hyper-v-kmp-trace-0_2.6.32.59_0.9-0.18.37")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-ec2-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-ec2-base-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-ec2-devel-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-xen-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"btrfs-kmp-pae-0_2.6.32.59_0.9-0.3.151")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"ext4dev-kmp-pae-0_2.6.32.59_0.9-7.9.118")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"hyper-v-kmp-pae-0_2.6.32.59_0.9-0.18.37")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-pae-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-pae-base-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-pae-devel-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"s390x", reference:"kernel-default-man-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"btrfs-kmp-default-0_2.6.32.59_0.9-0.3.151")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"ext4dev-kmp-default-0_2.6.32.59_0.9-7.9.118")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"ext4dev-kmp-trace-0_2.6.32.59_0.9-7.9.118")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-default-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-default-base-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-default-devel-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-source-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-syms-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-trace-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-trace-base-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-trace-devel-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"btrfs-kmp-xen-0_2.6.32.59_0.9-0.3.151")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"ext4dev-kmp-xen-0_2.6.32.59_0.9-7.9.118")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"hyper-v-kmp-default-0_2.6.32.59_0.9-0.18.37")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"hyper-v-kmp-trace-0_2.6.32.59_0.9-0.18.37")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-ec2-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-ec2-base-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-ec2-devel-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-xen-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-xen-base-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-xen-devel-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"btrfs-kmp-pae-0_2.6.32.59_0.9-0.3.151")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"ext4dev-kmp-pae-0_2.6.32.59_0.9-7.9.118")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"hyper-v-kmp-pae-0_2.6.32.59_0.9-0.18.37")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-pae-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-pae-base-2.6.32.59-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-pae-devel-2.6.32.59-0.9.1")) flag++;


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
