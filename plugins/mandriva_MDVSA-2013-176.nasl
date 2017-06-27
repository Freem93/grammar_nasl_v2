#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:176. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66975);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id("CVE-2012-5532", "CVE-2012-6547", "CVE-2012-6548", "CVE-2012-6549", "CVE-2013-0216", "CVE-2013-0217", "CVE-2013-0228", "CVE-2013-0290", "CVE-2013-0311", "CVE-2013-0914", "CVE-2013-1763", "CVE-2013-1767", "CVE-2013-1792", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1848", "CVE-2013-1860", "CVE-2013-1929", "CVE-2013-1979", "CVE-2013-2094", "CVE-2013-2141", "CVE-2013-2146", "CVE-2013-2546", "CVE-2013-2547", "CVE-2013-2548", "CVE-2013-2596", "CVE-2013-2634", "CVE-2013-2635", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3227", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3233", "CVE-2013-3234", "CVE-2013-3235");
  script_bugtraq_id(56710, 57743, 57744, 57940, 57964, 58053, 58137, 58177, 58368, 58382, 58426, 58510, 58597, 58600, 58604, 58605, 58607, 58908, 58993, 58994, 58996, 59264, 59377, 59380, 59381, 59383, 59385, 59388, 59389, 59390, 59393, 59394, 59396, 59397, 59538, 59846, 60254, 60324);
  script_xref(name:"MDVSA", value:"2013:176");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2013:176)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been found and corrected in the Linux
kernel :

The scm_set_cred function in include/net/scm.h in the Linux kernel
before 3.8.11 uses incorrect uid and gid values during credentials
passing, which allows local users to gain privileges via a crafted
application. (CVE-2013-1979)

The nr_recvmsg function in net/netrom/af_netrom.c in the Linux kernel
before 3.9-rc7 does not initialize a certain data structure, which
allows local users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call. (CVE-2013-3232)

net/tipc/socket.c in the Linux kernel before 3.9-rc7 does not
initialize a certain data structure and a certain length variable,
which allows local users to obtain sensitive information from kernel
stack memory via a crafted recvmsg or recvfrom system call.
(CVE-2013-3235)

The rose_recvmsg function in net/rose/af_rose.c in the Linux kernel
before 3.9-rc7 does not initialize a certain data structure, which
allows local users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call. (CVE-2013-3234)

The llcp_sock_recvmsg function in net/nfc/llcp/sock.c in the Linux
kernel before 3.9-rc7 does not initialize a certain length variable
and a certain data structure, which allows local users to obtain
sensitive information from kernel stack memory via a crafted recvmsg
or recvfrom system call. (CVE-2013-3233)

The llc_ui_recvmsg function in net/llc/af_llc.c in the Linux kernel
before 3.9-rc7 does not initialize a certain length variable, which
allows local users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call. (CVE-2013-3231)

The iucv_sock_recvmsg function in net/iucv/af_iucv.c in the Linux
kernel before 3.9-rc7 does not initialize a certain length variable,
which allows local users to obtain sensitive information from kernel
stack memory via a crafted recvmsg or recvfrom system call.
(CVE-2013-3229)

The irda_recvmsg_dgram function in net/irda/af_irda.c in the Linux
kernel before 3.9-rc7 does not initialize a certain length variable,
which allows local users to obtain sensitive information from kernel
stack memory via a crafted recvmsg or recvfrom system call.
(CVE-2013-3228)

The caif_seqpkt_recvmsg function in net/caif/caif_socket.c in the
Linux kernel before 3.9-rc7 does not initialize a certain length
variable, which allows local users to obtain sensitive information
from kernel stack memory via a crafted recvmsg or recvfrom system
call. (CVE-2013-3227)

The rfcomm_sock_recvmsg function in net/bluetooth/rfcomm/sock.c in the
Linux kernel before 3.9-rc7 does not initialize a certain length
variable, which allows local users to obtain sensitive information
from kernel stack memory via a crafted recvmsg or recvfrom system
call. (CVE-2013-3225)

The bt_sock_recvmsg function in net/bluetooth/af_bluetooth.c in the
Linux kernel before 3.9-rc7 does not properly initialize a certain
length variable, which allows local users to obtain sensitive
information from kernel stack memory via a crafted recvmsg or recvfrom
system call. (CVE-2013-3224)

The ax25_recvmsg function in net/ax25/af_ax25.c in the Linux kernel
before 3.9-rc7 does not initialize a certain data structure, which
allows local users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call. (CVE-2013-3223)

The vcc_recvmsg function in net/atm/common.c in the Linux kernel
before 3.9-rc7 does not initialize a certain length variable, which
allows local users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call. (CVE-2013-3222)

Integer overflow in the fb_mmap function in drivers/video/fbmem.c in
the Linux kernel before 3.8.9, as used in a certain Motorola build of
Android 4.1.2 and other products, allows local users to create a
read-write memory mapping for the entirety of kernel memory, and
consequently gain privileges, via crafted /dev/graphics/fb0 mmap2
system calls, as demonstrated by the Motochopper pwn program.
(CVE-2013-2596)

arch/x86/kernel/cpu/perf_event_intel.c in the Linux kernel before
3.8.9, when the Performance Events Subsystem is enabled, specifies an
incorrect bitmask, which allows local users to cause a denial of
service (general protection fault and system crash) by attempting to
set a reserved bit. (CVE-2013-2146)

The perf_swevent_init function in kernel/events/core.c in the Linux
kernel before 3.8.9 uses an incorrect integer data type, which allows
local users to gain privileges via a crafted perf_event_open system
call. (CVE-2013-2094)

The ioapic_read_indirect function in virt/kvm/ioapic.c in the Linux
kernel through 3.8.4 does not properly handle a certain combination of
invalid IOAPIC_REG_SELECT and IOAPIC_REG_WINDOW operations, which
allows guest OS users to obtain sensitive information from host OS
memory or cause a denial of service (host OS OOPS) via a crafted
application. (CVE-2013-1798)

Use-after-free vulnerability in arch/x86/kvm/x86.c in the Linux kernel
through 3.8.4 allows guest OS users to cause a denial of service (host
OS memory corruption) or possibly have unspecified other impact via a
crafted application that triggers use of a guest physical address
(GPA) in (1) movable or (2) removable memory during an
MSR_KVM_SYSTEM_TIME kvm_set_msr_common operation. (CVE-2013-1797)

The kvm_set_msr_common function in arch/x86/kvm/x86.c in the Linux
kernel through 3.8.4 does not ensure a required time_page alignment
during an MSR_KVM_SYSTEM_TIME operation, which allows guest OS users
to cause a denial of service (buffer overflow and host OS memory
corruption) or possibly have unspecified other impact via a crafted
application. (CVE-2013-1796)

The do_tkill function in kernel/signal.c in the Linux kernel before
3.8.9 does not initialize a certain data structure, which allows local
users to obtain sensitive information from kernel memory via a crafted
application that makes a (1) tkill or (2) tgkill system call.
(CVE-2013-2141)

Heap-based buffer overflow in the tg3_read_vpd function in
drivers/net/ethernet/broadcom/tg3.c in the Linux kernel before 3.8.6
allows physically proximate attackers to cause a denial of service
(system crash) or possibly execute arbitrary code via crafted firmware
that specifies a long string in the Vital Product Data (VPD) data
structure. (CVE-2013-1929)

The main function in tools/hv/hv_kvp_daemon.c in hypervkvpd, as
distributed in the Linux kernel before 3.8-rc1, allows local users to
cause a denial of service (daemon exit) via a crafted application that
sends a Netlink message. NOTE: this vulnerability exists because of an
incorrect fix for CVE-2012-2669. (CVE-2012-5532)

The udf_encode_fh function in fs/udf/namei.c in the Linux kernel
before 3.6 does not initialize a certain structure member, which
allows local users to obtain sensitive information from kernel heap
memory via a crafted application. (CVE-2012-6548)

The isofs_export_encode_fh function in fs/isofs/export.c in the Linux
kernel before 3.6 does not initialize a certain structure member,
which allows local users to obtain sensitive information from kernel
heap memory via a crafted application. (CVE-2012-6549)

net/dcb/dcbnl.c in the Linux kernel before 3.8.4 does not initialize
certain structures, which allows local users to obtain sensitive
information from kernel stack memory via a crafted application.
(CVE-2013-2634)

The rtnl_fill_ifinfo function in net/core/rtnetlink.c in the Linux
kernel before 3.8.4 does not initialize a certain structure member,
which allows local users to obtain sensitive information from kernel
stack memory via a crafted application. (CVE-2013-2635)

fs/ext3/super.c in the Linux kernel before 3.8.4 uses incorrect
arguments to functions in certain circumstances related to printk
input, which allows local users to conduct format-string attacks and
possibly gain privileges via a crafted application. (CVE-2013-1848)

The flush_signal_handlers function in kernel/signal.c in the Linux
kernel before 3.8.4 preserves the value of the sa_restorer field
across an exec operation, which makes it easier for local users to
bypass the ASLR protection mechanism via a crafted application
containing a sigaction system call. (CVE-2013-0914)

Heap-based buffer overflow in the wdm_in_callback function in
drivers/usb/class/cdc-wdm.c in the Linux kernel before 3.8.4 allows
physically proximate attackers to cause a denial of service (system
crash) or possibly execute arbitrary code via a crafted cdc-wdm USB
device. (CVE-2013-1860)

Race condition in the install_user_keyrings function in
security/keys/process_keys.c in the Linux kernel before 3.8.3 allows
local users to cause a denial of service (NULL pointer dereference and
system crash) via crafted keyctl system calls that trigger keyring
operations in simultaneous threads. (CVE-2013-1792)

The report API in the crypto user configuration API in the Linux
kernel through 3.8.2 uses an incorrect C library function for copying
strings, which allows local users to obtain sensitive information from
kernel stack memory by leveraging the CAP_NET_ADMIN capability.
(CVE-2013-2546)

The crypto_report_one function in crypto/crypto_user.c in the report
API in the crypto user configuration API in the Linux kernel through
3.8.2 does not initialize certain structure members, which allows
local users to obtain sensitive information from kernel heap memory by
leveraging the CAP_NET_ADMIN capability. (CVE-2013-2547)

The crypto_report_one function in crypto/crypto_user.c in the report
API in the crypto user configuration API in the Linux kernel through
3.8.2 uses an incorrect length value during a copy operation, which
allows local users to obtain sensitive information from kernel memory
by leveraging the CAP_NET_ADMIN capability. (CVE-2013-2548)

The translate_desc function in drivers/vhost/vhost.c in the Linux
kernel before 3.7 does not properly handle cross-region descriptors,
which allows guest OS users to obtain host OS privileges by leveraging
KVM guest OS privileges. (CVE-2013-0311)

Array index error in the __sock_diag_rcv_msg function in
net/core/sock_diag.c in the Linux kernel before 3.7.10 allows local
users to gain privileges via a large family value in a Netlink
message. (CVE-2013-1763)

The __skb_recv_datagram function in net/core/datagram.c in the Linux
kernel before 3.8 does not properly handle the MSG_PEEK flag with
zero-length data, which allows local users to cause a denial of
service (infinite loop and system hang) via a crafted application.
(CVE-2013-0290)

Use-after-free vulnerability in the shmem_remount_fs function in
mm/shmem.c in the Linux kernel before 3.7.10 allows local users to
gain privileges or cause a denial of service (system crash) by
remounting a tmpfs filesystem without specifying a required mpol (aka
mempolicy) mount option. (CVE-2013-1767)

The xen_iret function in arch/x86/xen/xen-asm_32.S in the Linux kernel
before 3.7.9 on 32-bit Xen paravirt_ops platforms does not properly
handle an invalid value in the DS segment register, which allows guest
OS users to gain guest OS privileges via a crafted application.
(CVE-2013-0228)

Memory leak in drivers/net/xen-netback/netback.c in the Xen netback
functionality in the Linux kernel before 3.7.8 allows guest OS users
to cause a denial of service (memory consumption) by triggering
certain error conditions. (CVE-2013-0217)

The Xen netback functionality in the Linux kernel before 3.7.8 allows
guest OS users to cause a denial of service (loop) by triggering ring
pointer corruption. (CVE-2013-0216)

The __tun_chr_ioctl function in drivers/net/tun.c in the Linux kernel
before 3.6 does not initialize a certain structure, which allows local
users to obtain sensitive information from kernel stack memory via a
crafted application. (CVE-2012-6547)

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"cpupower-3.4.47-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-firmware-3.4.47-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-headers-3.4.47-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-3.4.47-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-devel-3.4.47-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-source-3.4.47-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower-devel-3.4.47-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower0-3.4.47-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perf-3.4.47-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
