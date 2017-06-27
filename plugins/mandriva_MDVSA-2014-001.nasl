#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:001. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71936);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/01/15 16:34:06 $");

  script_cve_id("CVE-2013-4587", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6382", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2013-7266", "CVE-2013-7267", "CVE-2013-7268", "CVE-2013-7269", "CVE-2013-7270", "CVE-2013-7271", "CVE-2013-7281");
  script_bugtraq_id(63889, 64270, 64291, 64328, 64677, 64685, 64686, 64739, 64741, 64742, 64743, 64744, 64746, 64747);
  script_xref(name:"MDVSA", value:"2014:001");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2014:001)");
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

The KVM subsystem in the Linux kernel through 3.12.5 allows local
users to gain privileges or cause a denial of service (system crash)
via a VAPIC synchronization operation involving a page-end address
(CVE-2013-6368).

The apic_get_tmcct function in arch/x86/kvm/lapic.c in the KVM
subsystem in the Linux kernel through 3.12.5 allows guest OS users to
cause a denial of service (divide-by-zero error and host OS crash) via
crafted modifications of the TMICT value (CVE-2013-6367).

Multiple buffer underflows in the XFS implementation in the Linux
kernel through 3.12.1 allow local users to cause a denial of service
(memory corruption) or possibly have unspecified other impact by
leveraging the CAP_SYS_ADMIN capability for a (1)
XFS_IOC_ATTRLIST_BY_HANDLE or (2) XFS_IOC_ATTRLIST_BY_HANDLE_32 ioctl
call with a crafted length value, related to the
xfs_attrlist_by_handle function in fs/xfs/xfs_ioctl.c and the
xfs_compat_attrlist_by_handle function in fs/xfs/xfs_ioctl32.c
(CVE-2013-6382).

Array index error in the kvm_vm_ioctl_create_vcpu function in
virt/kvm/kvm_main.c in the KVM subsystem in the Linux kernel through
3.12.5 allows local users to gain privileges via a large id value
(CVE-2013-4587).

The mISDN_sock_recvmsg function in drivers/isdn/mISDN/socket.c in the
Linux kernel before 3.12.4 does not ensure that a certain length value
is consistent with the size of an associated data structure, which
allows local users to obtain sensitive information from kernel memory
via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call
(CVE-2013-7266).

The atalk_recvmsg function in net/appletalk/ddp.c in the Linux kernel
before 3.12.4 updates a certain length value without ensuring that an
associated data structure has been initialized, which allows local
users to obtain sensitive information from kernel memory via a (1)
recvfrom, (2) recvmmsg, or (3) recvmsg system call (CVE-2013-7267).

The ipx_recvmsg function in net/ipx/af_ipx.c in the Linux kernel
before 3.12.4 updates a certain length value without ensuring that an
associated data structure has been initialized, which allows local
users to obtain sensitive information from kernel memory via a (1)
recvfrom, (2) recvmmsg, or (3) recvmsg system call (CVE-2013-7268).

The nr_recvmsg function in net/netrom/af_netrom.c in the Linux kernel
before 3.12.4 updates a certain length value without ensuring that an
associated data structure has been initialized, which allows local
users to obtain sensitive information from kernel memory via a (1)
recvfrom, (2) recvmmsg, or (3) recvmsg system call (CVE-2013-7269).

The packet_recvmsg function in net/packet/af_packet.c in the Linux
kernel before 3.12.4 updates a certain length value before ensuring
that an associated data structure has been initialized, which allows
local users to obtain sensitive information from kernel memory via a
(1) recvfrom, (2) recvmmsg, or (3) recvmsg system call
(CVE-2013-7270).

The x25_recvmsg function in net/x25/af_x25.c in the Linux kernel
before 3.12.4 updates a certain length value without ensuring that an
associated data structure has been initialized, which allows local
users to obtain sensitive information from kernel memory via a (1)
recvfrom, (2) recvmmsg, or (3) recvmsg system call (CVE-2013-7271).

The Linux kernel before 3.12.4 updates certain length values before
ensuring that associated data structures have been initialized, which
allows local users to obtain sensitive information from kernel stack
memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call,
related to net/ipv4/ping.c, net/ipv4/raw.c, net/ipv4/udp.c,
net/ipv6/raw.c, and net/ipv6/udp.c (CVE-2013-7263).

The l2tp_ip_recvmsg function in net/l2tp/l2tp_ip.c in the Linux kernel
before 3.12.4 updates a certain length value before ensuring that an
associated data structure has been initialized, which allows local
users to obtain sensitive information from kernel stack memory via a
(1) recvfrom, (2) recvmmsg, or (3) recvmsg system call
(CVE-2013-7264).

The pn_recvmsg function in net/phonet/datagram.c in the Linux kernel
before 3.12.4 updates a certain length value before ensuring that an
associated data structure has been initialized, which allows local
users to obtain sensitive information from kernel stack memory via a
(1) recvfrom, (2) recvmmsg, or (3) recvmsg system call
(CVE-2013-7265).

The dgram_recvmsg function in net/ieee802154/dgram.c in the Linux
kernel before 3.12.4 updates a certain length value without ensuring
that an associated data structure has been initialized, which allows
local users to obtain sensitive information from kernel stack memory
via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call
(CVE-2013-7281).

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"cpupower-3.4.76-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-firmware-3.4.76-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-headers-3.4.76-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-3.4.76-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-devel-3.4.76-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-source-3.4.76-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower-devel-3.4.76-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower0-3.4.76-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perf-3.4.76-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
