#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:124. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(74513);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id("CVE-2012-2137", "CVE-2013-2897", "CVE-2014-0069", "CVE-2014-0077", "CVE-2014-0101", "CVE-2014-0196", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-1874", "CVE-2014-2039", "CVE-2014-2309", "CVE-2014-2523", "CVE-2014-2672", "CVE-2014-2678", "CVE-2014-2706", "CVE-2014-2851", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3153", "CVE-2014-3917");
  script_bugtraq_id(54063, 62044, 65459, 65588, 65700, 65943, 66095, 66279, 66492, 66543, 66591, 66678, 66779, 67282, 67300, 67302, 67309, 67321, 67906);
  script_xref(name:"MDVSA", value:"2014:124");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2014:124)");
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

kernel/auditsc.c in the Linux kernel through 3.14.5, when
CONFIG_AUDITSYSCALL is enabled with certain syscall rules, allows
local users to obtain potentially sensitive single-bit values from
kernel memory or cause a denial of service (OOPS) via a large value of
a syscall number (CVE-2014-3917).

The futex_requeue function in kernel/futex.c in the Linux kernel
through 3.14.5 does not ensure that calls have two different futex
addresses, which allows local users to gain privileges via a crafted
FUTEX_REQUEUE command that facilitates unsafe waiter modification
(CVE-2014-3153).

Race condition in the ath_tx_aggr_sleep function in
drivers/net/wireless/ath/ath9k/xmit.c in the Linux kernel before
3.13.7 allows remote attackers to cause a denial of service (system
crash) via a large amount of network traffic that triggers certain
list deletions (CVE-2014-2672).

The (1) BPF_S_ANC_NLATTR and (2) BPF_S_ANC_NLATTR_NEST extension
implementations in the sk_run_filter function in net/core/filter.c in
the Linux kernel through 3.14.3 do not check whether a certain length
value is sufficiently large, which allows local users to cause a
denial of service (integer underflow and system crash) via crafted BPF
instructions. NOTE: the affected code was moved to the
__skb_get_nlattr and __skb_get_nlattr_nest functions before the
vulnerability was announced (CVE-2014-3144).

The BPF_S_ANC_NLATTR_NEST extension implementation in the
sk_run_filter function in net/core/filter.c in the Linux kernel
through 3.14.3 uses the reverse order in a certain subtraction, which
allows local users to cause a denial of service (over-read and system
crash) via crafted BPF instructions. NOTE: the affected code was moved
to the __skb_get_nlattr_nest function before the vulnerability was
announced (CVE-2014-3145).

Integer overflow in the ping_init_sock function in net/ipv4/ping.c in
the Linux kernel through 3.14.1 allows local users to cause a denial
of service (use-after-free and system crash) or possibly gain
privileges via a crafted application that leverages an improperly
managed reference counter (CVE-2014-2851).

The n_tty_write function in drivers/tty/n_tty.c in the Linux kernel
through 3.14.3 does not properly manage tty driver access in the LECHO
!OPOST case, which allows local users to cause a denial of service
(memory corruption and system crash) or gain privileges by triggering
a race condition involving read and write operations with long strings
(CVE-2014-0196).

The raw_cmd_copyout function in drivers/block/floppy.c in the Linux
kernel through 3.14.3 does not properly restrict access to certain
pointers during processing of an FDRAWCMD ioctl call, which allows
local users to obtain sensitive information from kernel heap memory by
leveraging write access to a /dev/fd device (CVE-2014-1738).

The raw_cmd_copyin function in drivers/block/floppy.c in the Linux
kernel through 3.14.3 does not properly handle error conditions during
processing of an FDRAWCMD ioctl call, which allows local users to
trigger kfree operations and gain privileges by leveraging write
access to a /dev/fd device (CVE-2014-1737).

The rds_iw_laddr_check function in net/rds/iw.c in the Linux kernel
through 3.14 allows local users to cause a denial of service (NULL
pointer dereference and system crash) or possibly have unspecified
other impact via a bind system call for an RDS socket on a system that
lacks RDS transports (CVE-2014-2678).

drivers/vhost/net.c in the Linux kernel before 3.13.10, when mergeable
buffers are disabled, does not properly validate packet lengths, which
allows guest OS users to cause a denial of service (memory corruption
and host OS crash) or possibly gain privileges on the host OS via
crafted packets, related to the handle_rx and get_rx_bufs functions
(CVE-2014-0077).

The ip6_route_add function in net/ipv6/route.c in the Linux kernel
through 3.13.6 does not properly count the addition of routes, which
allows remote attackers to cause a denial of service (memory
consumption) via a flood of ICMPv6 Router Advertisement packets
(CVE-2014-2309).

Multiple array index errors in drivers/hid/hid-multitouch.c in the
Human Interface Device (HID) subsystem in the Linux kernel through
3.11, when CONFIG_HID_MULTITOUCH is enabled, allow physically
proximate attackers to cause a denial of service (heap memory
corruption, or NULL pointer dereference and OOPS) via a crafted device
(CVE-2013-2897).

net/netfilter/nf_conntrack_proto_dccp.c in the Linux kernel through
3.13.6 uses a DCCP header pointer incorrectly, which allows remote
attackers to cause a denial of service (system crash) or possibly
execute arbitrary code via a DCCP packet that triggers a call to the
(1) dccp_new, (2) dccp_packet, or (3) dccp_error function
(CVE-2014-2523).

Race condition in the mac80211 subsystem in the Linux kernel before
3.13.7 allows remote attackers to cause a denial of service (system
crash) via network traffic that improperly interacts with the
WLAN_STA_PS_STA state (aka power-save mode), related to sta_info.c and
tx.c (CVE-2014-2706).

The sctp_sf_do_5_1D_ce function in net/sctp/sm_statefuns.c in the
Linux kernel through 3.13.6 does not validate certain auth_enable and
auth_capable fields before making an sctp_sf_authenticate call, which
allows remote attackers to cause a denial of service (NULL pointer
dereference and system crash) via an SCTP handshake with a modified
INIT chunk and a crafted AUTH chunk before a COOKIE_ECHO chunk
(CVE-2014-0101).

The cifs_iovec_write function in fs/cifs/file.c in the Linux kernel
through 3.13.5 does not properly handle uncached write operations that
copy fewer than the requested number of bytes, which allows local
users to obtain sensitive information from kernel memory, cause a
denial of service (memory corruption and system crash), or possibly
gain privileges via a writev system call with a crafted pointer
(CVE-2014-0069).

arch/s390/kernel/head64.S in the Linux kernel before 3.13.5 on the
s390 platform does not properly handle attempted use of the linkage
stack, which allows local users to cause a denial of service (system
crash) by executing a crafted instruction (CVE-2014-2039).

Buffer overflow in virt/kvm/irq_comm.c in the KVM subsystem in the
Linux kernel before 3.2.24 allows local users to cause a denial of
service (crash) and possibly execute arbitrary code via vectors
related to Message Signaled Interrupts (MSI), irq routing entries, and
an incorrect check by the setup_routing_entry function before invoking
the kvm_set_irq function (CVE-2012-2137).

The security_context_to_sid_core function in
security/selinux/ss/services.c in the Linux kernel before 3.13.4
allows local users to cause a denial of service (system crash) by
leveraging the CAP_MAC_ADMIN capability to set a zero-length security
context (CVE-2014-1874).

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android \'Towelroot\' Futex Requeue Kernel Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"cpupower-3.4.93-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-firmware-3.4.93-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-headers-3.4.93-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-3.4.93-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-devel-3.4.93-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-source-3.4.93-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower-devel-3.4.93-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower0-3.4.93-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perf-3.4.93-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
