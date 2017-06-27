#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:194. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67254);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/04/24 13:06:47 $");

  script_cve_id("CVE-2012-5517", "CVE-2013-0231", "CVE-2013-1059", "CVE-2013-1774", "CVE-2013-2147", "CVE-2013-2148", "CVE-2013-2164", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2850", "CVE-2013-2851", "CVE-2013-2852", "CVE-2013-3301");
  script_bugtraq_id(56527, 57740, 58202, 59055, 60243, 60280, 60341, 60375, 60409, 60410, 60874, 60893, 60922, 60953);
  script_xref(name:"MDVSA", value:"2013:194");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2013:194)");
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

net/ceph/auth_none.c in the Linux kernel through 3.10 allows remote
attackers to cause a denial of service (NULL pointer dereference and
system crash) or possibly have unspecified other impact via an
auth_reply message that triggers an attempted build_request operation.
(CVE-2013-1059)

The HP Smart Array controller disk-array driver and Compaq SMART2
controller disk-array driver in the Linux kernel through 3.9.4 do not
initialize certain data structures, which allows local users to obtain
sensitive information from kernel memory via (1) a crafted
IDAGETPCIINFO command for a /dev/ida device, related to the
ida_locked_ioctl function in drivers/block/cpqarray.c or (2) a crafted
CCISS_PASSTHRU32 command for a /dev/cciss device, related to the
cciss_ioctl32_passthru function in drivers/block/cciss.c.
(CVE-2013-2147)

The fill_event_metadata function in fs/notify/fanotify/fanotify_user.c
in the Linux kernel through 3.9.4 does not initialize a certain
structure member, which allows local users to obtain sensitive
information from kernel memory via a read operation on the fanotify
descriptor. (CVE-2013-2148)

Format string vulnerability in the register_disk function in
block/genhd.c in the Linux kernel through 3.9.4 allows local users to
gain privileges by leveraging root access and writing format string
specifiers to /sys/module/md_mod/parameters/new_array in order to
create a crafted /dev/md device name. (CVE-2013-2851)

The mmc_ioctl_cdrom_read_data function in drivers/cdrom/cdrom.c in the
Linux kernel through 3.10 allows local users to obtain sensitive
information from kernel memory via a read operation on a
malfunctioning CD-ROM drive. (CVE-2013-2164)

The key_notify_policy_flush function in net/key/af_key.c in the Linux
kernel before 3.9 does not initialize a certain structure member,
which allows local users to obtain sensitive information from kernel
heap memory by reading a broadcast message from the notify_policy
interface of an IPSec key_socket. (CVE-2013-2237)

The (1) key_notify_sa_flush and (2) key_notify_policy_flush functions
in net/key/af_key.c in the Linux kernel before 3.10 do not initialize
certain structure members, which allows local users to obtain
sensitive information from kernel heap memory by reading a broadcast
message from the notify interface of an IPSec key_socket.
(CVE-2013-2234)

The ip6_sk_dst_check function in net/ipv6/ip6_output.c in the Linux
kernel before 3.10 allows local users to cause a denial of service
(system crash) by using an AF_INET6 socket for a connection to an IPv4
interface. (CVE-2013-2232)

The online_pages function in mm/memory_hotplug.c in the Linux kernel
before 3.6 allows local users to cause a denial of service (NULL
pointer dereference and system crash) or possibly have unspecified
other impact in opportunistic circumstances by using memory that was
hot-added by an administrator. (CVE-2012-5517)

Format string vulnerability in the b43_request_firmware function in
drivers/net/wireless/b43/main.c in the Broadcom B43 wireless driver in
the Linux kernel through 3.9.4 allows local users to gain privileges
by leveraging root access and including format string specifiers in an
fwpostfix modprobe parameter, leading to improper construction of an
error message. (CVE-2013-2852)

The ftrace implementation in the Linux kernel before 3.8.8 allows
local users to cause a denial of service (NULL pointer dereference and
system crash) or possibly have unspecified other impact by leveraging
the CAP_SYS_ADMIN capability for write access to the (1)
set_ftrace_pid or (2) set_graph_function file, and then making an
lseek system call. (CVE-2013-3301)

The pciback_enable_msi function in the PCI backend driver
(drivers/xen/pciback/conf_space_capability_msi.c) in Xen for the Linux
kernel 2.6.18 and 3.8 allows guest OS users with PCI device access to
cause a denial of service via a large number of kernel log messages.
NOTE: some of these details are obtained from third-party information.
(CVE-2013-0231)

The chase_port function in drivers/usb/serial/io_ti.c in the Linux
kernel before 3.7.4 allows local users to cause a denial of service
(NULL pointer dereference and system crash) via an attempted
/dev/ttyUSB read or write operation on a disconnected Edgeport USB
serial converter. (CVE-2013-1774)

Heap-based buffer overflow in the iscsi_add_notunderstood_response
function in drivers/target/iscsi/iscsi_target_parameters.c in the
iSCSI target subsystem in the Linux kernel through 3.9.4 allows remote
attackers to cause a denial of service (memory corruption and OOPS) or
possibly execute arbitrary code via a long key that is not properly
handled during construction of an error-response packet.
(CVE-2013-2850)

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"cpupower-3.4.52-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-firmware-3.4.52-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-headers-3.4.52-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-3.4.52-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-devel-3.4.52-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-source-3.4.52-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower-devel-3.4.52-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower0-3.4.52-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perf-3.4.52-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
