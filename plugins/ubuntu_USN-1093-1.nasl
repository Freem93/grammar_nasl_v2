#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1093-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(65103);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

  script_cve_id("CVE-2010-2478", "CVE-2010-2942", "CVE-2010-2943", "CVE-2010-2954", "CVE-2010-2955", "CVE-2010-2960", "CVE-2010-2962", "CVE-2010-2963", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3084", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3298", "CVE-2010-3310", "CVE-2010-3432", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3448", "CVE-2010-3477", "CVE-2010-3698", "CVE-2010-3705", "CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-3858", "CVE-2010-3859", "CVE-2010-3861", "CVE-2010-3865", "CVE-2010-3873", "CVE-2010-3874", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-3881", "CVE-2010-3904", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4075", "CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4079", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4164", "CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4175", "CVE-2010-4242", "CVE-2010-4248", "CVE-2010-4249", "CVE-2010-4258", "CVE-2010-4343", "CVE-2010-4346", "CVE-2010-4526", "CVE-2010-4527", "CVE-2010-4648", "CVE-2010-4649", "CVE-2010-4650", "CVE-2010-4655", "CVE-2010-4656", "CVE-2010-4668", "CVE-2011-0006", "CVE-2011-0521", "CVE-2011-0712", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1044", "CVE-2011-1082", "CVE-2011-1093");
  script_xref(name:"USN", value:"1093-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 : linux-mvl-dove vulnerabilities (USN-1093-1)");
  script_summary(english:"Checks dpkg output for updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing one or more security-related patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dan Rosenberg discovered that the RDS network protocol did not
correctly check certain parameters. A local attacker could exploit
this gain root privileges. (CVE-2010-3904)

Nelson Elhage discovered several problems with the Acorn Econet
protocol driver. A local user could cause a denial of service via a
NULL pointer dereference, escalate privileges by overflowing the
kernel stack, and assign Econet addresses to arbitrary interfaces.
(CVE-2010-3848, CVE-2010-3849, CVE-2010-3850)

Ben Hutchings discovered that the ethtool interface did not correctly
check certain sizes. A local attacker could perform malicious ioctl
calls that could crash the system, leading to a denial of service.
(CVE-2010-2478, CVE-2010-3084)

Eric Dumazet discovered that many network functions could leak kernel
stack contents. A local attacker could exploit this to read portions
of kernel memory, leading to a loss of privacy. (CVE-2010-2942,
CVE-2010-3477)

Dave Chinner discovered that the XFS filesystem did not correctly
order inode lookups when exported by NFS. A remote attacker could
exploit this to read or write disk blocks that had changed file
assignment or had become unlinked, leading to a loss of privacy.
(CVE-2010-2943)

Tavis Ormandy discovered that the IRDA subsystem did not correctly
shut down. A local attacker could exploit this to cause the system to
crash or possibly gain root privileges. (CVE-2010-2954)

Brad Spengler discovered that the wireless extensions did not
correctly validate certain request sizes. A local attacker could
exploit this to read portions of kernel memory, leading to a loss of
privacy. (CVE-2010-2955)

Tavis Ormandy discovered that the session keyring did not correctly
check for its parent. On systems without a default session keyring, a
local attacker could exploit this to crash the system, leading to a
denial of service. (CVE-2010-2960)

Kees Cook discovered that the Intel i915 graphics driver did not
correctly validate memory regions. A local attacker with access to the
video card could read and write arbitrary kernel memory to gain root
privileges. (CVE-2010-2962)

Kees Cook discovered that the V4L1 32bit compat interface did not
correctly validate certain parameters. A local attacker on a 64bit
system with access to a video device could exploit this to gain root
privileges. (CVE-2010-2963)

Tavis Ormandy discovered that the AIO subsystem did not correctly
validate certain parameters. A local attacker could exploit this to
crash the system or possibly gain root privileges. (CVE-2010-3067)

Dan Rosenberg discovered that certain XFS ioctls leaked kernel stack
contents. A local attacker could exploit this to read portions of
kernel memory, leading to a loss of privacy. (CVE-2010-3078)

Robert Swiecki discovered that ftrace did not correctly handle
mutexes. A local attacker could exploit this to crash the kernel,
leading to a denial of service. (CVE-2010-3079)

Tavis Ormandy discovered that the OSS sequencer device did not
correctly shut down. A local attacker could exploit this to crash the
system or possibly gain root privileges. (CVE-2010-3080)

Dan Rosenberg discovered that several network ioctls did not clear
kernel memory correctly. A local user could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-3296,
CVE-2010-3297, CVE-2010-3298)

Dan Rosenberg discovered that the ROSE driver did not correctly check
parameters. A local attacker with access to a ROSE network device
could exploit this to crash the system or possibly gain root
privileges. (CVE-2010-3310)

Thomas Dreibholz discovered that SCTP did not correctly handle
appending packet chunks. A remote attacker could send specially
crafted traffic to crash the system, leading to a denial of service.
(CVE-2010-3432)

Dan Rosenberg discovered that the CD driver did not correctly check
parameters. A local attacker could exploit this to read arbitrary
kernel memory, leading to a loss of privacy. (CVE-2010-3437)

Dan Rosenberg discovered that the Sound subsystem did not correctly
validate parameters. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-3442)

Dan Jacobson discovered that ThinkPad video output was not correctly
access controlled. A local attacker could exploit this to hang the
system, leading to a denial of service. (CVE-2010-3448)

It was discovered that KVM did not correctly initialize certain CPU
registers. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-3698)

Dan Rosenberg discovered that SCTP did not correctly handle HMAC
calculations. A remote attacker could send specially crafted traffic
that would crash the system, leading to a denial of service.
(CVE-2010-3705)

Brad Spengler discovered that stack memory for new a process was not
correctly calculated. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-3858)

Dan Rosenberg discovered that the Linux kernel TIPC implementation
contained multiple integer signedness errors. A local attacker could
exploit this to gain root privileges. (CVE-2010-3859)

Kees Cook discovered that the ethtool interface did not correctly
clear kernel memory. A local attacker could read kernel heap memory,
leading to a loss of privacy. (CVE-2010-3861)

Thomas Pollet discovered that the RDS network protocol did not check
certain iovec buffers. A local attacker could exploit this to crash
the system or possibly execute arbitrary code as the root user.
(CVE-2010-3865)

Dan Rosenberg discovered that the Linux kernel X.25 implementation
incorrectly parsed facilities. A remote attacker could exploit this to
crash the kernel, leading to a denial of service. (CVE-2010-3873)

Dan Rosenberg discovered that the CAN protocol on 64bit systems did
not correctly calculate the size of certain buffers. A local attacker
could exploit this to crash the system or possibly execute arbitrary
code as the root user. (CVE-2010-3874)

Vasiliy Kulikov discovered that the Linux kernel X.25 implementation
did not correctly clear kernel memory. A local attacker could exploit
this to read kernel stack memory, leading to a loss of privacy.
(CVE-2010-3875)

Vasiliy Kulikov discovered that the Linux kernel sockets
implementation did not properly initialize certain structures. A local
attacker could exploit this to read kernel stack memory, leading to a
loss of privacy. (CVE-2010-3876)

Vasiliy Kulikov discovered that the TIPC interface did not correctly
initialize certain structures. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-3877)

Nelson Elhage discovered that the Linux kernel IPv4 implementation did
not properly audit certain bytecodes in netlink messages. A local
attacker could exploit this to cause the kernel to hang, leading to a
denial of service. (CVE-2010-3880)

Vasiliy Kulikov discovered that kvm did not correctly clear memory. A
local attacker could exploit this to read portions of the kernel
stack, leading to a loss of privacy. (CVE-2010-3881)

Kees Cook and Vasiliy Kulikov discovered that the shm interface did
not clear kernel memory correctly. A local attacker could exploit this
to read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4072)

Dan Rosenberg discovered that IPC structures were not correctly
initialized on 64bit systems. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4073)

Dan Rosenberg discovered that multiple terminal ioctls did not
correctly initialize structure memory. A local attacker could exploit
this to read portions of kernel stack memory, leading to a loss of
privacy. (CVE-2010-4075)

Dan Rosenberg discovered that the ivtv V4L driver did not correctly
initialize certian structures. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4079)

Dan Rosenberg discovered that the RME Hammerfall DSP audio interface
driver did not correctly clear kernel memory. A local attacker could
exploit this to read kernel stack memory, leading to a loss of
privacy. (CVE-2010-4080, CVE-2010-4081)

Dan Rosenberg discovered that the VIA video driver did not correctly
clear kernel memory. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-4082)

Dan Rosenberg discovered that the semctl syscall did not correctly
clear kernel memory. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-4083)

James Bottomley discovered that the ICP vortex storage array
controller driver did not validate certain sizes. A local attacker on
a 64bit system could exploit this to crash the kernel, leading to a
denial of service. (CVE-2010-4157)

Dan Rosenberg discovered that the socket filters did not correctly
initialize structure memory. A local attacker could create malicious
filters to read portions of kernel stack memory, leading to a loss of
privacy. (CVE-2010-4158)

Dan Rosenberg discovered that the Linux kernel L2TP implementation
contained multiple integer signedness errors. A local attacker could
exploit this to to crash the kernel, or possibly gain root privileges.
(CVE-2010-4160)

Dan Rosenberg discovered that certain iovec operations did not
calculate page counts correctly. A local attacker could exploit this
to crash the system, leading to a denial of service. (CVE-2010-4162)

Dan Rosenberg discovered that the SCSI subsystem did not correctly
validate iov segments. A local attacker with access to a SCSI device
could send specially crafted requests to crash the system, leading to
a denial of service. (CVE-2010-4163, CVE-2010-4668)

Dan Rosenberg discovered multiple flaws in the X.25 facilities
parsing. If a system was using X.25, a remote attacker could exploit
this to crash the system, leading to a denial of service.
(CVE-2010-4164)

Steve Chen discovered that setsockopt did not correctly check MSS
values. A local attacker could make a specially crafted socket call to
crash the system, leading to a denial of service. (CVE-2010-4165)

Dave Jones discovered that the mprotect system call did not correctly
handle merged VMAs. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-4169)

Dan Rosenberg discovered that the RDS protocol did not correctly check
ioctl arguments. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-4175)

Alan Cox discovered that the HCI UART driver did not correctly check
if a write operation was available. If the mmap_min-addr sysctl was
changed from the Ubuntu default to a value of 0, a local attacker
could exploit this flaw to gain root privileges. (CVE-2010-4242)

It was discovered that multithreaded exec did not handle CPU timers
correctly. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-4248)

Vegard Nossum discovered that memory garbage collection was not
handled correctly for active sockets. A local attacker could exploit
this to allocate all available kernel memory, leading to a denial of
service. (CVE-2010-4249)

Nelson Elhage discovered that the kernel did not correctly handle
process cleanup after triggering a recoverable kernel bug. If a local
attacker were able to trigger certain kinds of kernel bugs, they could
create a specially crafted process to gain root privileges.
(CVE-2010-4258)

Krishna Gudipati discovered that the bfa adapter driver did not
correctly initialize certain structures. A local attacker could read
files in /sys to crash the system, leading to a denial of service.
(CVE-2010-4343)

Tavis Ormandy discovered that the install_special_mapping function
could bypass the mmap_min_addr restriction. A local attacker could
exploit this to mmap 4096 bytes below the mmap_min_addr area, possibly
improving the chances of performing NULL pointer dereference attacks.
(CVE-2010-4346)

It was discovered that the ICMP stack did not correctly handle certain
unreachable messages. If a remote attacker were able to acquire a
socket lock, they could send specially crafted traffic that would
crash the system, leading to a denial of service. (CVE-2010-4526)

Dan Rosenberg discovered that the OSS subsystem did not handle name
termination correctly. A local attacker could exploit this crash the
system or gain root privileges. (CVE-2010-4527)

An error was reported in the kernel's ORiNOCO wireless driver's
handling of TKIP countermeasures. This reduces the amount of time an
attacker needs breach a wireless network using WPA+TKIP for security.
(CVE-2010-4648)

Dan Carpenter discovered that the Infiniband driver did not correctly
handle certain requests. A local user could exploit this to crash the
system or potentially gain root privileges. (CVE-2010-4649,
CVE-2011-1044)

An error was discovered in the kernel's handling of CUSE (Character
device in Userspace). A local attacker might exploit this flaw to
escalate privilege, if access to /dev/cuse has been modified to allow
non-root users. (CVE-2010-4650)

Kees Cook discovered that some ethtool functions did not correctly
clear heap memory. A local attacker with CAP_NET_ADMIN privileges
could exploit this to read portions of kernel heap memory, leading to
a loss of privacy. (CVE-2010-4655)

Kees Cook discovered that the IOWarrior USB device driver did not
correctly check certain size fields. A local attacker with physical
access could plug in a specially crafted USB device to crash the
system or potentially gain root privileges. (CVE-2010-4656)

Joel Becker discovered that OCFS2 did not correctly validate on-disk
symlink structures. If an attacker were able to trick a user or
automated system into mounting a specially crafted filesystem, it
could crash the system or expose kernel memory, leading to a loss of
privacy. (CVE-2010-NNN2)

A flaw was found in the kernel's Integrity Measurement Architecture
(IMA). Changes made by an attacker might not be discovered by IMA, if
SELinux was disabled, and a new IMA rule was loaded. (CVE-2011-0006)

Dan Carpenter discovered that the TTPCI DVB driver did not check
certain values during an ioctl. If the dvb-ttpci module was loaded, a
local attacker could exploit this to crash the system, leading to a
denial of service, or possibly gain root privileges. (CVE-2011-0521)

Rafael Dominguez Vega discovered that the caiaq Native Instruments USB
driver did not correctly validate string lengths. A local attacker
with physical access could plug in a specially crafted USB device to
crash the system or potentially gain root privileges. (CVE-2011-0712)

Timo Warns discovered that MAC partition parsing routines did not
correctly calculate block counts. A local attacker with physical
access could plug in a specially crafted block device to crash the
system or potentially gain root privileges. (CVE-2011-1010)

Timo Warns discovered that LDM partition parsing routines did not
correctly calculate block counts. A local attacker with physical
access could plug in a specially crafted block device to crash the
system, leading to a denial of service. (CVE-2011-1012)

Nelson Elhage discovered that the epoll subsystem did not correctly
handle certain structures. A local attacker could create malicious
requests that would hang the system, leading to a denial of service.
(CVE-2011-1082)

Johan Hovold discovered that the DCCP network stack did not correctly
handle certain packet combinations. A remote attacker could send
specially crafted network traffic that would crash the system, leading
to a denial of service. (CVE-2011-1093)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-2.6.32-216-dove and / or
linux-image-2.6.32-416-dove packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2013 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}



include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/Ubuntu/release") ) audit(AUDIT_OS_NOT, "Ubuntu");
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-216-dove", pkgver:"2.6.32-216.33")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.32-416-dove", pkgver:"2.6.32-416.33")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
