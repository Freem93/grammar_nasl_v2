#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1083-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65101);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/26 14:05:56 $");

  script_cve_id("CVE-2009-4895", "CVE-2010-0435", "CVE-2010-2066", "CVE-2010-2226", "CVE-2010-2248", "CVE-2010-2478", "CVE-2010-2495", "CVE-2010-2521", "CVE-2010-2524", "CVE-2010-2537", "CVE-2010-2538", "CVE-2010-2798", "CVE-2010-2942", "CVE-2010-2943", "CVE-2010-2946", "CVE-2010-2954", "CVE-2010-2955", "CVE-2010-2960", "CVE-2010-2962", "CVE-2010-2963", "CVE-2010-3015", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3084", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3298", "CVE-2010-3301", "CVE-2010-3310", "CVE-2010-3432", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3477", "CVE-2010-3705", "CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-3858", "CVE-2010-3859", "CVE-2010-3861", "CVE-2010-3874", "CVE-2010-3904", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4164", "CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4175", "CVE-2010-4242", "CVE-2010-4243", "CVE-2010-4249", "CVE-2010-4256", "CVE-2010-4258", "CVE-2010-4655", "CVE-2011-0709");
  script_bugtraq_id(40920, 41077, 41223, 41466, 41847, 41854, 41904, 42124, 42242, 42249, 42477, 42527, 42529, 42582, 42589, 42885, 42900, 42932, 43022, 43062, 43098, 43221, 43226, 43229, 43353, 43355, 43368, 43480, 43551, 43684, 43701, 43787, 44067, 44219, 44242, 44301, 44427, 44830, 44861, 45037, 45054, 45072);
  script_xref(name:"USN", value:"1083-1");

  script_name(english:"Ubuntu 10.04 LTS : linux-lts-backport-maverick vulnerabilities (USN-1083-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
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

Ben Hawkes discovered that the Linux kernel did not correctly filter
registers on 64bit kernels when performing 32bit system calls. On a
64bit system, a local attacker could manipulate 32bit system calls to
gain root privileges. (CVE-2010-3301)

Al Viro discovered a race condition in the TTY driver. A local
attacker could exploit this to crash the system, leading to a denial
of service. (CVE-2009-4895)

Gleb Napatov discovered that KVM did not correctly check certain
privileged operations. A local attacker with access to a guest kernel
could exploit this to crash the host system, leading to a denial of
service. (CVE-2010-0435)

Dan Rosenberg discovered that the MOVE_EXT ext4 ioctl did not
correctly check file permissions. A local attacker could overwrite
append-only files, leading to potential data loss. (CVE-2010-2066)

Dan Rosenberg discovered that the swapexit xfs ioctl did not correctly
check file permissions. A local attacker could exploit this to read
from write-only files, leading to a loss of privacy. (CVE-2010-2226)

Suresh Jayaraman discovered that CIFS did not correctly validate
certain response packats. A remote attacker could send specially
crafted traffic that would crash the system, leading to a denial of
service. (CVE-2010-2248)

Ben Hutchings discovered that the ethtool interface did not correctly
check certain sizes. A local attacker could perform malicious ioctl
calls that could crash the system, leading to a denial of service.
(CVE-2010-2478, CVE-2010-3084)

James Chapman discovered that L2TP did not correctly evaluate checksum
capabilities. If an attacker could make malicious routing changes,
they could crash the system, leading to a denial of service.
(CVE-2010-2495)

Neil Brown discovered that NFSv4 did not correctly check certain write
requests. A remote attacker could send specially crafted traffic that
could crash the system or possibly gain root privileges.
(CVE-2010-2521)

David Howells discovered that DNS resolution in CIFS could be spoofed.
A local attacker could exploit this to control DNS replies, leading to
a loss of privacy and possible privilege escalation. (CVE-2010-2524)

Dan Rosenberg discovered that the btrfs filesystem did not correctly
validate permissions when using the clone function. A local attacker
could overwrite the contents of file handles that were opened for
append-only, or potentially read arbitrary contents, leading to a loss
of privacy. (CVE-2010-2537, CVE-2010-2538)

Bob Peterson discovered that GFS2 rename operations did not correctly
validate certain sizes. A local attacker could exploit this to crash
the system, leading to a denial of service. (CVE-2010-2798)

Eric Dumazet discovered that many network functions could leak kernel
stack contents. A local attacker could exploit this to read portions
of kernel memory, leading to a loss of privacy. (CVE-2010-2942,
CVE-2010-3477)

Dave Chinner discovered that the XFS filesystem did not correctly
order inode lookups when exported by NFS. A remote attacker could
exploit this to read or write disk blocks that had changed file
assignment or had become unlinked, leading to a loss of privacy.
(CVE-2010-2943)

Sergey Vlasov discovered that JFS did not correctly handle certain
extended attributes. A local attacker could bypass namespace access
rules, leading to a loss of privacy. (CVE-2010-2946)

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

Toshiyuki Okajima discovered that ext4 did not correctly check certain
parameters. A local attacker could exploit this to crash the system or
overwrite the last block of large files. (CVE-2010-3015)

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

Dan Rosenberg discovered that the CAN protocol on 64bit systems did
not correctly calculate the size of certain buffers. A local attacker
could exploit this to crash the system or possibly execute arbitrary
code as the root user. (CVE-2010-3874)

Kees Cook and Vasiliy Kulikov discovered that the shm interface did
not clear kernel memory correctly. A local attacker could exploit this
to read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4072)

Dan Rosenberg discovered that IPC structures were not correctly
initialized on 64bit systems. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4073)

Dan Rosenberg discovered that the RME Hammerfall DSP audio interface
driver did not correctly clear kernel memory. A local attacker could
exploit this to read kernel stack memory, leading to a loss of
privacy. (CVE-2010-4080, CVE-2010-4081)

Dan Rosenberg discovered that the VIA video driver did not correctly
clear kernel memory. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-4082)

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

Brad Spengler discovered that the kernel did not correctly account for
userspace memory allocations during exec() calls. A local attacker
could exploit this to consume all system memory, leading to a denial
of service. (CVE-2010-4243)

Vegard Nossum discovered that memory garbage collection was not
handled correctly for active sockets. A local attacker could exploit
this to allocate all available kernel memory, leading to a denial of
service. (CVE-2010-4249)

It was discovered that named pipes did not correctly handle certain
fcntl calls. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-4256)

Nelson Elhage discovered that the kernel did not correctly handle
process cleanup after triggering a recoverable kernel bug. If a local
attacker were able to trigger certain kinds of kernel bugs, they could
create a specially crafted process to gain root privileges.
(CVE-2010-4258)

Kees Cook discovered that some ethtool functions did not correctly
clear heap memory. A local attacker with CAP_NET_ADMIN privileges
could exploit this to read portions of kernel heap memory, leading to
a loss of privacy. (CVE-2010-4655)

Frank Arnold discovered that the IGMP protocol did not correctly parse
certain packets. A remote attacker could send specially crafted
traffic to crash the system, leading to a denial of service.
(CVE-2011-0709).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.35-25", pkgver:"2.6.35-25.44~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.35-25-generic", pkgver:"2.6.35-25.44~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.35-25-generic-pae", pkgver:"2.6.35-25.44~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.35-25-server", pkgver:"2.6.35-25.44~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.35-25-virtual", pkgver:"2.6.35-25.44~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.35-25-generic", pkgver:"2.6.35-25.44~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.35-25-generic-pae", pkgver:"2.6.35-25.44~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.35-25-server", pkgver:"2.6.35-25.44~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.35-25-virtual", pkgver:"2.6.35-25.44~lucid1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-headers-2.6 / linux-headers-2.6-generic / etc");
}
