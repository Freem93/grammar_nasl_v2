# This script was automatically generated from Ubuntu Security
# Notice USN-1202-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(56190);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/26 16:14:09 $");

  script_cve_id("CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3858", "CVE-2010-3859", "CVE-2010-3874", "CVE-2010-3880", "CVE-2010-4073", "CVE-2010-4075", "CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4169", "CVE-2010-4175", "CVE-2010-4242", "CVE-2010-4243", "CVE-2010-4248", "CVE-2010-4256", "CVE-2010-4565", "CVE-2010-4649", "CVE-2010-4655", "CVE-2010-4656", "CVE-2010-4668", "CVE-2011-0463", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-0726", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1017", "CVE-2011-1019", "CVE-2011-1020", "CVE-2011-1044", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1082", "CVE-2011-1090", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1169", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1478", "CVE-2011-1493", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1577", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1748", "CVE-2011-1770", "CVE-2011-1833", "CVE-2011-2022", "CVE-2011-2484", "CVE-2011-2492", "CVE-2011-2534", "CVE-2011-2699", "CVE-2011-2918");
  script_xref(name:"USN", value:"1202-1");

  script_name(english:"USN-1202-1 : linux-ti-omap4 vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Dan Rosenberg discovered that several network ioctls did not clear
kernel memory correctly. A local user could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-3296,
CVE-2010-3297)

Brad Spengler discovered that stack memory for new a process was not
correctly calculated. A local attacker could exploit this to crash
the system, leading to a denial of service. (CVE-2010-3858)

Dan Rosenberg discovered that the Linux kernel TIPC implementation
contained multiple integer signedness errors. A local attacker could
exploit this to gain root privileges. (CVE-2010-3859)

Dan Rosenberg discovered that the CAN protocol on 64bit systems did
not correctly calculate the size of certain buffers. A local attacker
could exploit this to crash the system or possibly execute arbitrary
code as the root user. (CVE-2010-3874)

Nelson Elhage discovered that the Linux kernel IPv4 implementation
did not properly audit certain bytecodes in netlink messages. A local
attacker could exploit this to cause the kernel to hang, leading to a
denial of service. (CVE-2010-3880)

Dan Rosenberg discovered that IPC structures were not correctly
initialized on 64bit systems. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4073)

Dan Rosenberg discovered that multiple terminal ioctls did not
correctly initialize structure memory. A local attacker could exploit
this to read portions of kernel stack memory, leading to a loss of
privacy. (CVE-2010-4075, CVE-2010-4076, CVE-2010-4077)

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

Dan Rosenberg discovered that the Linux kernel L2TP implementation
contained multiple integer signedness errors. A local attacker could
exploit this to to crash the kernel, or possibly gain root
privileges. (CVE-2010-4160)

Dan Rosenberg discovered that certain iovec operations did not
calculate page counts correctly. A local attacker could exploit this
to crash the system, leading to a denial of service. (CVE-2010-4162)

Dan Rosenberg discovered that the SCSI subsystem did not correctly
validate iov segments. A local attacker with access to a SCSI device
could send specially crafted requests to crash the system, leading to
a denial of service. (CVE-2010-4163, CVE-2010-4668)

Dave Jones discovered that the mprotect system call did not correctly
handle merged VMAs. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-4169)

Dan Rosenberg discovered that the RDS protocol did not correctly
check ioctl arguments. A local attacker could exploit this to crash
the system, leading to a denial of service. (CVE-2010-4175)

Alan Cox discovered that the HCI UART driver did not correctly check
if a write operation was available. If the mmap_min-addr sysctl was
changed from the Ubuntu default to a value of 0, a local attacker
could exploit this flaw to gain root privileges. (CVE-2010-4242)

Brad Spengler discovered that the kernel did not correctly account
for userspace memory allocations during exec() calls. A local
attacker could exploit this to consume all system memory, leading to
a denial of service. (CVE-2010-4243)

It was discovered that multithreaded exec did not handle CPU timers
correctly. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-4248)

It was discovered that named pipes did not correctly handle certain
fcntl calls. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-4256)

Dan Rosenburg discovered that the CAN subsystem leaked kernel
addresses into the /proc filesystem. A local attacker could use this
to increase the chances of a successful memory corruption exploit.
(CVE-2010-4565)

Dan Carpenter discovered that the Infiniband driver did not correctly
handle certain requests. A local user could exploit this to crash the
system or potentially gain root privileges. (CVE-2010-4649,
CVE-2011-1044)

Kees Cook discovered that some ethtool functions did not correctly
clear heap memory. A local attacker with CAP_NET_ADMIN privileges
could exploit this to read portions of kernel heap memory, leading to
a loss of privacy. (CVE-2010-4655)

Kees Cook discovered that the IOWarrior USB device driver did not
correctly check certain size fields. A local attacker with physical
access could plug in a specially crafted USB device to crash the
system or potentially gain root privileges. (CVE-2010-4656)

Goldwyn Rodrigues discovered that the OCFS2 filesystem did not
correctly clear memory when writing certain file holes. A local
attacker could exploit this to read uninitialized data from the disk,
leading to a loss of privacy. (CVE-2011-0463)

Dan Carpenter discovered that the TTPCI DVB driver did not check
certain values during an ioctl. If the dvb-ttpci module was loaded, a
local attacker could exploit this to crash the system, leading to a
denial of service, or possibly gain root privileges. (CVE-2011-0521)

Jens Kuehnel discovered that the InfiniBand driver contained a race
condition. On systems using InfiniBand, a local attacker could send
specially crafted requests to crash the system, leading to a denial
of service. (CVE-2011-0695)

Dan Rosenberg discovered that XFS did not correctly initialize
memory. A local attacker could make crafted ioctl calls to leak
portions of kernel stack memory, leading to a loss of privacy.
(CVE-2011-0711)

Rafael Dominguez Vega discovered that the caiaq Native Instruments
USB driver did not correctly validate string lengths. A local
attacker with physical access could plug in a specially crafted USB
device to crash the system or potentially gain root privileges.
(CVE-2011-0712)

Kees Cook reported that /proc/pid/stat did not correctly filter
certain memory locations. A local attacker could determine the memory
layout of processes in an attempt to increase the chances of a
successful memory corruption exploit. (CVE-2011-0726)

Timo Warns discovered that MAC partition parsing routines did not
correctly calculate block counts. A local attacker with physical
access could plug in a specially crafted block device to crash the
system or potentially gain root privileges. (CVE-2011-1010)

Timo Warns discovered that LDM partition parsing routines did not
correctly calculate block counts. A local attacker with physical
access could plug in a specially crafted block device to crash the
system, leading to a denial of service. (CVE-2011-1012)

Matthiew Herrb discovered that the drm modeset interface did not
correctly handle a signed comparison. A local attacker could exploit
this to crash the system or possibly gain root privileges.
(CVE-2011-1013)

Marek Olsak discovered that the Radeon GPU drivers did not
correctly validate certain registers. On systems with specific
hardware, a local attacker could exploit this to write to arbitrary
video memory. (CVE-2011-1016)

Timo Warns discovered that the LDM disk partition handling code did
not correctly handle certain values. By inserting a specially crafted
disk device, a local attacker could exploit this to gain root
privileges. (CVE-2011-1017)

Vasiliy Kulikov discovered that the CAP_SYS_MODULE capability was not
needed to load kernel modules. A local attacker with the
CAP_NET_ADMIN capability could load existing kernel modules, possibly
increasing the attack surface available on the system.
(CVE-2011-1019)

It was discovered that the /proc filesystem did not correctly handle
permission changes when programs executed. A local attacker could
hold open files to examine details about programs running with higher
privileges, potentially increasing the chances of exploiting
additional vulnerabilities. (CVE-2011-1020)

Vasiliy Kulikov discovered that the Bluetooth stack did not correctly
clear memory. A local attacker could exploit this to read kernel
stack memory, leading to a loss of privacy. (CVE-2011-1078)

Vasiliy Kulikov discovered that the Bluetooth stack did not correctly
check that device name strings were NULL terminated. A local attacker
could exploit this to crash the system, leading to a denial of
service, or leak contents of kernel stack memory, leading to a loss
of privacy. (CVE-2011-1079)

Vasiliy Kulikov discovered that bridge network filtering did not
check that name fields were NULL terminated. A local attacker could
exploit this to leak contents of kernel stack memory, leading to a
loss of privacy. (CVE-2011-1080)

Nelson Elhage discovered that the epoll subsystem did not correctly
handle certain structures. A local attacker could create malicious
requests that would hang the system, leading to a denial of service.
(CVE-2011-1082)

Neil Horman discovered that NFSv4 did not correctly handle certain
orders of operation with ACL data. A remote attacker with access to
an NFSv4 mount could exploit this to crash the system, leading to a
denial of service. (CVE-2011-1090)

Johan Hovold discovered that the DCCP network stack did not correctly
handle certain packet combinations. A remote attacker could send
specially crafted network traffic that would crash the system,
leading to a denial of service. (CVE-2011-1093)

Peter Huewe discovered that the TPM device did not correctly
initialize memory. A local attacker could exploit this to read kernel
heap memory contents, leading to a loss of privacy. (CVE-2011-1160)

Timo Warns discovered that OSF partition parsing routines did not
correctly clear memory. A local attacker with physical access could
plug in a specially crafted block device to read kernel memory,
leading to a loss of privacy. (CVE-2011-1163)

Dan Rosenberg discovered that some ALSA drivers did not correctly
check the adapter index during ioctl calls. If this driver was
loaded, a local attacker could make a specially crafted ioctl call to
gain root privileges. (CVE-2011-1169)

Vasiliy Kulikov discovered that the netfilter code did not check
certain strings copied from userspace. A local attacker with
netfilter access could exploit this to read kernel memory or crash
the system, leading to a denial of service. (CVE-2011-1170,
CVE-2011-1171, CVE-2011-1172, CVE-2011-2534)

Vasiliy Kulikov discovered that the Acorn Universal Networking driver
did not correctly initialize memory. A remote attacker could send
specially crafted traffic to read kernel stack memory, leading to a
loss of privacy. (CVE-2011-1173)

Dan Rosenberg discovered that the IRDA subsystem did not correctly
check certain field sizes. If a system was using IRDA, a remote
attacker could send specially crafted traffic to crash the system or
gain root privileges. (CVE-2011-1180)

Julien Tinnes discovered that the kernel did not correctly validate
the signal structure from tkill(). A local attacker could exploit
this to send signals to arbitrary threads, possibly bypassing
expected restrictions. (CVE-2011-1182)

Ryan Sweat discovered that the GRO code did not correctly validate
memory. In some configurations on systems using VLANs, a remote
attacker could send specially crafted traffic to crash the system,
leading to a denial of service. (CVE-2011-1478)

Dan Rosenberg discovered that the X.25 Rose network stack did not
correctly handle certain fields. If a system was running with Rose
enabled, a remote attacker could send specially crafted traffic to
gain root privileges. (CVE-2011-1493)

Dan Rosenberg discovered that MPT devices did not correctly validate
certain values in ioctl calls. If these drivers were loaded, a local
attacker could exploit this to read arbitrary kernel memory, leading
to a loss of privacy. (CVE-2011-1494, CVE-2011-1495)

Timo Warns discovered that the GUID partition parsing routines did
not correctly validate certain structures. A local attacker with
physical access could plug in a specially crafted block device to
crash the system, leading to a denial of service. (CVE-2011-1577)

Tavis Ormandy discovered that the pidmap function did not correctly
handle large requests. A local attacker could exploit this to crash
the system, leading to a denial of service. (CVE-2011-1593)

Oliver Hartkopp and Dave Jones discovered that the CAN network driver
did not correctly validate certain socket structures. If this driver
was loaded, a local attacker could crash the system, leading to a
denial of service. (CVE-2011-1598, CVE-2011-1748)

Vasiliy Kulikov discovered that the AGP driver did not check certain
ioctl values. A local attacker with access to the video subsystem
could exploit this to crash the system, leading to a denial of
service, or possibly gain root privileges. (CVE-2011-1745,
CVE-2011-2022)

Vasiliy Kulikov discovered that the AGP driver did not check the size
of certain memory allocations. A local attacker with access to the
video subsystem could exploit this to run the system out of memory,
leading to a denial of service. (CVE-2011-1746)

Dan Rosenberg discovered that the DCCP stack did not correctly handle
certain packet structures. A remote attacker could exploit this to
crash the system, leading to a denial of service. (CVE-2011-1770)

Vasiliy Kulikov and Dan Rosenberg discovered that ecryptfs did not
correctly check the origin of mount points. A local attacker could
exploit this to trick the system into unmounting arbitrary mount
points, leading to a denial of service. (CVE-2011-1833)

Vasiliy Kulikov discovered that taskstats listeners were not
correctly handled. A local attacker could expoit this to exhaust
memory and CPU resources, leading to a denial of service.
(CVE-2011-2484)

It was discovered that Bluetooth l2cap and rfcomm did not correctly
initialize structures. A local attacker could exploit this to read
portions of the kernel stack, leading to a loss of privacy.
(CVE-2011-2492)

Fernando Gont discovered that the IPv6 stack used predictable
fragment identification numbers. A remote attacker could exploit this
to exhaust network resources, leading to a denial of service.
(CVE-2011-2699)

The performance counter subsystem did not correctly handle certain
counters. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-2918)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1202-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/13");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2011/09/14");
  script_end_attributes();
    
  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright("Ubuntu Security Notice (C) 2011 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include("ubuntu.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Ubuntu/release")) exit(0, "The host is not running Ubuntu.");
if (!get_kb_item("Host/Debian/dpkg-l")) exit(1, "Could not obtain the list of installed packages.");

flag = 0;

if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-903-omap4", pkgver:"2.6.35-903.24")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
