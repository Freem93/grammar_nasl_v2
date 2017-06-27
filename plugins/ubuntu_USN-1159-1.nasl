#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1159-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55589);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/26 16:14:08 $");

  script_cve_id("CVE-2010-4243", "CVE-2010-4263", "CVE-2010-4342", "CVE-2010-4529", "CVE-2010-4565", "CVE-2011-0463", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0726", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1017", "CVE-2011-1019", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1090", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1478", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1573", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1747", "CVE-2011-1748", "CVE-2011-1759", "CVE-2011-1770", "CVE-2011-1776", "CVE-2011-2022", "CVE-2011-2534", "CVE-2011-3359", "CVE-2011-3363", "CVE-2011-4611", "CVE-2011-4913");
  script_bugtraq_id(44661, 44666, 45004, 45208, 45321, 45556, 46417, 46557, 46766, 46839, 46878, 46919, 46921, 47003, 47116, 47185, 47497, 47503, 47534, 47535, 47639, 47769, 47791, 47792, 47832, 47835, 47843, 47990);
  script_xref(name:"USN", value:"1159-1");

  script_name(english:"Ubuntu 10.10 : linux-mvl-dove vulnerabilities (USN-1159-1)");
  script_summary(english:"Checks dpkg output for updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Brad Spengler discovered that the kernel did not correctly account for
userspace memory allocations during exec() calls. A local attacker
could exploit this to consume all system memory, leading to a denial
of service. (CVE-2010-4243)

Alexander Duyck discovered that the Intel Gigabit Ethernet driver did
not correctly handle certain configurations. If such a device was
configured without VLANs, a remote attacker could crash the system,
leading to a denial of service. (CVE-2010-4263)

Nelson Elhage discovered that Econet did not correctly handle AUN
packets over UDP. A local attacker could send specially crafted
traffic to crash the system, leading to a denial of service.
(CVE-2010-4342)

Dan Rosenberg discovered that IRDA did not correctly check the size of
buffers. On non-x86 systems, a local attacker could exploit this to
read kernel heap memory, leading to a loss of privacy. (CVE-2010-4529)

Dan Rosenburg discovered that the CAN subsystem leaked kernel
addresses into the /proc filesystem. A local attacker could use this
to increase the chances of a successful memory corruption exploit.
(CVE-2010-4565)

Goldwyn Rodrigues discovered that the OCFS2 filesystem did not
correctly clear memory when writing certain file holes. A local
attacker could exploit this to read uninitialized data from the disk,
leading to a loss of privacy. (CVE-2011-0463)

Jens Kuehnel discovered that the InfiniBand driver contained a race
condition. On systems using InfiniBand, a local attacker could send
specially crafted requests to crash the system, leading to a denial of
service. (CVE-2011-0695)

Dan Rosenberg discovered that XFS did not correctly initialize memory.
A local attacker could make crafted ioctl calls to leak portions of
kernel stack memory, leading to a loss of privacy. (CVE-2011-0711)

Kees Cook reported that /proc/pid/stat did not correctly filter
certain memory locations. A local attacker could determine the memory
layout of processes in an attempt to increase the chances of a
successful memory corruption exploit. (CVE-2011-0726)

Matthiew Herrb discovered that the drm modeset interface did not
correctly handle a signed comparison. A local attacker could exploit
this to crash the system or possibly gain root privileges.
(CVE-2011-1013)

Marek Olsak discovered that the Radeon GPU drivers did not correctly
validate certain registers. On systems with specific hardware, a local
attacker could exploit this to write to arbitrary video memory.
(CVE-2011-1016)

Timo Warns discovered that the LDM disk partition handling code did
not correctly handle certain values. By inserting a specially crafted
disk device, a local attacker could exploit this to gain root
privileges. (CVE-2011-1017)

Vasiliy Kulikov discovered that the CAP_SYS_MODULE capability was not
needed to load kernel modules. A local attacker with the CAP_NET_ADMIN
capability could load existing kernel modules, possibly increasing the
attack surface available on the system. (CVE-2011-1019)

Vasiliy Kulikov discovered that the Bluetooth stack did not correctly
clear memory. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2011-1078)

Vasiliy Kulikov discovered that the Bluetooth stack did not correctly
check that device name strings were NULL terminated. A local attacker
could exploit this to crash the system, leading to a denial of
service, or leak contents of kernel stack memory, leading to a loss of
privacy. (CVE-2011-1079)

Vasiliy Kulikov discovered that bridge network filtering did not check
that name fields were NULL terminated. A local attacker could exploit
this to leak contents of kernel stack memory, leading to a loss of
privacy. (CVE-2011-1080)

Neil Horman discovered that NFSv4 did not correctly handle certain
orders of operation with ACL data. A remote attacker with access to an
NFSv4 mount could exploit this to crash the system, leading to a
denial of service. (CVE-2011-1090)

Peter Huewe discovered that the TPM device did not correctly
initialize memory. A local attacker could exploit this to read kernel
heap memory contents, leading to a loss of privacy. (CVE-2011-1160)

Timo Warns discovered that OSF partition parsing routines did not
correctly clear memory. A local attacker with physical access could
plug in a specially crafted block device to read kernel memory,
leading to a loss of privacy. (CVE-2011-1163)

Vasiliy Kulikov discovered that the netfilter code did not check
certain strings copied from userspace. A local attacker with netfilter
access could exploit this to read kernel memory or crash the system,
leading to a denial of service. (CVE-2011-1170, CVE-2011-1171,
CVE-2011-1172, CVE-2011-2534)

Vasiliy Kulikov discovered that the Acorn Universal Networking driver
did not correctly initialize memory. A remote attacker could send
specially crafted traffic to read kernel stack memory, leading to a
loss of privacy. (CVE-2011-1173)

Dan Rosenberg discovered that the IRDA subsystem did not correctly
check certain field sizes. If a system was using IRDA, a remote
attacker could send specially crafted traffic to crash the system or
gain root privileges. (CVE-2011-1180)

Julien Tinnes discovered that the kernel did not correctly validate
the signal structure from tkill(). A local attacker could exploit this
to send signals to arbitrary threads, possibly bypassing expected
restrictions. (CVE-2011-1182)

Dan Rosenberg reported errors in the OSS (Open Sound System) MIDI
interface. A local attacker on non-x86 systems might be able to cause
a denial of service. (CVE-2011-1476)

Dan Rosenberg reported errors in the kernel's OSS (Open Sound System)
driver for Yamaha FM synthesizer chips. A local user can exploit this
to cause memory corruption, causing a denial of service or privilege
escalation. (CVE-2011-1477)

Ryan Sweat discovered that the GRO code did not correctly validate
memory. In some configurations on systems using VLANs, a remote
attacker could send specially crafted traffic to crash the system,
leading to a denial of service. (CVE-2011-1478)

Dan Rosenberg discovered that MPT devices did not correctly validate
certain values in ioctl calls. If these drivers were loaded, a local
attacker could exploit this to read arbitrary kernel memory, leading
to a loss of privacy. (CVE-2011-1494, CVE-2011-1495)

It was discovered that the Stream Control Transmission Protocol (SCTP)
implementation incorrectly calculated lengths. If the
net.sctp.addip_enable variable was turned on, a remote attacker could
send specially crafted traffic to crash the system. (CVE-2011-1573)

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

Dan Rosenberg reported an error in the old ABI compatibility layer of
ARM kernels. A local attacker could exploit this flaw to cause a
denial of service or gain root privileges. (CVE-2011-1759)

Dan Rosenberg discovered that the DCCP stack did not correctly handle
certain packet structures. A remote attacker could exploit this to
crash the system, leading to a denial of service. (CVE-2011-1770)

Timo Warns discovered that the EFI GUID partition table was not
correctly parsed. A physically local attacker that could insert
mountable devices could exploit this to crash the system or possibly
gain root privileges. (CVE-2011-1776)

A flaw was found in the b43 driver in the Linux kernel. An attacker
could use this flaw to cause a denial of service if the system has an
active wireless interface using the b43 driver. (CVE-2011-3359)

Yogesh Sharma discovered that CIFS did not correctly handle UNCs that
had no prefixpaths. A local attacker with access to a CIFS partition
could exploit this to crash the system, leading to a denial of
service. (CVE-2011-3363)

Maynard Johnson discovered that on POWER7, certain speculative events
may raise a performance monitor exception. A local attacker could
exploit this to crash the system, leading to a denial of service.
(CVE-2011-4611)

Dan Rosenberg discovered flaws in the linux Rose (X.25 PLP) layer used
by amateur radio. A local user or a remote user on an X.25 network
could exploit these flaws to execute arbitrary code as root.
(CVE-2011-4913)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected linux-image-2.6.32-417-dove package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2013 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.32-417-dove", pkgver:"2.6.32-417.34")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
