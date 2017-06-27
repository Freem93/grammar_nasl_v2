#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1256-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56768);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/26 14:05:57 $");

  script_cve_id("CVE-2010-4250", "CVE-2011-1020", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1180", "CVE-2011-1478", "CVE-2011-1479", "CVE-2011-1493", "CVE-2011-1573", "CVE-2011-1576", "CVE-2011-1577", "CVE-2011-1581", "CVE-2011-1585", "CVE-2011-1767", "CVE-2011-1768", "CVE-2011-1771", "CVE-2011-1776", "CVE-2011-1833", "CVE-2011-2182", "CVE-2011-2183", "CVE-2011-2213", "CVE-2011-2479", "CVE-2011-2484", "CVE-2011-2491", "CVE-2011-2492", "CVE-2011-2493", "CVE-2011-2494", "CVE-2011-2495", "CVE-2011-2496", "CVE-2011-2497", "CVE-2011-2517", "CVE-2011-2525", "CVE-2011-2689", "CVE-2011-2695", "CVE-2011-2699", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2905", "CVE-2011-2909", "CVE-2011-2918", "CVE-2011-2928", "CVE-2011-2942", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3209", "CVE-2011-3363", "CVE-2011-3619", "CVE-2011-3637", "CVE-2011-4087", "CVE-2011-4326", "CVE-2011-4914");
  script_bugtraq_id(46567, 46616, 46793, 46866, 46935, 46980, 47056, 47296, 47308, 47321, 47343, 47381, 47768, 47796, 47852, 47853, 47926, 48101, 48333, 48347, 48383, 48441, 48472, 48538, 48641, 48677, 48697, 48802, 48804, 48907, 48929, 49108, 49140, 49141, 49408, 49411, 50314);
  script_osvdb_id(71271, 71604, 71656, 73049, 73054, 73237, 73451, 73459, 73460, 73802, 73882, 74123, 74138, 74624, 74633, 74634, 74635, 74636, 74639, 74640, 74642, 74645, 74650, 74651, 74652, 74653, 74654, 74655, 74657, 74658, 74659, 74660, 74661, 74676, 74677, 74678, 74679, 74680, 74823, 74879, 74881, 74882, 74910, 75580, 75716, 76796, 77684);
  script_xref(name:"USN", value:"1256-1");

  script_name(english:"Ubuntu 10.04 LTS : linux-lts-backport-natty vulnerabilities (USN-1256-1)");
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
"It was discovered that the /proc filesystem did not correctly handle
permission changes when programs executed. A local attacker could hold
open files to examine details about programs running with higher
privileges, potentially increasing the chances of exploiting
additional vulnerabilities. (CVE-2011-1020)

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

Johan Hovold discovered that the DCCP network stack did not correctly
handle certain packet combinations. A remote attacker could send
specially crafted network traffic that would crash the system, leading
to a denial of service. (CVE-2011-1093)

Peter Huewe discovered that the TPM device did not correctly
initialize memory. A local attacker could exploit this to read kernel
heap memory contents, leading to a loss of privacy. (CVE-2011-1160)

Dan Rosenberg discovered that the IRDA subsystem did not correctly
check certain field sizes. If a system was using IRDA, a remote
attacker could send specially crafted traffic to crash the system or
gain root privileges. (CVE-2011-1180)

Ryan Sweat discovered that the GRO code did not correctly validate
memory. In some configurations on systems using VLANs, a remote
attacker could send specially crafted traffic to crash the system,
leading to a denial of service. (CVE-2011-1478)

It was discovered that the security fix for CVE-2010-4250 introduced a
regression. A remote attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-1479)

Dan Rosenberg discovered that the X.25 Rose network stack did not
correctly handle certain fields. If a system was running with Rose
enabled, a remote attacker could send specially crafted traffic to
gain root privileges. (CVE-2011-1493)

It was discovered that the Stream Control Transmission Protocol (SCTP)
implementation incorrectly calculated lengths. If the
net.sctp.addip_enable variable was turned on, a remote attacker could
send specially crafted traffic to crash the system. (CVE-2011-1573)

Ryan Sweat discovered that the kernel incorrectly handled certain VLAN
packets. On some systems, a remote attacker could send specially
crafted traffic to crash the system, leading to a denial of service.
(CVE-2011-1576)

Timo Warns discovered that the GUID partition parsing routines did not
correctly validate certain structures. A local attacker with physical
access could plug in a specially crafted block device to crash the
system, leading to a denial of service. (CVE-2011-1577)

Phil Oester discovered that the network bonding system did not
correctly handle large queues. On some systems, a remote attacker
could send specially crafted traffic to crash the system, leading to a
denial of service. (CVE-2011-1581)

It was discovered that CIFS incorrectly handled authentication. When a
user had a CIFS share mounted that required authentication, a local
user could mount the same share without knowing the correct password.
(CVE-2011-1585)

It was discovered that the GRE protocol incorrectly handled netns
initialization. A remote attacker could send a packet while the ip_gre
module was loading, and crash the system, leading to a denial of
service. (CVE-2011-1767)

It was discovered that the IP/IP protocol incorrectly handled netns
initialization. A remote attacker could send a packet while the ipip
module was loading, and crash the system, leading to a denial of
service. (CVE-2011-1768)

Ben Greear discovered that CIFS did not correctly handle direct I/O. A
local attacker with access to a CIFS partition could exploit this to
crash the system, leading to a denial of service. (CVE-2011-1771)

Timo Warns discovered that the EFI GUID partition table was not
correctly parsed. A physically local attacker that could insert
mountable devices could exploit this to crash the system or possibly
gain root privileges. (CVE-2011-1776)

Vasiliy Kulikov and Dan Rosenberg discovered that ecryptfs did not
correctly check the origin of mount points. A local attacker could
exploit this to trick the system into unmounting arbitrary mount
points, leading to a denial of service. (CVE-2011-1833)

Ben Hutchings reported a flaw in the kernel's handling of corrupt LDM
partitions. A local user could exploit this to cause a denial of
service or escalate privileges. (CVE-2011-2182)

Dan Rosenberg discovered that the IPv4 diagnostic routines did not
correctly validate certain requests. A local attacker could exploit
this to consume CPU resources, leading to a denial of service.
(CVE-2011-2213)

It was discovered that an mmap() call with the MAP_PRIVATE flag on
'/dev/zero' was incorrectly handled. A local attacker could exploit
this to crash the system, leading to a denial of service.
(CVE-2011-2479)

Vasiliy Kulikov discovered that taskstats listeners were not correctly
handled. A local attacker could exploit this to exhaust memory and CPU
resources, leading to a denial of service. (CVE-2011-2484)

It was discovered that Bluetooth l2cap and rfcomm did not correctly
initialize structures. A local attacker could exploit this to read
portions of the kernel stack, leading to a loss of privacy.
(CVE-2011-2492)

Sami Liedes discovered that ext4 did not correctly handle missing root
inodes. A local attacker could trigger the mount of a specially
crafted filesystem to cause the system to crash, leading to a denial
of service. (CVE-2011-2493)

Robert Swiecki discovered that mapping extensions were incorrectly
handled. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-2496)

Dan Rosenberg discovered that the Bluetooth stack incorrectly handled
certain L2CAP requests. If a system was using Bluetooth, a remote
attacker could send specially crafted traffic to crash the system or
gain root privileges. (CVE-2011-2497)

Ben Pfaff discovered that Classless Queuing Disciplines (qdiscs) were
being incorrectly handled. A local attacker could exploit this to
crash the system, leading to a denial of service. (CVE-2011-2525)

It was discovered that GFS2 did not correctly check block sizes. A
local attacker could exploit this to crash the system, leading to a
denial of service. (CVE-2011-2689)

It was discovered that the EXT4 filesystem contained multiple
off-by-one flaws. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2011-2695)

Fernando Gont discovered that the IPv6 stack used predictable fragment
identification numbers. A remote attacker could exploit this to
exhaust network resources, leading to a denial of service.
(CVE-2011-2699)

Mauro Carvalho Chehab discovered that the si4713 radio driver did not
correctly check the length of memory copies. If this hardware was
available, a local attacker could exploit this to crash the system or
gain root privileges. (CVE-2011-2700)

Herbert Xu discovered that certain fields were incorrectly handled
when Generic Receive Offload (CVE-2011-2723)

The performance counter subsystem did not correctly handle certain
counters. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-2918)

Time Warns discovered that long symlinks were incorrectly handled on
Be filesystems. A local attacker could exploit this with a malformed
Be filesystem and crash the system, leading to a denial of service.
(CVE-2011-2928)

Qianfeng Zhang discovered that the bridge networking interface
incorrectly handled certain network packets. A remote attacker could
exploit this to crash the system, leading to a denial of service.
(CVE-2011-2942)

Dan Kaminsky discovered that the kernel incorrectly handled random
sequence number generation. An attacker could use this flaw to
possibly predict sequence numbers and inject packets. (CVE-2011-3188)

Darren Lavender discovered that the CIFS client incorrectly handled
certain large values. A remote attacker with a malicious server could
exploit this to crash the system or possibly execute arbitrary code as
the root user. (CVE-2011-3191)

Yasuaki Ishimatsu discovered a flaw in the kernel's clock
implementation. A local unprivileged attacker could exploit this
causing a denial of service. (CVE-2011-3209)

Yogesh Sharma discovered that CIFS did not correctly handle UNCs that
had no prefixpaths. A local attacker with access to a CIFS partition
could exploit this to crash the system, leading to a denial of
service. (CVE-2011-3363)

A flaw was discovered in the Linux kernel's AppArmor security
interface when invalid information was written to it. An unprivileged
local user could use this to cause a denial of service on the system.
(CVE-2011-3619)

A flaw was found in the Linux kernel's /proc/*/*map* interface. A
local, unprivileged user could exploit this flaw to cause a denial of
service. (CVE-2011-3637)

Scot Doyle discovered that the bridge networking interface incorrectly
handled certain network packets. A remote attacker could exploit this
to crash the system, leading to a denial of service. (CVE-2011-4087)

A bug was found in the way headroom check was performed in
udp6_ufo_fragment() function. A remote attacker could use this flaw to
crash the system. (CVE-2011-4326)

Ben Hutchings discovered several flaws in the Linux Rose (X.25 PLP)
layer. A local user or a remote user on an X.25 network could exploit
these flaws to execute arbitrary code as root. (CVE-2011-4914).

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
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.38-12-generic", pkgver:"2.6.38-12.51~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.38-12-generic-pae", pkgver:"2.6.38-12.51~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.38-12-server", pkgver:"2.6.38-12.51~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.38-12-virtual", pkgver:"2.6.38-12.51~lucid1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-generic / linux-image-2.6-generic-pae / etc");
}
