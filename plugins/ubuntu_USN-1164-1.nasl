# This script was automatically generated from Ubuntu Security
# Notice USN-1164-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(55530);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

  script_cve_id("CVE-2010-3865", "CVE-2010-3874", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4164", "CVE-2010-4248", "CVE-2010-4258", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4527", "CVE-2010-4529", "CVE-2010-4565", "CVE-2010-4655", "CVE-2010-4656", "CVE-2011-0463", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-1017", "CVE-2011-1182", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1593", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1747", "CVE-2011-1748", "CVE-2011-2022");
  script_xref(name:"USN", value:"1164-1");

  script_name(english:"USN-1164-1 : linux-fsl-imx51 vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Thomas Pollet discovered that the RDS network protocol did not check
certain iovec buffers. A local attacker could exploit this to crash
the system or possibly execute arbitrary code as the root user.
(CVE-2010-3865)

Dan Rosenberg discovered that the CAN protocol on 64bit systems did
not correctly calculate the size of certain buffers. A local attacker
could exploit this to crash the system or possibly execute arbitrary
code as the root user. (CVE-2010-3874)

Vasiliy Kulikov discovered that the Linux kernel X.25 implementation
did not correctly clear kernel memory. A local attacker could exploit
this to read kernel stack memory, leading to a loss of privacy.
(CVE-2010-3875)

Vasiliy Kulikov discovered that the Linux kernel sockets
implementation did not properly initialize certain structures. A
local attacker could exploit this to read kernel stack memory,
leading to a loss of privacy. (CVE-2010-3876)

Vasiliy Kulikov discovered that the TIPC interface did not correctly
initialize certain structures. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-3877)

Nelson Elhage discovered that the Linux kernel IPv4 implementation
did not properly audit certain bytecodes in netlink messages. A local
attacker could exploit this to cause the kernel to hang, leading to a
denial of service. (CVE-2010-3880)

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

Dan Rosenberg discovered multiple flaws in the X.25 facilities
parsing. If a system was using X.25, a remote attacker could exploit
this to crash the system, leading to a denial of service.
(CVE-2010-4164)

It was discovered that multithreaded exec did not handle CPU timers
correctly. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-4248)

Nelson Elhage discovered that the kernel did not correctly handle
process cleanup after triggering a recoverable kernel bug. If a local
attacker were able to trigger certain kinds of kernel bugs, they
could create a specially crafted process to gain root privileges.
(CVE-2010-4258)

Nelson Elhage discovered that Econet did not correctly handle AUN
packets over UDP. A local attacker could send specially crafted
traffic to crash the system, leading to a denial of service.
(CVE-2010-4342)

Tavis Ormandy discovered that the install_special_mapping function
could bypass the mmap_min_addr restriction. A local attacker could
exploit this to mmap 4096 bytes below the mmap_min_addr area,
possibly improving the chances of performing NULL pointer dereference
attacks. (CVE-2010-4346)

Dan Rosenberg discovered that the OSS subsystem did not handle name
termination correctly. A local attacker could exploit this crash the
system or gain root privileges. (CVE-2010-4527)

Dan Rosenberg discovered that IRDA did not correctly check the size
of buffers. On non-x86 systems, a local attacker could exploit this
to read kernel heap memory, leading to a loss of privacy.
(CVE-2010-4529)

Dan Rosenburg discovered that the CAN subsystem leaked kernel
addresses into the /proc filesystem. A local attacker could use this
to increase the chances of a successful memory corruption exploit.
(CVE-2010-4565)

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

Timo Warns discovered that the LDM disk partition handling code did
not correctly handle certain values. By inserting a specially crafted
disk device, a local attacker could exploit this to gain root
privileges. (CVE-2011-1017)

Julien Tinnes discovered that the kernel did not correctly validate
the signal structure from tkill(). A local attacker could exploit
this to send signals to arbitrary threads, possibly bypassing
expected restrictions. (CVE-2011-1182)

Dan Rosenberg discovered that MPT devices did not correctly validate
certain values in ioctl calls. If these drivers were loaded, a local
attacker could exploit this to read arbitrary kernel memory, leading
to a loss of privacy. (CVE-2011-1494, CVE-2011-1495)

Tavis Ormandy discovered that the pidmap function did not correctly
handle large requests. A local attacker could exploit this to crash
the system, leading to a denial of service. (CVE-2011-1593)

Vasiliy Kulikov discovered that the AGP driver did not check certain
ioctl values. A local attacker with access to the video subsystem
could exploit this to crash the system, leading to a denial of
service, or possibly gain root privileges. (CVE-2011-1745,
CVE-2011-2022)

Vasiliy Kulikov discovered that the AGP driver did not check the size
of certain memory allocations. A local attacker with access to the
video subsystem could exploit this to run the system out of memory,
leading to a denial of service. (CVE-2011-1746, CVE-2011-1747)

Oliver Hartkopp and Dave Jones discovered that the CAN network driver
did not correctly validate certain socket structures. If this driver
was loaded, a local attacker could crash the system, leading to a
denial of service. (CVE-2011-1748)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1164-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/06");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2011/07/07");
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

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.31-609-imx51", pkgver:"2.6.31-609.26")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
