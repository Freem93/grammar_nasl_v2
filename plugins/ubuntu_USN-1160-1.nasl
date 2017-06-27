#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1160-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55454);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/26 14:05:57 $");

  script_cve_id("CVE-2010-4529", "CVE-2010-4565", "CVE-2010-4656", "CVE-2011-0463", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-0726", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1017", "CVE-2011-1019", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1082", "CVE-2011-1083", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1169", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1478", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1593", "CVE-2011-1745", "CVE-2011-1748", "CVE-2011-2022", "CVE-2011-2534", "CVE-2011-3359", "CVE-2011-4611", "CVE-2011-4913");
  script_bugtraq_id(44661, 45556, 45986, 46069, 46417, 46419, 46492, 46512, 46839, 47116, 47791);
  script_xref(name:"USN", value:"1160-1");

  script_name(english:"Ubuntu 10.10 : linux vulnerabilities (USN-1160-1)");
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
"Dan Rosenberg discovered that IRDA did not correctly check the size of
buffers. On non-x86 systems, a local attacker could exploit this to
read kernel heap memory, leading to a loss of privacy. (CVE-2010-4529)

Dan Rosenburg discovered that the CAN subsystem leaked kernel
addresses into the /proc filesystem. A local attacker could use this
to increase the chances of a successful memory corruption exploit.
(CVE-2010-4565)

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
specially crafted requests to crash the system, leading to a denial of
service. (CVE-2011-0695)

Dan Rosenberg discovered that XFS did not correctly initialize memory.
A local attacker could make crafted ioctl calls to leak portions of
kernel stack memory, leading to a loss of privacy. (CVE-2011-0711)

Rafael Dominguez Vega discovered that the caiaq Native Instruments USB
driver did not correctly validate string lengths. A local attacker
with physical access could plug in a specially crafted USB device to
crash the system or potentially gain root privileges. (CVE-2011-0712)

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

Nelson Elhage discovered that the epoll subsystem did not correctly
handle certain structures. A local attacker could create malicious
requests that would hang the system, leading to a denial of service.
(CVE-2011-1082)

Johan Hovold discovered that the DCCP network stack did not correctly
handle certain packet combinations. A remote attacker could send
specially crafted network traffic that would crash the system, leading
to a denial of service. (CVE-2011-1093)

Peter Huewe discovered that the TPM device did not correctly
initialize memory. A local attacker could exploit this to read kernel
heap memory contents, leading to a loss of privacy. (CVE-2011-1160)

Dan Rosenberg discovered that some ALSA drivers did not correctly
check the adapter index during ioctl calls. If this driver was loaded,
a local attacker could make a specially crafted ioctl call to gain
root privileges. (CVE-2011-1169)

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

Tavis Ormandy discovered that the pidmap function did not correctly
handle large requests. A local attacker could exploit this to crash
the system, leading to a denial of service. (CVE-2011-1593)

Vasiliy Kulikov discovered that the AGP driver did not check certain
ioctl values. A local attacker with access to the video subsystem
could exploit this to crash the system, leading to a denial of
service, or possibly gain root privileges. (CVE-2011-1745,
CVE-2011-2022)

Oliver Hartkopp and Dave Jones discovered that the CAN network driver
did not correctly validate certain socket structures. If this driver
was loaded, a local attacker could crash the system, leading to a
denial of service. (CVE-2011-1748)

A flaw was found in the b43 driver in the Linux kernel. An attacker
could use this flaw to cause a denial of service if the system has an
active wireless interface using the b43 driver. (CVE-2011-3359)

Maynard Johnson discovered that on POWER7, certain speculative events
may raise a performance monitor exception. A local attacker could
exploit this to crash the system, leading to a denial of service.
(CVE-2011-4611)

Dan Rosenberg discovered flaws in the linux Rose (X.25 PLP) layer used
by amateur radio. A local user or a remote user on an X.25 network
could exploit these flaws to execute arbitrary code as root.
(CVE-2011-4913).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/29");
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
if (! ereg(pattern:"^(10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-30-generic", pkgver:"2.6.35-30.54")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-30-generic-pae", pkgver:"2.6.35-30.54")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-30-server", pkgver:"2.6.35-30.54")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-30-versatile", pkgver:"2.6.35-30.54")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-30-virtual", pkgver:"2.6.35-30.54")) flag++;

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
