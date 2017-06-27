#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1167-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55591);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/10/26 14:05:57 $");

  script_cve_id("CVE-2010-3859", "CVE-2010-3874", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-4158", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4164", "CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4175", "CVE-2010-4243", "CVE-2010-4248", "CVE-2010-4249", "CVE-2010-4250", "CVE-2010-4256", "CVE-2010-4258", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4527", "CVE-2010-4529", "CVE-2010-4565", "CVE-2010-4649", "CVE-2010-4668", "CVE-2011-0463", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-0726", "CVE-2011-0999", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1017", "CVE-2011-1019", "CVE-2011-1044", "CVE-2011-1076", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1082", "CVE-2011-1083", "CVE-2011-1090", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1169", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1479", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1747", "CVE-2011-1748", "CVE-2011-1759", "CVE-2011-1770", "CVE-2011-1771", "CVE-2011-1776", "CVE-2011-1927", "CVE-2011-2022", "CVE-2011-2479", "CVE-2011-2496", "CVE-2011-2498", "CVE-2011-2534", "CVE-2011-3359", "CVE-2011-3363", "CVE-2011-4913");
  script_bugtraq_id(44354, 44630, 44661, 44665, 44758, 44793, 44830, 44861, 44921, 45004, 45028, 45037, 45055, 45125, 45159, 45321, 45323, 45556, 45629, 45660, 45986, 46073, 46417, 46419, 46442, 46488, 46492, 46557, 46732, 46839, 47116, 47639, 47791, 47792);
  script_xref(name:"USN", value:"1167-1");

  script_name(english:"Ubuntu 11.04 : linux vulnerabilities (USN-1167-1)");
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
"Aristide Fattori and Roberto Paleari reported a flaw in the Linux
kernel's handling of IPv4 icmp packets. A remote user could exploit
this to cause a denial of service. (CVE-2011-1927)

Goldwyn Rodrigues discovered that the OCFS2 filesystem did not
correctly clear memory when writing certain file holes. A local
attacker could exploit this to read uninitialized data from the disk,
leading to a loss of privacy. (CVE-2011-0463)

Timo Warns discovered that the LDM disk partition handling code did
not correctly handle certain values. By inserting a specially crafted
disk device, a local attacker could exploit this to gain root
privileges. (CVE-2011-1017)

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

Dan Rosenberg reported errors in the OSS (Open Sound System) MIDI
interface. A local attacker on non-x86 systems might be able to cause
a denial of service. (CVE-2011-1476)

Dan Rosenberg reported errors in the kernel's OSS (Open Sound System)
driver for Yamaha FM synthesizer chips. A local user can exploit this
to cause memory corruption, causing a denial of service or privilege
escalation. (CVE-2011-1477)

It was discovered that the security fix for CVE-2010-4250 introduced a
regression. A remote attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-1479)

Dan Rosenberg discovered that MPT devices did not correctly validate
certain values in ioctl calls. If these drivers were loaded, a local
attacker could exploit this to read arbitrary kernel memory, leading
to a loss of privacy. (CVE-2011-1494, CVE-2011-1495)

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

Ben Greear discovered that CIFS did not correctly handle direct I/O. A
local attacker with access to a CIFS partition could exploit this to
crash the system, leading to a denial of service. (CVE-2011-1771)

Timo Warns discovered that the EFI GUID partition table was not
correctly parsed. A physically local attacker that could insert
mountable devices could exploit this to crash the system or possibly
gain root privileges. (CVE-2011-1776)

It was discovered that an mmap() call with the MAP_PRIVATE flag on
'/dev/zero' was incorrectly handled. A local attacker could exploit
this to crash the system, leading to a denial of service.
(CVE-2011-2479)

Robert Swiecki discovered that mapping extensions were incorrectly
handled. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-2496)

The linux kernel did not properly account for PTE pages when deciding
which task to kill in out of memory conditions. A local, unprivileged
could exploit this flaw to cause a denial of service. (CVE-2011-2498)

A flaw was found in the b43 driver in the Linux kernel. An attacker
could use this flaw to cause a denial of service if the system has an
active wireless interface using the b43 driver. (CVE-2011-3359)

Yogesh Sharma discovered that CIFS did not correctly handle UNCs that
had no prefixpaths. A local attacker with access to a CIFS partition
could exploit this to crash the system, leading to a denial of
service. (CVE-2011-3363)

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
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/14");
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
if (! ereg(pattern:"^(11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-10-generic", pkgver:"2.6.38-10.46")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-10-generic-pae", pkgver:"2.6.38-10.46")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-10-server", pkgver:"2.6.38-10.46")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-10-versatile", pkgver:"2.6.38-10.46")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-10-virtual", pkgver:"2.6.38-10.46")) flag++;

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
