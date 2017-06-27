#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1219-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56344);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/26 14:05:57 $");

  script_cve_id("CVE-2011-1576", "CVE-2011-1776", "CVE-2011-1833", "CVE-2011-2213", "CVE-2011-2497", "CVE-2011-2699", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2918", "CVE-2011-2928", "CVE-2011-3191", "CVE-2011-3593");
  script_bugtraq_id(47796, 48472, 48802, 48907, 49108, 49256, 49295);
  script_xref(name:"USN", value:"1219-1");

  script_name(english:"Ubuntu 10.04 LTS : linux-lts-backport-maverick vulnerabilities (USN-1219-1)");
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
"Ryan Sweat discovered that the kernel incorrectly handled certain VLAN
packets. On some systems, a remote attacker could send specially
crafted traffic to crash the system, leading to a denial of service.
(CVE-2011-1576)

Timo Warns discovered that the EFI GUID partition table was not
correctly parsed. A physically local attacker that could insert
mountable devices could exploit this to crash the system or possibly
gain root privileges. (CVE-2011-1776)

Vasiliy Kulikov and Dan Rosenberg discovered that ecryptfs did not
correctly check the origin of mount points. A local attacker could
exploit this to trick the system into unmounting arbitrary mount
points, leading to a denial of service. (CVE-2011-1833)

Dan Rosenberg discovered that the IPv4 diagnostic routines did not
correctly validate certain requests. A local attacker could exploit
this to consume CPU resources, leading to a denial of service.
(CVE-2011-2213)

Dan Rosenberg discovered that the Bluetooth stack incorrectly handled
certain L2CAP requests. If a system was using Bluetooth, a remote
attacker could send specially crafted traffic to crash the system or
gain root privileges. (CVE-2011-2497)

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

Darren Lavender discovered that the CIFS client incorrectly handled
certain large values. A remote attacker with a malicious server could
exploit this to crash the system or possibly execute arbitrary code as
the root user. (CVE-2011-3191)

Gideon Naim discovered a flaw in the Linux kernel's handling VLAN 0
frames. An attacker on the local network could exploit this flaw to
cause a denial of service. (CVE-2011-3593).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/30");
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

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.35-30-generic", pkgver:"2.6.35-30.60~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.35-30-generic-pae", pkgver:"2.6.35-30.60~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.35-30-server", pkgver:"2.6.35-30.60~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.35-30-virtual", pkgver:"2.6.35-30.60~lucid1")) flag++;

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
