#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-486-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28087);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/03/28 13:31:43 $");

  script_cve_id("CVE-2006-7203", "CVE-2007-0005", "CVE-2007-1000", "CVE-2007-1353", "CVE-2007-1861", "CVE-2007-2242", "CVE-2007-2453", "CVE-2007-2525", "CVE-2007-2875", "CVE-2007-2876", "CVE-2007-2878");
  script_bugtraq_id(23615, 23870, 24376, 24389, 24390);
  script_osvdb_id(33023, 33025, 34739, 34741, 35303, 35926, 35929, 35932, 37112, 37113, 37114, 107978);
  script_xref(name:"USN", value:"486-1");

  script_name(english:"Ubuntu 6.10 : linux-source-2.6.17 vulnerabilities (USN-486-1)");
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
"The compat_sys_mount function allowed local users to cause a denial of
service when mounting a smbfs filesystem in compatibility mode.
(CVE-2006-7203)

The Omnikey CardMan 4040 driver (cm4040_cs) did not limit the size of
buffers passed to read() and write(). A local attacker could exploit
this to execute arbitrary code with kernel privileges. (CVE-2007-0005)

Due to a variable handling flaw in the ipv6_getsockopt_sticky()
function a local attacker could exploit the getsockopt() calls to read
arbitrary kernel memory. This could disclose sensitive data.
(CVE-2007-1000)

Ilja van Sprundel discovered that Bluetooth setsockopt calls could
leak kernel memory contents via an uninitialized stack buffer. A local
attacker could exploit this flaw to view sensitive kernel information.
(CVE-2007-1353)

A flaw was discovered in the handling of netlink messages. Local
attackers could cause infinite recursion leading to a denial of
service. (CVE-2007-1861)

A flaw was discovered in the IPv6 stack's handling of type 0 route
headers. By sending a specially crafted IPv6 packet, a remote attacker
could cause a denial of service between two IPv6 hosts.
(CVE-2007-2242)

The random number generator was hashing a subset of the available
entropy, leading to slightly less random numbers. Additionally,
systems without an entropy source would be seeded with the same inputs
at boot time, leading to a repeatable series of random numbers.
(CVE-2007-2453)

A flaw was discovered in the PPP over Ethernet implementation. Local
attackers could manipulate ioctls and cause kernel memory consumption
leading to a denial of service. (CVE-2007-2525)

An integer underflow was discovered in the cpuset filesystem. If
mounted, local attackers could obtain kernel memory using large file
offsets while reading the tasks file. This could disclose sensitive
data. (CVE-2007-2875)

Vilmos Nebehaj discovered that the SCTP netfilter code did not
correctly validate certain states. A remote attacker could send a
specially crafted packet causing a denial of service. (CVE-2007-2876)

Luca Tettamanti discovered a flaw in the VFAT compat ioctls on 64-bit
systems. A local attacker could corrupt a kernel_dirent struct and
cause a denial of service. (CVE-2007-2878).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.17");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2017 Canonical, Inc. / NASL script (C) 2007-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.10", pkgname:"linux-doc-2.6.17", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-386", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-generic", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-server", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-386", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-generic", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-server", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-386", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-generic", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-server", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-kdump", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-kernel-devel", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-libc-dev", pkgver:"2.6.17.1-12.39")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-source-2.6.17", pkgver:"2.6.17.1-12.39")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.17 / linux-headers-2.6 / linux-headers-2.6-386 / etc");
}
