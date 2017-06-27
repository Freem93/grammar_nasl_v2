#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2133-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72897);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/26 14:16:26 $");

  script_cve_id("CVE-2013-4579", "CVE-2013-6368", "CVE-2014-1438", "CVE-2014-1446", "CVE-2014-1874");
  script_xref(name:"USN", value:"2133-1");

  script_name(english:"Ubuntu 12.04 LTS : linux vulnerabilities (USN-2133-1)");
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
"Mathy Vanhoef discovered an error in the the way the ath9k driver was
handling the BSSID masking. A remote attacker could exploit this error
to discover the original MAC address after a spoofing atack.
(CVE-2013-4579)

Andrew Honig reported an error in the Linux Kernel's Kernel Virtual
Machine (KVM) VAPIC synchronization operation. A local user could
exploit this flaw to gain privileges or cause a denial of service
(system crash). (CVE-2013-6368)

halfdog reported an error in the AMD K7 and K8 platform support in the
Linux kernel. An unprivileged local user could exploit this flaw on
AMD based systems to cause a denial of service (task kill) or possibly
gain privileges via a crafted application. (CVE-2014-1438)

An information leak was discovered in the Linux kernel's hamradio YAM
driver for AX.25 packet radio. A local user with the CAP_NET_ADMIN
capability could exploit this flaw to obtain sensitive information
from kernel memory. (CVE-2014-1446)

Matthew Thode reported a denial of service vulnerability in the Linux
kernel when SELinux support is enabled. A local user with the
CAP_MAC_ADMIN capability (and the SELinux mac_admin permission if
running in enforcing mode) could exploit this flaw to cause a denial
of service (kernel crash). (CVE-2014-1874).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-60-generic", pkgver:"3.2.0-60.91")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-60-generic-pae", pkgver:"3.2.0-60.91")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-60-highbank", pkgver:"3.2.0-60.91")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-60-virtual", pkgver:"3.2.0-60.91")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.2-generic / linux-image-3.2-generic-pae / etc");
}
