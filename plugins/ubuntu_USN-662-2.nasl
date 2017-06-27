#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-662-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37161);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/10/26 14:35:56 $");

  script_cve_id("CVE-2008-4395");
  script_xref(name:"USN", value:"662-2");

  script_name(english:"Ubuntu 7.10 / 8.04 LTS : linux-ubuntu-modules-2.6.22/24 vulnerability (USN-662-2)");
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
"USN-662-1 fixed vulnerabilities in ndiswrapper in Ubuntu 8.10. This
update provides the corresponding updates for Ubuntu 8.04 and 7.10.

Anders Kaseorg discovered that ndiswrapper did not correctly handle
long ESSIDs. For a system using ndiswrapper, a physically near-by
attacker could generate specially crafted wireless network traffic and
execute arbitrary code with root privileges. (CVE-2008-4395).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-386", pkgver:"2.6.22-15.40")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-generic", pkgver:"2.6.22-15.40")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-rt", pkgver:"2.6.22-15.40")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-server", pkgver:"2.6.22-15.40")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-ume", pkgver:"2.6.22-15.40")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-virtual", pkgver:"2.6.22-15.40")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-xen", pkgver:"2.6.22-15.40")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-21-386", pkgver:"2.6.24-21.33")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-21-generic", pkgver:"2.6.24-21.33")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-21-openvz", pkgver:"2.6.24-21.33")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-21-rt", pkgver:"2.6.24-21.33")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-21-server", pkgver:"2.6.24-21.33")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-21-virtual", pkgver:"2.6.24-21.33")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-21-xen", pkgver:"2.6.24-21.33")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-21-386", pkgver:"2.6.24-21.33")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-21-generic", pkgver:"2.6.24-21.33")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-21-openvz", pkgver:"2.6.24-21.33")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-21-rt", pkgver:"2.6.24-21.33")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-21-server", pkgver:"2.6.24-21.33")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-21-virtual", pkgver:"2.6.24-21.33")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-21-xen", pkgver:"2.6.24-21.33")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-headers-lum-2.6-386 / linux-headers-lum-2.6-generic / etc");
}
