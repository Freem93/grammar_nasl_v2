#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-762-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37762);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:37:18 $");

  script_cve_id("CVE-2009-1300");
  script_xref(name:"USN", value:"762-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 : apt vulnerabilities (USN-762-1)");
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
"Alexandre Martani discovered that the APT daily cron script did not
check the return code of the date command. If a machine is configured
for automatic updates and is in a time zone where DST occurs at
midnight, under certain circumstances automatic updates might not be
applied and could become permanently disabled. (CVE-2009-1300)

Michael Casadevall discovered that APT did not properly verify
repositories signed with a revoked or expired key. If a repository
were signed with only an expired or revoked key and the signature was
otherwise valid, APT would consider the repository valid.
(https://launchpad.net/bugs/356012)

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apt-transport-https");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apt-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapt-pkg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapt-pkg-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"apt", pkgver:"0.6.43.3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apt-doc", pkgver:"0.6.43.3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apt-utils", pkgver:"0.6.43.3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libapt-pkg-dev", pkgver:"0.6.43.3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libapt-pkg-doc", pkgver:"0.6.43.3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apt", pkgver:"0.7.9ubuntu17.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apt-doc", pkgver:"0.7.9ubuntu17.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apt-transport-https", pkgver:"0.7.9ubuntu17.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apt-utils", pkgver:"0.7.9ubuntu17.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libapt-pkg-dev", pkgver:"0.7.9ubuntu17.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libapt-pkg-doc", pkgver:"0.7.9ubuntu17.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apt", pkgver:"0.7.14ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apt-doc", pkgver:"0.7.14ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apt-transport-https", pkgver:"0.7.14ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apt-utils", pkgver:"0.7.14ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libapt-pkg-dev", pkgver:"0.7.14ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libapt-pkg-doc", pkgver:"0.7.14ubuntu6.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apt / apt-doc / apt-transport-https / apt-utils / libapt-pkg-dev / etc");
}
