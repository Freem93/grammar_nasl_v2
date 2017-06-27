#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-595-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31703);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_cve_id("CVE-2007-6697", "CVE-2008-0544");
  script_osvdb_id(42374, 42375);
  script_xref(name:"USN", value:"595-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : sdl-image1.2 vulnerabilities (USN-595-1)");
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
"Michael Skladnikiewicz discovered that SDL_image did not correctly
load GIF images. If a user or automated system were tricked into
processing a specially crafted GIF, a remote attacker could execute
arbitrary code or cause a crash, leading to a denial of service.
(CVE-2007-6697)

David Raulo discovered that SDL_image did not correctly load ILBM
images. If a user or automated system were tricked into processing a
specially crafted ILBM, a remote attacker could execute arbitrary code
or cause a crash, leading to a denial of service. (CVE-2008-0544).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libsdl-image1.2 and / or libsdl-image1.2-dev
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsdl-image1.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsdl-image1.2-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libsdl-image1.2", pkgver:"1.2.4-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsdl-image1.2-dev", pkgver:"1.2.4-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libsdl-image1.2", pkgver:"1.2.5-2ubuntu0.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libsdl-image1.2-dev", pkgver:"1.2.5-2ubuntu0.6.10.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libsdl-image1.2", pkgver:"1.2.5-2ubuntu0.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libsdl-image1.2-dev", pkgver:"1.2.5-2ubuntu0.7.04.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libsdl-image1.2", pkgver:"1.2.5-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libsdl-image1.2-dev", pkgver:"1.2.5-3ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsdl-image1.2 / libsdl-image1.2-dev");
}
