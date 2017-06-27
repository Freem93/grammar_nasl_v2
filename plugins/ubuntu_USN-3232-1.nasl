#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3232-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97753);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:43 $");

  script_cve_id("CVE-2017-6498", "CVE-2017-6499", "CVE-2017-6500");
  script_osvdb_id(151765, 152955, 152960);
  script_xref(name:"USN", value:"3232-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : imagemagick vulnerabilities (USN-3232-1)");
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
"It was discovered that ImageMagick incorrectly handled certain
malformed image files. If a user or automated system using ImageMagick
were tricked into opening a specially crafted image, an attacker could
exploit this to cause a denial of service or possibly execute code
with the privileges of the user invoking the program.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-5v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore4-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore5-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"imagemagick", pkgver:"8:6.6.9.7-5ubuntu3.9")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libmagick++4", pkgver:"8:6.6.9.7-5ubuntu3.9")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libmagickcore4", pkgver:"8:6.6.9.7-5ubuntu3.9")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libmagickcore4-extra", pkgver:"8:6.6.9.7-5ubuntu3.9")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"imagemagick", pkgver:"8:6.7.7.10-6ubuntu3.6")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagick++5", pkgver:"8:6.7.7.10-6ubuntu3.6")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagickcore5", pkgver:"8:6.7.7.10-6ubuntu3.6")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagickcore5-extra", pkgver:"8:6.7.7.10-6ubuntu3.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"imagemagick", pkgver:"8:6.8.9.9-7ubuntu5.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"imagemagick-6.q16", pkgver:"8:6.8.9.9-7ubuntu5.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagick++-6.q16-5v5", pkgver:"8:6.8.9.9-7ubuntu5.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagickcore-6.q16-2", pkgver:"8:6.8.9.9-7ubuntu5.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagickcore-6.q16-2-extra", pkgver:"8:6.8.9.9-7ubuntu5.6")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"imagemagick", pkgver:"8:6.8.9.9-7ubuntu8.5")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"imagemagick-6.q16", pkgver:"8:6.8.9.9-7ubuntu8.5")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libmagick++-6.q16-5v5", pkgver:"8:6.8.9.9-7ubuntu8.5")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libmagickcore-6.q16-2", pkgver:"8:6.8.9.9-7ubuntu8.5")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libmagickcore-6.q16-2-extra", pkgver:"8:6.8.9.9-7ubuntu8.5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imagemagick / imagemagick-6.q16 / libmagick++-6.q16-5v5 / etc");
}
