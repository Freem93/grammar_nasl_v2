#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1435-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58964);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/25 16:11:46 $");

  script_cve_id("CVE-2012-0247", "CVE-2012-0248", "CVE-2012-0259", "CVE-2012-1185", "CVE-2012-1186", "CVE-2012-1610", "CVE-2012-1798");
  script_bugtraq_id(51957, 52898);
  script_osvdb_id(79003, 79004, 80555, 80556, 81021, 81023, 81024);
  script_xref(name:"USN", value:"1435-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : imagemagick vulnerabilities (USN-1435-1)");
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
"Joonas Kuorilehto and Aleksis Kauppinen discovered that ImageMagick
incorrectly handled certain ResolutionUnit tags. If a user or
automated system using ImageMagick were tricked into opening a
specially crafted image, an attacker could exploit this to cause a
denial of service or possibly execute code with the privileges of the
user invoking the program. (CVE-2012-0247, CVE-2012-1185)

Joonas Kuorilehto and Aleksis Kauppinen discovered that ImageMagick
incorrectly handled certain IFD structures. If a user or automated
system using ImageMagick were tricked into opening a specially crafted
image, an attacker could exploit this to cause a denial of service.
(CVE-2012-0248, CVE-2012-1186)

Aleksis Kauppinen, Joonas Kuorilehto and Tuomas Parttimaa discovered
that ImageMagick incorrectly handled certain JPEG EXIF tags. If a user
or automated system using ImageMagick were tricked into opening a
specially crafted image, an attacker could exploit this to cause a
denial of service. (CVE-2012-0259)

It was discovered that ImageMagick incorrectly handled certain JPEG
EXIF tags. If a user or automated system using ImageMagick were
tricked into opening a specially crafted image, an attacker could
exploit this to cause a denial of service or possibly execute code
with the privileges of the user invoking the program. (CVE-2012-1610)

Aleksis Kauppinen, Joonas Kuorilehto and Tuomas Parttimaa discovered
that ImageMagick incorrectly handled certain TIFF EXIF tags. If a user
or automated system using ImageMagick were tricked into opening a
specially crafted image, an attacker could exploit this to cause a
denial of service or possibly execute code with the privileges of the
user invoking the program. (CVE-2012-1798).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"imagemagick", pkgver:"7:6.5.7.8-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmagick++2", pkgver:"7:6.5.7.8-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"imagemagick", pkgver:"7:6.6.2.6-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libmagick++3", pkgver:"7:6.6.2.6-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"imagemagick", pkgver:"8:6.6.0.4-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libmagick++3", pkgver:"8:6.6.0.4-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"imagemagick", pkgver:"8:6.6.9.7-5ubuntu3.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libmagick++4", pkgver:"8:6.6.9.7-5ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imagemagick / libmagick++2 / libmagick++3 / libmagick++4");
}
