#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3142-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97351);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/16 14:01:52 $");

  script_osvdb_id(144990, 144991, 145389, 146022, 147474, 151088, 151089, 151090, 151091, 151092, 151093, 151094, 151095, 151096, 151097, 151098, 151099, 151100, 151103, 151104, 151105, 151106, 151107, 151108, 151109, 151110, 151111, 151112, 151113, 151114, 151115, 151116, 151117, 151119, 151120, 151121, 151122, 151123, 151124, 151125, 151126, 151128, 151129, 151130, 151131, 151132);
  script_xref(name:"USN", value:"3142-2");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : imagemagick regression (USN-3142-2)");
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
"USN-3142-1 fixed vulnerabilities in ImageMagick. The security fixes
introduced a regression with text labels and a regression with the
text coder. This update fixes the problem.

We apologize for the inconvenience.

It was discovered that ImageMagick incorrectly handled certain
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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/23");
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

if (ubuntu_check(osver:"12.04", pkgname:"imagemagick", pkgver:"8:6.6.9.7-5ubuntu3.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libmagick++4", pkgver:"8:6.6.9.7-5ubuntu3.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libmagickcore4", pkgver:"8:6.6.9.7-5ubuntu3.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libmagickcore4-extra", pkgver:"8:6.6.9.7-5ubuntu3.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"imagemagick", pkgver:"8:6.7.7.10-6ubuntu3.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagick++5", pkgver:"8:6.7.7.10-6ubuntu3.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagickcore5", pkgver:"8:6.7.7.10-6ubuntu3.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagickcore5-extra", pkgver:"8:6.7.7.10-6ubuntu3.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"imagemagick", pkgver:"8:6.8.9.9-7ubuntu5.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"imagemagick-6.q16", pkgver:"8:6.8.9.9-7ubuntu5.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagick++-6.q16-5v5", pkgver:"8:6.8.9.9-7ubuntu5.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagickcore-6.q16-2", pkgver:"8:6.8.9.9-7ubuntu5.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagickcore-6.q16-2-extra", pkgver:"8:6.8.9.9-7ubuntu5.4")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"imagemagick", pkgver:"8:6.8.9.9-7ubuntu8.3")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"imagemagick-6.q16", pkgver:"8:6.8.9.9-7ubuntu8.3")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libmagick++-6.q16-5v5", pkgver:"8:6.8.9.9-7ubuntu8.3")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libmagickcore-6.q16-2", pkgver:"8:6.8.9.9-7ubuntu8.3")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libmagickcore-6.q16-2-extra", pkgver:"8:6.8.9.9-7ubuntu8.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imagemagick / imagemagick-6.q16 / libmagick++-6.q16-5v5 / etc");
}
