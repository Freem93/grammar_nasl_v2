#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-132-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20523);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2005-1275");
  script_xref(name:"USN", value:"132-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : imagemagick vulnerabilities (USN-132-1)");
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
"Damian Put discovered a buffer overflow in the PNM image decoder.
Processing a specially crafted PNM file with a small 'colors' value
resulted in a crash of the application that used the ImageMagick
library. (CAN-2005-1275)

Another Denial of Service vulnerability was found in the XWD decoder.
Specially crafted invalid color masks resulted in an infinite loop
which caused the application using the ImageMagick library to stop
working and use all available CPU resources.
(http://bugs.gentoo.org/show_bug.cgi?id=90423)

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"imagemagick", pkgver:"6.0.2.5-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libmagick++6", pkgver:"6.0.2.5-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libmagick++6-dev", pkgver:"6.0.2.5-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libmagick6", pkgver:"6.0.2.5-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libmagick6-dev", pkgver:"6.0.2.5-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perlmagick", pkgver:"6.0.2.5-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"imagemagick", pkgver:"6.0.6.2-2.1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmagick++6", pkgver:"6.0.6.2-2.1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmagick++6-dev", pkgver:"6.0.6.2-2.1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmagick6", pkgver:"6.0.6.2-2.1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmagick6-dev", pkgver:"6.0.6.2-2.1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"perlmagick", pkgver:"6.0.6.2-2.1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imagemagick / libmagick++6 / libmagick++6-dev / libmagick6 / etc");
}
