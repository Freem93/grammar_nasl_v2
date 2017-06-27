#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1028-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51075);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2010-4167");
  script_bugtraq_id(45044);
  script_osvdb_id(69445);
  script_xref(name:"USN", value:"1028-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : imagemagick vulnerability (USN-1028-1)");
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
"It was discovered that ImageMagick would search for configuration
files in the current directory. If a user were tricked into opening or
processing an image in an arbitrary directory, a local attacker could
execute arbitrary code with the user's privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"imagemagick", pkgver:"7:6.3.7.9.dfsg1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmagick++10", pkgver:"6.3.7.9.dfsg1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmagick++9-dev", pkgver:"6.3.7.9.dfsg1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmagick10", pkgver:"6.3.7.9.dfsg1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmagick9-dev", pkgver:"6.3.7.9.dfsg1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"perlmagick", pkgver:"6.3.7.9.dfsg1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"imagemagick", pkgver:"7:6.5.1.0-1.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"imagemagick-dbg", pkgver:"6.5.1.0-1.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"imagemagick-doc", pkgver:"6.5.1.0-1.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmagick++-dev", pkgver:"6.5.1.0-1.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmagick++2", pkgver:"6.5.1.0-1.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmagickcore-dev", pkgver:"6.5.1.0-1.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmagickcore2", pkgver:"6.5.1.0-1.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmagickwand-dev", pkgver:"6.5.1.0-1.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmagickwand2", pkgver:"6.5.1.0-1.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"perlmagick", pkgver:"6.5.1.0-1.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"imagemagick", pkgver:"7:6.5.7.8-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"imagemagick-dbg", pkgver:"6.5.7.8-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"imagemagick-doc", pkgver:"6.5.7.8-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmagick++-dev", pkgver:"6.5.7.8-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmagick++2", pkgver:"6.5.7.8-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmagickcore-dev", pkgver:"6.5.7.8-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmagickcore2", pkgver:"6.5.7.8-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmagickcore2-extra", pkgver:"6.5.7.8-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmagickwand-dev", pkgver:"6.5.7.8-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmagickwand2", pkgver:"6.5.7.8-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"perlmagick", pkgver:"6.5.7.8-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"imagemagick", pkgver:"7:6.6.2.6-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"imagemagick-dbg", pkgver:"6.6.2.6-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"imagemagick-doc", pkgver:"6.6.2.6-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libmagick++-dev", pkgver:"6.6.2.6-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libmagick++3", pkgver:"6.6.2.6-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libmagickcore-dev", pkgver:"6.6.2.6-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libmagickcore3", pkgver:"6.6.2.6-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libmagickcore3-extra", pkgver:"6.6.2.6-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libmagickwand-dev", pkgver:"6.6.2.6-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libmagickwand3", pkgver:"6.6.2.6-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"perlmagick", pkgver:"6.6.2.6-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imagemagick / imagemagick-dbg / imagemagick-doc / libmagick++-dev / etc");
}
