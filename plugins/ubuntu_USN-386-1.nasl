#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-386-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27969);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_cve_id("CVE-2006-4144", "CVE-2006-5868");
  script_osvdb_id(27951);
  script_xref(name:"USN", value:"386-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS : imagemagick vulnerability (USN-386-1)");
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
"Daniel Kobras discovered multiple buffer overflows in ImageMagick's
SGI file format decoder. By tricking a user or an automated system
into processing a specially crafted SGI image, this could be exploited
to execute arbitrary code with the user's privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++6c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++9c2a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.10|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"imagemagick", pkgver:"6.2.3.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagick++6-dev", pkgver:"6.2.3.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagick++6c2", pkgver:"6.2.3.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagick6", pkgver:"6:6.2.3.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagick6-dev", pkgver:"6.2.3.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"perlmagick", pkgver:"6.2.3.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"imagemagick", pkgver:"6.2.4.5-0.6ubuntu0.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmagick++9-dev", pkgver:"6.2.4.5-0.6ubuntu0.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmagick++9c2a", pkgver:"6.2.4.5-0.6ubuntu0.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmagick9", pkgver:"6:6.2.4.5-0.6ubuntu0.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmagick9-dev", pkgver:"6.2.4.5-0.6ubuntu0.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"perlmagick", pkgver:"6.2.4.5-0.6ubuntu0.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imagemagick / libmagick++6-dev / libmagick++6c2 / libmagick++9-dev / etc");
}
