#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-501-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28105);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_cve_id("CVE-2007-2721");
  script_osvdb_id(36137);
  script_xref(name:"USN", value:"501-2");

  script_name(english:"Ubuntu 6.10 / 7.04 / 7.10 : ghostscript, gs-gpl vulnerability (USN-501-2)");
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
"USN-501-1 fixed vulnerabilities in Jasper. This update provides the
corresponding update for the Jasper internal to Ghostscript.

It was discovered that Jasper did not correctly handle corrupted
JPEG2000 images. By tricking a user into opening a specially crafted
JPG, a remote attacker could cause the application using libjasper to
crash, resulting in a denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-aladdin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-esp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-esp-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-gpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs-esp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.10", pkgname:"gs", pkgver:"8.50-1.1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"gs-gpl", pkgver:"8.50-1.1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"gs", pkgver:"8.54.dfsg.1-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"gs-gpl", pkgver:"8.54.dfsg.1-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ghostscript", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ghostscript-doc", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ghostscript-x", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gs", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gs-aladdin", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gs-common", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gs-esp", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gs-esp-x", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gs-gpl", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgs-dev", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgs-esp-dev", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgs8", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-doc / ghostscript-x / gs / gs-aladdin / etc");
}
