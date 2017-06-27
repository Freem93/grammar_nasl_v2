#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1039-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51436);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_xref(name:"USN", value:"1039-1");

  script_name(english:"Ubuntu 9.10 / 10.04 LTS / 10.10 : apparmor update (USN-1039-1)");
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
"It was discovered that if AppArmor was misconfigured, under certain
circumstances the parser could generate policy using an unconfined
fallback execute transition when one was not specified.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apparmor-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apparmor-notify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apparmor-profiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apparmor-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapparmor-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapparmor-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapparmor1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-apparmor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.10", pkgname:"apparmor", pkgver:"2.3.1+1403-0ubuntu27.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apparmor-docs", pkgver:"2.3.1+1403-0ubuntu27.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apparmor-profiles", pkgver:"2.3.1+1403-0ubuntu27.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apparmor-utils", pkgver:"2.3.1+1403-0ubuntu27.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libapache2-mod-apparmor", pkgver:"2.3.1+1403-0ubuntu27.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libapparmor-dev", pkgver:"2.3.1+1403-0ubuntu27.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libapparmor-perl", pkgver:"2.3.1+1403-0ubuntu27.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libapparmor1", pkgver:"2.3.1+1403-0ubuntu27.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpam-apparmor", pkgver:"2.3.1+1403-0ubuntu27.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apparmor", pkgver:"2.5.1-0ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apparmor-docs", pkgver:"2.5.1-0ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apparmor-notify", pkgver:"2.5.1-0ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apparmor-profiles", pkgver:"2.5.1-0ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apparmor-utils", pkgver:"2.5.1-0ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libapache2-mod-apparmor", pkgver:"2.5.1-0ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libapparmor-dev", pkgver:"2.5.1-0ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libapparmor-perl", pkgver:"2.5.1-0ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libapparmor1", pkgver:"2.5.1-0ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpam-apparmor", pkgver:"2.5.1-0ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"apparmor", pkgver:"2.5.1-0ubuntu0.10.10.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"apparmor-docs", pkgver:"2.5.1-0ubuntu0.10.10.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"apparmor-notify", pkgver:"2.5.1-0ubuntu0.10.10.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"apparmor-profiles", pkgver:"2.5.1-0ubuntu0.10.10.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"apparmor-utils", pkgver:"2.5.1-0ubuntu0.10.10.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libapache2-mod-apparmor", pkgver:"2.5.1-0ubuntu0.10.10.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libapparmor-dev", pkgver:"2.5.1-0ubuntu0.10.10.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libapparmor-perl", pkgver:"2.5.1-0ubuntu0.10.10.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libapparmor1", pkgver:"2.5.1-0ubuntu0.10.10.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libpam-apparmor", pkgver:"2.5.1-0ubuntu0.10.10.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apparmor / apparmor-docs / apparmor-notify / apparmor-profiles / etc");
}
