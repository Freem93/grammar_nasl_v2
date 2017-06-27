#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-66-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20685);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/25 16:34:55 $");

  script_xref(name:"USN", value:"66-1");

  script_name(english:"Ubuntu 4.10 : php4 vulnerabilities (USN-66-1)");
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
"FraMe from kernelpanik.org reported that the cURL module does not
respect open_basedir restrictions. As a result, scripts which used
cURL to open files with an user-specified path could read arbitrary
local files outside of the open_basedir directory.

Stefano Di Paola discovered a vulnerability in PHP's shmop_write()
function. Its 'offset' parameter was not checked for negative values,
which allowed an attacker to write arbitrary data to arbitrary memory
locations. A script which passed unchecked parameters to shmop_write()
could possibly be exploited to execute arbitrary code with the
privileges of the web server and to bypass safe mode restrictions.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-domxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-mcal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-mhash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-xslt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/20");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libapache2-mod-php4", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-cgi", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-curl", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-dev", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-domxml", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-gd", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-ldap", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mcal", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mhash", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mysql", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-odbc", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-pear", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-recode", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-snmp", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-sybase", pkgver:"4.3.8-3ubuntu7.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-xslt", pkgver:"4.3.8-3ubuntu7.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php4 / php4 / php4-cgi / php4-curl / php4-dev / etc");
}
