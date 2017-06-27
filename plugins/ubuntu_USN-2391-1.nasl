#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2391-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78761);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/24 17:37:07 $");

  script_cve_id("CVE-2014-3668", "CVE-2014-3669", "CVE-2014-3670", "CVE-2014-3710");
  script_osvdb_id(113421, 113422, 113423, 113614);
  script_xref(name:"USN", value:"2391-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 14.04 LTS / 14.10 : php5 vulnerabilities (USN-2391-1)");
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
"Symeon Paraschoudis discovered that PHP incorrectly handled the
mkgmtime function. A remote attacker could possibly use this issue to
cause PHP to crash, resulting in a denial of service. (CVE-2014-3668)

Symeon Paraschoudis discovered that PHP incorrectly handled
unserializing objects. A remote attacker could possibly use this issue
to cause PHP to crash, resulting in a denial of service.
(CVE-2014-3669)

Otto Ebeling discovered that PHP incorrectly handled the
exif_thumbnail function. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2014-3670)

Francisco Alonso that PHP incorrectly handled ELF files in the
fileinfo extension. A remote attacker could possibly use this issue to
cause PHP to crash, resulting in a denial of service. (CVE-2014-3710)

It was discovered that PHP incorrectly handled NULL bytes when
processing certain URLs with the curl functions. A remote attacker
could possibly use this issue to bypass filename restrictions and
obtain access to sensitive files. (No CVE number).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|12\.04|14\.04|14\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 14.04 / 14.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.2-1ubuntu4.28")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cgi", pkgver:"5.3.2-1ubuntu4.28")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cli", pkgver:"5.3.2-1ubuntu4.28")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-curl", pkgver:"5.3.2-1ubuntu4.28")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-xmlrpc", pkgver:"5.3.2-1ubuntu4.28")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.10-1ubuntu3.15")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cgi", pkgver:"5.3.10-1ubuntu3.15")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cli", pkgver:"5.3.10-1ubuntu3.15")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-curl", pkgver:"5.3.10-1ubuntu3.15")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-fpm", pkgver:"5.3.10-1ubuntu3.15")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-xmlrpc", pkgver:"5.3.10-1ubuntu3.15")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libapache2-mod-php5", pkgver:"5.5.9+dfsg-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cgi", pkgver:"5.5.9+dfsg-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cli", pkgver:"5.5.9+dfsg-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-curl", pkgver:"5.5.9+dfsg-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-fpm", pkgver:"5.5.9+dfsg-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-xmlrpc", pkgver:"5.5.9+dfsg-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"libapache2-mod-php5", pkgver:"5.5.12+dfsg-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-cgi", pkgver:"5.5.12+dfsg-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-cli", pkgver:"5.5.12+dfsg-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-curl", pkgver:"5.5.12+dfsg-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-fpm", pkgver:"5.5.12+dfsg-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-xmlrpc", pkgver:"5.5.12+dfsg-2ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / php5-cgi / php5-cli / php5-curl / php5-fpm / etc");
}
