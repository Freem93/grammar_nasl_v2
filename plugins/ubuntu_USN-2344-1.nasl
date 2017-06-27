#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2344-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77602);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/24 17:37:06 $");

  script_cve_id("CVE-2014-3587", "CVE-2014-3597");
  script_bugtraq_id(69322, 69325);
  script_osvdb_id(79681, 110250, 110251);
  script_xref(name:"USN", value:"2344-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 14.04 LTS : php5 vulnerabilities (USN-2344-1)");
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
"It was discovered that the Fileinfo component in php5 contains an
integer overflow. An attacker could use this flaw to cause a denial of
service or possibly execute arbitrary code via a crafted CDF file.
(CVE-2014-3587)

It was discovered that the php_parserr function contains multiple
buffer overflows. An attacker could use this flaw to cause a denial of
service or possibly execute arbitrary code via crafted DNS records.
(CVE-2014-3597).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/10");
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
if (! ereg(pattern:"^(10\.04|12\.04|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.2-1ubuntu4.27")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5", pkgver:"5.3.2-1ubuntu4.27")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cgi", pkgver:"5.3.2-1ubuntu4.27")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.10-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5", pkgver:"5.3.10-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cgi", pkgver:"5.3.10-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-fpm", pkgver:"5.3.10-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libapache2-mod-php5", pkgver:"5.5.9+dfsg-1ubuntu4.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5", pkgver:"5.5.9+dfsg-1ubuntu4.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cgi", pkgver:"5.5.9+dfsg-1ubuntu4.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-fpm", pkgver:"5.5.9+dfsg-1ubuntu4.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / php5 / php5-cgi / php5-fpm");
}
