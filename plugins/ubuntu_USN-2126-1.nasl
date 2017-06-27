#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2126-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72799);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/24 17:29:02 $");

  script_cve_id("CVE-2013-7226", "CVE-2013-7327", "CVE-2013-7328", "CVE-2014-1943", "CVE-2014-2020");
  script_bugtraq_id(65533, 65596, 65656, 65668, 65676);
  script_xref(name:"USN", value:"2126-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 12.10 / 13.10 : php5 vulnerabilities (USN-2126-1)");
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
"Bernd Melchers discovered that PHP's embedded libmagic library
incorrectly handled indirect offset values. An attacker could use this
issue to cause PHP to consume resources or crash, resulting in a
denial of service. (CVE-2014-1943)

It was discovered that PHP incorrectly handled certain values when
using the imagecrop function. An attacker could possibly use this
issue to cause PHP to crash, resulting in a denial of service, obtain
sensitive information, or possibly execute arbitrary code. This issue
only affected Ubuntu 13.10. (CVE-2013-7226, CVE-2013-7327,
CVE-2013-7328, CVE-2014-2020).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/04");
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
if (! ereg(pattern:"^(10\.04|12\.04|12\.10|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 12.10 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.2-1ubuntu4.23")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cgi", pkgver:"5.3.2-1ubuntu4.23")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cli", pkgver:"5.3.2-1ubuntu4.23")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-gd", pkgver:"5.3.2-1ubuntu4.23")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.10-1ubuntu3.10")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cgi", pkgver:"5.3.10-1ubuntu3.10")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cli", pkgver:"5.3.10-1ubuntu3.10")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-gd", pkgver:"5.3.10-1ubuntu3.10")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libapache2-mod-php5", pkgver:"5.4.6-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"php5-cgi", pkgver:"5.4.6-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"php5-cli", pkgver:"5.4.6-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"php5-gd", pkgver:"5.4.6-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"libapache2-mod-php5", pkgver:"5.5.3+dfsg-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"php5-cgi", pkgver:"5.5.3+dfsg-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"php5-cli", pkgver:"5.5.3+dfsg-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"php5-gd", pkgver:"5.5.3+dfsg-1ubuntu2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / php5-cgi / php5-cli / php5-gd");
}
