#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2658-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84563);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4025", "CVE-2015-4026", "CVE-2015-4147", "CVE-2015-4148", "CVE-2015-4598", "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4603", "CVE-2015-4604", "CVE-2015-4605", "CVE-2015-4643", "CVE-2015-4644");
  script_bugtraq_id(73357, 74413, 74700, 74902, 74903, 74904, 75056, 75103, 75233, 75241, 75244, 75246, 75249, 75250, 75251, 75252, 75255, 75291, 75292);
  script_osvdb_id(117588, 119772, 120926, 121321, 121398, 122125, 122126, 122127, 122261, 122268, 123148, 123639, 123640, 123677);
  script_xref(name:"USN", value:"2658-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 14.10 / 15.04 : php5 vulnerabilities (USN-2658-1)");
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
"Neal Poole and Tomas Hoger discovered that PHP incorrectly handled
NULL bytes in file paths. A remote attacker could possibly use this
issue to bypass intended restrictions and create or obtain access to
sensitive files. (CVE-2015-3411, CVE-2015-3412, CVE-2015-4025,
CVE-2015-4026, CVE-2015-4598)

Emmanuel Law discovered that the PHP phar extension incorrectly
handled filenames starting with a NULL byte. A remote attacker could
use this issue with a crafted tar archive to cause a denial of
service. (CVE-2015-4021)

Max Spelsberg discovered that PHP incorrectly handled the LIST command
when connecting to remote FTP servers. A malicious FTP server could
possibly use this issue to execute arbitrary code. (CVE-2015-4022,
CVE-2015-4643)

Shusheng Liu discovered that PHP incorrectly handled certain malformed
form data. A remote attacker could use this issue with crafted form
data to cause CPU consumption, leading to a denial of service.
(CVE-2015-4024)

Andrea Palazzo discovered that the PHP Soap client incorrectly
validated data types. A remote attacker could use this issue with
crafted serialized data to possibly execute arbitrary code.
(CVE-2015-4147)

Andrea Palazzo discovered that the PHP Soap client incorrectly
validated that the uri property is a string. A remote attacker could
use this issue with crafted serialized data to possibly obtain
sensitive information. (CVE-2015-4148)

Taoguang Chen discovered that PHP incorrectly validated data types in
multiple locations. A remote attacker could possibly use these issues
to obtain sensitive information or cause a denial of service.
(CVE-2015-4599, CVE-2015-4600, CVE-2015-4601, CVE-2015-4602,
CVE-2015-4603)

It was discovered that the PHP Fileinfo component incorrectly handled
certain files. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service. This issue only affected
Ubuntu 15.04. (CVE-2015-4604, CVE-2015-4605)

It was discovered that PHP incorrectly handled table names in
php_pgsql_meta_data. A local attacker could possibly use this issue to
cause PHP to crash, resulting in a denial of service. (CVE-2015-4644).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|14\.10|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 14.10 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.10-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cgi", pkgver:"5.3.10-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cli", pkgver:"5.3.10-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-fpm", pkgver:"5.3.10-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libapache2-mod-php5", pkgver:"5.5.9+dfsg-1ubuntu4.11")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cgi", pkgver:"5.5.9+dfsg-1ubuntu4.11")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cli", pkgver:"5.5.9+dfsg-1ubuntu4.11")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-fpm", pkgver:"5.5.9+dfsg-1ubuntu4.11")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"libapache2-mod-php5", pkgver:"5.5.12+dfsg-2ubuntu4.6")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-cgi", pkgver:"5.5.12+dfsg-2ubuntu4.6")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-cli", pkgver:"5.5.12+dfsg-2ubuntu4.6")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-fpm", pkgver:"5.5.12+dfsg-2ubuntu4.6")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libapache2-mod-php5", pkgver:"5.6.4+dfsg-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"php5-cgi", pkgver:"5.6.4+dfsg-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"php5-cli", pkgver:"5.6.4+dfsg-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"php5-fpm", pkgver:"5.6.4+dfsg-4ubuntu6.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / php5-cgi / php5-cli / php5-fpm");
}
