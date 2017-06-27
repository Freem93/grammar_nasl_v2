#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2984-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91320);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2015-8865", "CVE-2016-3078", "CVE-2016-3132", "CVE-2016-4070", "CVE-2016-4071", "CVE-2016-4072", "CVE-2016-4073", "CVE-2016-4342", "CVE-2016-4343", "CVE-2016-4537", "CVE-2016-4538", "CVE-2016-4539", "CVE-2016-4540", "CVE-2016-4541", "CVE-2016-4542", "CVE-2016-4543", "CVE-2016-4544");
  script_osvdb_id(122863, 134031, 134037, 136483, 136484, 136485, 136486, 137738, 137781, 137782, 137783, 137784, 138122);
  script_xref(name:"USN", value:"2984-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 / 16.04 LTS : php5, php7.0 vulnerabilities (USN-2984-1)");
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
"It was discovered that the PHP Fileinfo component incorrectly handled
certain magic files. An attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 16.04 LTS. (CVE-2015-8865)

Hans Jerry Illikainen discovered that the PHP Zip extension
incorrectly handled certain malformed Zip archives. A remote attacker
could use this issue to cause PHP to crash, resulting in a denial of
service, or possibly execute arbitrary code. This issue only affected
Ubuntu 16.04 LTS. (CVE-2016-3078)

It was discovered that PHP incorrectly handled invalid indexes in the
SplDoublyLinkedList class. An attacker could use this issue to cause
PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 16.04 LTS.
(CVE-2016-3132)

It was discovered that the PHP rawurlencode() function incorrectly
handled large strings. A remote attacker could use this issue to cause
PHP to crash, resulting in a denial of service. This issue only
affected Ubuntu 16.04 LTS. (CVE-2016-4070)

It was discovered that the PHP php_snmp_error() function incorrectly
handled string formatting. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS.
(CVE-2016-4071)

It was discovered that the PHP phar extension incorrectly handled
certain filenames in archives. A remote attacker could use this issue
to cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS.
(CVE-2016-4072)

It was discovered that the PHP mb_strcut() function incorrectly
handled string formatting. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS.
(CVE-2016-4073)

It was discovered that the PHP phar extension incorrectly handled
certain archive files. A remote attacker could use this issue to cause
PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 12.04 LTS, Ubuntu
14.04 LTS and Ubuntu 15.10. (CVE-2016-4342, CVE-2016-4343)

It was discovered that the PHP bcpowmod() function incorrectly handled
memory. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2016-4537, CVE-2016-4538)

It was discovered that the PHP XML parser incorrectly handled certain
malformed XML data. A remote attacker could possibly use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-4539)

It was discovered that certain PHP grapheme functions incorrectly
handled negative offsets. A remote attacker could possibly use this
issue to cause PHP to crash, resulting in a denial of service.
(CVE-2016-4540, CVE-2016-4541)

It was discovered that PHP incorrectly handled certain malformed EXIF
tags. A remote attacker could possibly use this issue to cause PHP to
crash, resulting in a denial of service. (CVE-2016-4542,
CVE-2016-4543, CVE-2016-4544).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-fpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.10|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.10 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.10-1ubuntu3.23")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cgi", pkgver:"5.3.10-1ubuntu3.23")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cli", pkgver:"5.3.10-1ubuntu3.23")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-fpm", pkgver:"5.3.10-1ubuntu3.23")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libapache2-mod-php5", pkgver:"5.5.9+dfsg-1ubuntu4.17")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cgi", pkgver:"5.5.9+dfsg-1ubuntu4.17")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cli", pkgver:"5.5.9+dfsg-1ubuntu4.17")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-fpm", pkgver:"5.5.9+dfsg-1ubuntu4.17")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libapache2-mod-php5", pkgver:"5.6.11+dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"php5-cgi", pkgver:"5.6.11+dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"php5-cli", pkgver:"5.6.11+dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"php5-fpm", pkgver:"5.6.11+dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libapache2-mod-php7.0", pkgver:"7.0.4-7ubuntu2.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-cgi", pkgver:"7.0.4-7ubuntu2.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-cli", pkgver:"7.0.4-7ubuntu2.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-fpm", pkgver:"7.0.4-7ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / libapache2-mod-php7.0 / php5-cgi / php5-cli / etc");
}
