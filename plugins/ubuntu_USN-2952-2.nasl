#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2952-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90825);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/01 21:07:48 $");

  script_cve_id("CVE-2014-9767", "CVE-2015-8835", "CVE-2015-8838", "CVE-2016-1903", "CVE-2016-2554", "CVE-2016-3141", "CVE-2016-3142", "CVE-2016-3185");
  script_osvdb_id(125855, 127122, 132661, 134034, 135224, 135225, 135227, 137454);
  script_xref(name:"USN", value:"2952-2");

  script_name(english:"Ubuntu 15.10 : php5 regression (USN-2952-2)");
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
"USN-2952-1 fixed vulnerabilities in PHP. One of the backported patches
caused a regression in the PHP Soap client. This update fixes the
problem.

We apologize for the inconvenience.

It was discovered that the PHP Zip extension incorrectly handled
directories when processing certain zip files. A remote attacker could
possibly use this issue to create arbitrary directories.
(CVE-2014-9767)

It was discovered that the PHP Soap client incorrectly
validated data types. A remote attacker could use this issue
to cause PHP to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2015-8835,
CVE-2016-3185)

It was discovered that the PHP MySQL native driver
incorrectly handled TLS connections to MySQL databases. A
man in the middle attacker could possibly use this issue to
downgrade and snoop on TLS connections. This vulnerability
is known as BACKRONYM. (CVE-2015-8838)

It was discovered that PHP incorrectly handled the
imagerotate function. A remote attacker could use this issue
to cause PHP to crash, resulting in a denial of service, or
possibly obtain sensitive information. This issue only
applied to Ubuntu 14.04 LTS and Ubuntu 15.10.
(CVE-2016-1903)

Hans Jerry Illikainen discovered that the PHP phar extension
incorrectly handled certain tar archives. A remote attacker
could use this issue to cause PHP to crash, resulting in a
denial of service, or possibly execute arbitrary code.
(CVE-2016-2554)

It was discovered that the PHP WDDX extension incorrectly
handled certain malformed XML data. A remote attacker could
possibly use this issue to cause PHP to crash, resulting in
a denial of service, or possibly execute arbitrary code.
(CVE-2016-3141)

It was discovered that the PHP phar extension incorrectly
handled certain zip files. A remote attacker could use this
issue to cause PHP to crash, resulting in a denial of
service, or possibly obtain sensitive information.
(CVE-2016-3142)

It was discovered that the PHP
libxml_disable_entity_loader() setting was shared between
threads. When running under PHP-FPM, this could result in
XML external entity injection and entity expansion issues.
This issue only applied to Ubuntu 12.04 LTS and Ubuntu 14.04
LTS. (No CVE number)

It was discovered that the PHP openssl_random_pseudo_bytes()
function did not return cryptographically strong
pseudo-random bytes. (No CVE number)

It was discovered that the PHP Fileinfo component
incorrectly handled certain magic files. An attacker could
use this issue to cause PHP to crash, resulting in a denial
of service, or possibly execute arbitrary code. (CVE number
pending)

It was discovered that the PHP php_snmp_error() function
incorrectly handled string formatting. A remote attacker
could use this issue to cause PHP to crash, resulting in a
denial of service, or possibly execute arbitrary code. This
issue only applied to Ubuntu 14.04 LTS and Ubuntu 15.10.
(CVE number pending)

It was discovered that the PHP rawurlencode() function
incorrectly handled large strings. A remote attacker could
use this issue to cause PHP to crash, resulting in a denial
of service. (CVE number pending)

It was discovered that the PHP phar extension incorrectly
handled certain filenames in archives. A remote attacker
could use this issue to cause PHP to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE
number pending)

It was discovered that the PHP mb_strcut() function
incorrectly handled string formatting. A remote attacker
could use this issue to cause PHP to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE
number pending).

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/02");
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
if (! ereg(pattern:"^(15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"15.10", pkgname:"libapache2-mod-php5", pkgver:"5.6.11+dfsg-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"php5-cgi", pkgver:"5.6.11+dfsg-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"php5-cli", pkgver:"5.6.11+dfsg-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"php5-fpm", pkgver:"5.6.11+dfsg-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"php5-gd", pkgver:"5.6.11+dfsg-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"php5-mysqlnd", pkgver:"5.6.11+dfsg-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"php5-snmp", pkgver:"5.6.11+dfsg-1ubuntu3.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / php5-cgi / php5-cli / php5-fpm / php5-gd / etc");
}
