#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3045-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92699);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2015-4116", "CVE-2015-8873", "CVE-2015-8876", "CVE-2015-8935", "CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5095", "CVE-2016-5096", "CVE-2016-5114", "CVE-2016-5385", "CVE-2016-5399", "CVE-2016-5768", "CVE-2016-5769", "CVE-2016-5771", "CVE-2016-5772", "CVE-2016-5773", "CVE-2016-6288", "CVE-2016-6289", "CVE-2016-6290", "CVE-2016-6291", "CVE-2016-6292", "CVE-2016-6294", "CVE-2016-6295", "CVE-2016-6296", "CVE-2016-6297");
  script_osvdb_id(122735, 125852, 125853, 132662, 138996, 138997, 139005, 140308, 140377, 140381, 140384, 140387, 140391, 141667, 141942, 141943, 141944, 141945, 141946, 141954, 141957, 141958, 142018, 142133);
  script_xref(name:"USN", value:"3045-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS : php5, php7.0 vulnerabilities (USN-3045-1) (httpoxy)");
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
"It was discovered that PHP incorrectly handled certain
SplMinHeap::compare operations. A remote attacker could use this issue
to cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2015-4116)

It was discovered that PHP incorrectly handled recursive method calls.
A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service. This issue only affected Ubuntu
12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-8873)

It was discovered that PHP incorrectly validated certain Exception
objects when unserializing data. A remote attacker could use this
issue to cause PHP to crash, resulting in a denial of service, or
possibly execute arbitrary code. This issue only affected Ubuntu 12.04
LTS and Ubuntu 14.04 LTS. (CVE-2015-8876)

It was discovered that PHP header() function performed insufficient
filtering for Internet Explorer. A remote attacker could possibly use
this issue to perform a XSS attack. This issue only affected Ubuntu
12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-8935)

It was discovered that PHP incorrectly handled certain locale
operations. An attacker could use this issue to cause PHP to crash,
resulting in a denial of service. This issue only affected Ubuntu
12.04 LTS and Ubuntu 14.04 LTS. (CVE-2016-5093)

It was discovered that the PHP php_html_entities() function
incorrectly handled certain string lengths. A remote attacker could
use this issue to cause PHP to crash, resulting in a denial of
service, or possibly execute arbitrary code. This issue only affected
Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2016-5094, CVE-2016-5095)

It was discovered that the PHP fread() function incorrectly handled
certain lengths. An attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2016-5096)

It was discovered that the PHP FastCGI Process Manager (FPM) SAPI
incorrectly handled memory in the access logging feature. An attacker
could use this issue to cause PHP to crash, resulting in a denial of
service, or possibly expose sensitive information. This issue only
affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2016-5114)

It was discovered that PHP would not protect applications from
contents of the HTTP_PROXY environment variable when based on the
contents of the Proxy header from HTTP requests. A remote attacker
could possibly use this issue in combination with scripts that honour
the HTTP_PROXY variable to redirect outgoing HTTP requests.
(CVE-2016-5385)

Hans Jerry Illikainen discovered that the PHP bzread() function
incorrectly performed error handling. A remote attacker could use this
issue to cause PHP to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2016-5399)

It was discovered that certain PHP multibyte string functions
incorrectly handled memory. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 14.04 LTS.
(CVE-2016-5768)

It was discovered that the PHP Mcrypt extension incorrectly handled
memory. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2016-5769)

It was discovered that the PHP garbage collector incorrectly handled
certain objects when unserializing malicious data. A remote attacker
could use this issue to cause PHP to crash, resulting in a denial of
service, or possibly execute arbitrary code. This issue was only
addressed in Ubuntu Ubuntu 14.04 LTS. (CVE-2016-5771, CVE-2016-5773)

It was discovered that PHP incorrectly handled memory when
unserializing malicious xml data. A remote attacker could use this
issue to cause PHP to crash, resulting in a denial of service, or
possibly execute arbitrary code. This issue only affected Ubuntu 12.04
LTS and Ubuntu 14.04 LTS. (CVE-2016-5772)

It was discovered that the PHP php_url_parse_ex() function incorrectly
handled string termination. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2016-6288)

It was discovered that PHP incorrectly handled path lengths when
extracting certain Zip archives. A remote attacker could use this
issue to cause PHP to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2016-6289)

It was discovered that PHP incorrectly handled session
deserialization. A remote attacker could use this issue to cause PHP
to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-6290)

It was discovered that PHP incorrectly handled exif headers when
processing certain JPEG images. A remote attacker could use this issue
to cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-6291, CVE-2016-6292)

It was discovered that PHP incorrectly handled certain locale
operations. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2016-6294)

It was discovered that the PHP garbage collector incorrectly handled
certain objects when unserializing SNMP data. A remote attacker could
use this issue to cause PHP to crash, resulting in a denial of
service, or possibly execute arbitrary code. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-6295)

It was discovered that the PHP xmlrpc_encode_request() function
incorrectly handled certain lengths. An attacker could use this issue
to cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-6296)

It was discovered that the PHP php_stream_zip_opener() function
incorrectly handled memory. An attacker could use this issue to cause
PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-6297).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/03");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.10-1ubuntu3.24")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cgi", pkgver:"5.3.10-1ubuntu3.24")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cli", pkgver:"5.3.10-1ubuntu3.24")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-fpm", pkgver:"5.3.10-1ubuntu3.24")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libapache2-mod-php5", pkgver:"5.5.9+dfsg-1ubuntu4.19")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cgi", pkgver:"5.5.9+dfsg-1ubuntu4.19")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cli", pkgver:"5.5.9+dfsg-1ubuntu4.19")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-fpm", pkgver:"5.5.9+dfsg-1ubuntu4.19")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libapache2-mod-php7.0", pkgver:"7.0.8-0ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-cgi", pkgver:"7.0.8-0ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-cli", pkgver:"7.0.8-0ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-fpm", pkgver:"7.0.8-0ubuntu0.16.04.2")) flag++;

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
