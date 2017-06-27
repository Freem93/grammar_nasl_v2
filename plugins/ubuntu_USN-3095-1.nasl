#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3095-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93864);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2016-7124", "CVE-2016-7125", "CVE-2016-7127", "CVE-2016-7128", "CVE-2016-7129", "CVE-2016-7130", "CVE-2016-7131", "CVE-2016-7132", "CVE-2016-7133", "CVE-2016-7134", "CVE-2016-7411", "CVE-2016-7412", "CVE-2016-7413", "CVE-2016-7414", "CVE-2016-7416", "CVE-2016-7417", "CVE-2016-7418");
  script_osvdb_id(143095, 143096, 143103, 143104, 143106, 143110, 143111, 143115, 143116, 143118, 144259, 144260, 144261, 144262, 144263, 144268, 144269);
  script_xref(name:"USN", value:"3095-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS : php5, php7.0 vulnerabilities (USN-3095-1)");
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
"Taoguang Chen discovered that PHP incorrectly handled certain invalid
objects when unserializing data. A remote attacker could use this
issue to cause PHP to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2016-7124)

Taoguang Chen discovered that PHP incorrectly handled invalid session
names. A remote attacker could use this issue to inject arbitrary
session data. (CVE-2016-7125)

It was discovered that PHP incorrectly handled certain gamma values in
the imagegammacorrect function. A remote attacker could use this issue
to cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-7127)

It was discovered that PHP incorrectly handled certain crafted TIFF
image thumbnails. A remote attacker could use this issue to cause PHP
to crash, resulting in a denial of service, or possibly expose
sensitive information. (CVE-2016-7128)

It was discovered that PHP incorrectly handled unserializing certain
wddxPacket XML documents. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-7129, CVE-2016-7130, CVE-2016-7131,
CVE-2016-7132, CVE-2016-7413)

It was discovered that PHP incorrectly handled certain memory
operations. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 16.04 LTS. (CVE-2016-7133)

It was discovered that PHP incorrectly handled long strings in
curl_escape calls. A remote attacker could use this issue to cause PHP
to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 16.04 LTS.
(CVE-2016-7134)

Taoguang Chen discovered that PHP incorrectly handled certain failures
when unserializing data. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2016-7411)

It was discovered that PHP incorrectly handled certain flags in the
MySQL driver. Malicious remote MySQL servers could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-7412)

It was discovered that PHP incorrectly handled ZIP file signature
verification when processing a PHAR archive. A remote attacker could
use this issue to cause PHP to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2016-7414)

It was discovered that PHP incorrectly handled certain locale
operations. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2016-7416)

It was discovered that PHP incorrectly handled SplArray unserializing.
A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2016-7417)

Ke Liu discovered that PHP incorrectly handled unserializing
wddxPacket XML documents with incorrect boolean elements. A remote
attacker could use this issue to cause PHP to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2016-7418).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/05");
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

if (ubuntu_check(osver:"12.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.10-1ubuntu3.25")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cgi", pkgver:"5.3.10-1ubuntu3.25")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cli", pkgver:"5.3.10-1ubuntu3.25")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-curl", pkgver:"5.3.10-1ubuntu3.25")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-fpm", pkgver:"5.3.10-1ubuntu3.25")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-gd", pkgver:"5.3.10-1ubuntu3.25")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-mysqlnd", pkgver:"5.3.10-1ubuntu3.25")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libapache2-mod-php5", pkgver:"5.5.9+dfsg-1ubuntu4.20")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cgi", pkgver:"5.5.9+dfsg-1ubuntu4.20")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cli", pkgver:"5.5.9+dfsg-1ubuntu4.20")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-curl", pkgver:"5.5.9+dfsg-1ubuntu4.20")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-fpm", pkgver:"5.5.9+dfsg-1ubuntu4.20")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-gd", pkgver:"5.5.9+dfsg-1ubuntu4.20")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-mysqlnd", pkgver:"5.5.9+dfsg-1ubuntu4.20")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libapache2-mod-php7.0", pkgver:"7.0.8-0ubuntu0.16.04.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-cgi", pkgver:"7.0.8-0ubuntu0.16.04.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-cli", pkgver:"7.0.8-0ubuntu0.16.04.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-curl", pkgver:"7.0.8-0ubuntu0.16.04.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-fpm", pkgver:"7.0.8-0ubuntu0.16.04.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-gd", pkgver:"7.0.8-0ubuntu0.16.04.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-mysql", pkgver:"7.0.8-0ubuntu0.16.04.3")) flag++;

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
