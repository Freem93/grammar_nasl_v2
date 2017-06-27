#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2572-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82911);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/24 17:37:08 $");

  script_cve_id("CVE-2015-2305", "CVE-2015-2348", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3329", "CVE-2015-3330");
  script_bugtraq_id(72611, 73431, 73434, 74204);
  script_osvdb_id(118433, 119773, 119774, 120925, 120930, 120938);
  script_xref(name:"USN", value:"2572-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 14.04 LTS / 14.10 : php5 vulnerabilities (USN-2572-1)");
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
"It was discovered that PHP incorrectly handled cleanup when used with
Apache 2.4. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2015-3330)

It was discovered that PHP incorrectly handled opening tar, zip or
phar archives through the PHAR extension. A remote attacker could use
this issue to cause PHP to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2015-3329)

It was discovered that PHP incorrectly handled regular expressions. A
remote attacker could use this issue to cause PHP to crash, resulting
in a denial of service, or possibly execute arbitrary code.
(CVE-2015-2305)

Paulos Yibelo discovered that PHP incorrectly handled moving files
when a pathname contained a null character. A remote attacker could
use this issue to possibly bypass filename restrictions. This issue
only applied to Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2015-2348)

It was discovered that PHP incorrectly handled unserializing PHAR
files. A remote attacker could use this issue to cause PHP to possibly
expose sensitive information. (CVE-2015-2783)

Taoguang Chen discovered that PHP incorrectly handled unserializing
certain objects. A remote attacker could use this issue to cause PHP
to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2015-2787).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/21");
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
if (! ereg(pattern:"^(10\.04|12\.04|14\.04|14\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 14.04 / 14.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.2-1ubuntu4.30")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cgi", pkgver:"5.3.2-1ubuntu4.30")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cli", pkgver:"5.3.2-1ubuntu4.30")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.10-1ubuntu3.18")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cgi", pkgver:"5.3.10-1ubuntu3.18")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cli", pkgver:"5.3.10-1ubuntu3.18")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-fpm", pkgver:"5.3.10-1ubuntu3.18")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libapache2-mod-php5", pkgver:"5.5.9+dfsg-1ubuntu4.9")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cgi", pkgver:"5.5.9+dfsg-1ubuntu4.9")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cli", pkgver:"5.5.9+dfsg-1ubuntu4.9")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-fpm", pkgver:"5.5.9+dfsg-1ubuntu4.9")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"libapache2-mod-php5", pkgver:"5.5.12+dfsg-2ubuntu4.4")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-cgi", pkgver:"5.5.12+dfsg-2ubuntu4.4")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-cli", pkgver:"5.5.12+dfsg-2ubuntu4.4")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-fpm", pkgver:"5.5.12+dfsg-2ubuntu4.4")) flag++;

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
