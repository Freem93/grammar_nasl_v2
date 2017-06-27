#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3211-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97384);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/02/28 14:42:20 $");

  script_cve_id("CVE-2016-10158", "CVE-2016-10159", "CVE-2016-10160", "CVE-2016-10161", "CVE-2016-10162", "CVE-2016-7479", "CVE-2016-9137", "CVE-2016-9935", "CVE-2016-9936", "CVE-2017-5340");
  script_osvdb_id(145606, 147470, 148281, 149442, 149623, 149628, 149629, 149664, 149665, 149666);
  script_xref(name:"USN", value:"3211-1");

  script_name(english:"Ubuntu 16.04 LTS / 16.10 : php7.0 vulnerabilities (USN-3211-1)");
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
"It was discovered that PHP incorrectly handled certain invalid objects
when unserializing data. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-7479)

It was discovered that PHP incorrectly handled certain invalid objects
when unserializing data. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-9137)

It was discovered that PHP incorrectly handled unserializing certain
wddxPacket XML documents. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-9935)

It was discovered that PHP incorrectly handled certain invalid objects
when unserializing data. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-9936)

It was discovered that PHP incorrectly handled certain EXIF data. A
remote attacker could use this issue to cause PHP to crash, resulting
in a denial of service. (CVE-2016-10158)

It was discovered that PHP incorrectly handled certain PHAR archives.
A remote attacker could use this issue to cause PHP to crash or
consume resources, resulting in a denial of service. (CVE-2016-10159)

It was discovered that PHP incorrectly handled certain PHAR archives.
A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2016-10160)

It was discovered that PHP incorrectly handled certain invalid objects
when unserializing data. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service. (CVE-2016-10161)

It was discovered that PHP incorrectly handled unserializing certain
wddxPacket XML documents. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service. (CVE-2016-10162)

It was discovered that PHP incorrectly handled certain invalid objects
when unserializing data. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2017-5340).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-fpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"libapache2-mod-php7.0", pkgver:"7.0.15-0ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-cgi", pkgver:"7.0.15-0ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-cli", pkgver:"7.0.15-0ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-fpm", pkgver:"7.0.15-0ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libapache2-mod-php7.0", pkgver:"7.0.15-0ubuntu0.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"php7.0-cgi", pkgver:"7.0.15-0ubuntu0.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"php7.0-cli", pkgver:"7.0.15-0ubuntu0.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"php7.0-fpm", pkgver:"7.0.15-0ubuntu0.16.10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php7.0 / php7.0-cgi / php7.0-cli / php7.0-fpm");
}
