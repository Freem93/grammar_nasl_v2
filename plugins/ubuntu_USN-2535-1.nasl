#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2535-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81950);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/24 17:37:08 $");

  script_cve_id("CVE-2014-8117", "CVE-2014-9705", "CVE-2015-0273", "CVE-2015-2301");
  script_bugtraq_id(71692, 72701, 73031, 73037);
  script_osvdb_id(115923, 118582, 118589, 119650);
  script_xref(name:"USN", value:"2535-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 14.04 LTS / 14.10 : php5 vulnerabilities (USN-2535-1)");
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
"Thomas Jarosch discovered that PHP incorrectly limited recursion in
the fileinfo extension. A remote attacker could possibly use this
issue to cause PHP to consume resources or crash, resulting in a
denial of service. (CVE-2014-8117)

S. Paraschoudis discovered that PHP incorrectly handled memory in the
enchant binding. A remote attacker could use this issue to cause PHP
to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2014-9705)

Taoguang Chen discovered that PHP incorrectly handled unserializing
objects. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2015-0273)

It was discovered that PHP incorrectly handled memory in the phar
extension. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2015-2301).

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/19");
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

if (ubuntu_check(osver:"10.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.2-1ubuntu4.29")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cgi", pkgver:"5.3.2-1ubuntu4.29")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cli", pkgver:"5.3.2-1ubuntu4.29")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-enchant", pkgver:"5.3.2-1ubuntu4.29")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.10-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cgi", pkgver:"5.3.10-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-cli", pkgver:"5.3.10-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-enchant", pkgver:"5.3.10-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5-fpm", pkgver:"5.3.10-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libapache2-mod-php5", pkgver:"5.5.9+dfsg-1ubuntu4.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cgi", pkgver:"5.5.9+dfsg-1ubuntu4.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cli", pkgver:"5.5.9+dfsg-1ubuntu4.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-enchant", pkgver:"5.5.9+dfsg-1ubuntu4.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-fpm", pkgver:"5.5.9+dfsg-1ubuntu4.7")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"libapache2-mod-php5", pkgver:"5.5.12+dfsg-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-cgi", pkgver:"5.5.12+dfsg-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-cli", pkgver:"5.5.12+dfsg-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-enchant", pkgver:"5.5.12+dfsg-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"php5-fpm", pkgver:"5.5.12+dfsg-2ubuntu4.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / php5-cgi / php5-cli / php5-enchant / php5-fpm");
}
