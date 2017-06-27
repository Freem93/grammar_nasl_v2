#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1358-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57932);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/25 16:11:45 $");

  script_cve_id("CVE-2011-0441", "CVE-2011-4153", "CVE-2011-4885", "CVE-2012-0057", "CVE-2012-0788", "CVE-2012-0830", "CVE-2012-0831");
  script_xref(name:"USN", value:"1358-2");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 / 11.10 : php5 regression (USN-1358-2)");
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
"USN 1358-1 fixed multiple vulnerabilities in PHP. The fix for
CVE-2012-0831 introduced a regression where the state of the
magic_quotes_gpc setting was not correctly reflected when calling the
ini_get() function.

We apologize for the inconvenience.

It was discovered that PHP computed hash values for form parameters
without restricting the ability to trigger hash collisions
predictably. This could allow a remote attacker to cause a denial of
service by sending many crafted parameters. (CVE-2011-4885)

ATTENTION: this update changes previous PHP behavior by
limiting the number of external input variables to 1000.
This may be increased by adding a 'max_input_vars' directive
to the php.ini configuration file. See
http://www.php.net/manual/en/info.configuration.php#ini.max-
input-vars for more information.

Stefan Esser discovered that the fix to address the
predictable hash collision issue, CVE-2011-4885, did not
properly handle the situation where the limit was reached.
This could allow a remote attacker to cause a denial of
service or execute arbitrary code via a request containing a
large number of variables. (CVE-2012-0830)

It was discovered that PHP did not always check the return
value of the zend_strndup function. This could allow a
remote attacker to cause a denial of service.
(CVE-2011-4153)

It was discovered that PHP did not properly enforce libxslt
security settings. This could allow a remote attacker to
create arbitrary files via a crafted XSLT stylesheet that
uses the libxslt output extension. (CVE-2012-0057)

It was discovered that PHP did not properly enforce that
PDORow objects could not be serialized and not be saved in a
session. A remote attacker could use this to cause a denial
of service via an application crash. (CVE-2012-0788)

It was discovered that PHP allowed the magic_quotes_gpc
setting to be disabled remotely. This could allow a remote
attacker to bypass restrictions that could prevent a SQL
injection. (CVE-2012-0831)

USN 1126-1 addressed an issue where the /etc/cron.d/php5
cron job for PHP allowed local users to delete arbitrary
files via a symlink attack on a directory under
/var/lib/php5/. Emese Revfy discovered that the fix had not
been applied to PHP for Ubuntu 10.04 LTS. This update
corrects the issue. We apologize for the error.
(CVE-2011-0441).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libapache2-mod-php5", pkgver:"5.2.4-2ubuntu5.23")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5", pkgver:"5.2.4-2ubuntu5.23")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cgi", pkgver:"5.2.4-2ubuntu5.23")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cli", pkgver:"5.2.4-2ubuntu5.23")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.2-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5", pkgver:"5.3.2-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cgi", pkgver:"5.3.2-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cli", pkgver:"5.3.2-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libapache2-mod-php5", pkgver:"5.3.3-1ubuntu9.10")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5", pkgver:"5.3.3-1ubuntu9.10")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5-cgi", pkgver:"5.3.3-1ubuntu9.10")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5-cli", pkgver:"5.3.3-1ubuntu9.10")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.5-1ubuntu7.7")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5", pkgver:"5.3.5-1ubuntu7.7")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5-cgi", pkgver:"5.3.5-1ubuntu7.7")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5-cli", pkgver:"5.3.5-1ubuntu7.7")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libapache2-mod-php5", pkgver:"5.3.6-13ubuntu3.6")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"php5", pkgver:"5.3.6-13ubuntu3.6")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"php5-cgi", pkgver:"5.3.6-13ubuntu3.6")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"php5-cli", pkgver:"5.3.6-13ubuntu3.6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / php5 / php5-cgi / php5-cli");
}
