#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-862-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42930);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2008-7068", "CVE-2009-3291", "CVE-2009-3292", "CVE-2009-3557", "CVE-2009-3558", "CVE-2009-4017", "CVE-2009-4018");
  script_bugtraq_id(36449, 37079, 37138);
  script_osvdb_id(52206, 58185, 58186, 60434, 60435, 60451);
  script_xref(name:"USN", value:"862-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 / 9.10 : php5 vulnerabilities (USN-862-1)");
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
"Maksymilian Arciemowicz discovered that PHP did not properly validate
arguments to the dba_replace function. If a script passed untrusted
input to the dba_replace function, an attacker could truncate the
database. This issue only applied to Ubuntu 6.06 LTS, 8.04 LTS, and
8.10. (CVE-2008-7068)

It was discovered that PHP's php_openssl_apply_verification_policy
function did not correctly handle SSL certificates with zero bytes in
the Common Name. A remote attacker could exploit this to perform a man
in the middle attack to view sensitive information or alter encrypted
communications. (CVE-2009-3291)

It was discovered that PHP did not properly handle certain malformed
images when being parsed by the Exif module. A remote attacker could
exploit this flaw and cause the PHP server to crash, resulting in a
denial of service. (CVE-2009-3292)

Grzegorz Stachowiak discovered that PHP did not properly enforce
restrictions in the tempnam function. An attacker could exploit this
issue to bypass safe_mode restrictions. (CVE-2009-3557)

Grzegorz Stachowiak discovered that PHP did not properly enforce
restrictions in the posix_mkfifo function. An attacker could exploit
this issue to bypass open_basedir restrictions. (CVE-2009-3558)

Bogdan Calin discovered that PHP did not limit the number of temporary
files created when handling multipart/form-data POST requests. A
remote attacker could exploit this flaw and cause the PHP server to
consume all available resources, resulting in a denial of service.
(CVE-2009-4017)

ATTENTION: This update changes previous PHP behaviour by limiting the
number of files in a POST request to 50. This may be increased by
adding a 'max_file_uploads' directive to the php.ini configuration
file.

It was discovered that PHP did not properly enforce restrictions in
the proc_open function. An attacker could exploit this issue to bypass
safe_mode_protected_env_vars restrictions and possibly execute
arbitrary code with application privileges. (CVE-2009-4018).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mhash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mysqli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libapache2-mod-php5", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php-pear", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cgi", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cli", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-common", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-curl", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-dev", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-gd", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-ldap", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mhash", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysql", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysqli", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-odbc", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-pgsql", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-recode", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-snmp", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sqlite", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sybase", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xmlrpc", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xsl", pkgver:"5.1.2-1ubuntu3.17")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libapache2-mod-php5", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php-pear", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cgi", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cli", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-common", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-curl", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-dev", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-gd", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-gmp", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-ldap", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-mhash", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-mysql", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-odbc", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-pgsql", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-pspell", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-recode", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-snmp", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-sqlite", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-sybase", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-tidy", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-xmlrpc", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-xsl", pkgver:"5.2.4-2ubuntu5.9")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libapache2-mod-php5", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libapache2-mod-php5filter", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php-pear", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-cgi", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-cli", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-common", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-curl", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-dbg", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-dev", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-gd", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-gmp", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-ldap", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-mhash", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-mysql", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-odbc", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-pgsql", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-pspell", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-recode", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-snmp", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-sqlite", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-sybase", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-tidy", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-xmlrpc", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-xsl", pkgver:"5.2.6-2ubuntu4.5")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libapache2-mod-php5", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libapache2-mod-php5filter", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php-pear", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-cgi", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-cli", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-common", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-curl", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-dbg", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-dev", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-gd", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-gmp", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-ldap", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-mhash", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-mysql", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-odbc", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-pgsql", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-pspell", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-recode", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-snmp", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-sqlite", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-sybase", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-tidy", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-xmlrpc", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-xsl", pkgver:"5.2.6.dfsg.1-3ubuntu4.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libapache2-mod-php5", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libapache2-mod-php5filter", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php-pear", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-cgi", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-cli", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-common", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-curl", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-dbg", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-dev", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-gd", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-gmp", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-ldap", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-mhash", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-mysql", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-odbc", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-pgsql", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-pspell", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-recode", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-snmp", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-sqlite", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-sybase", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-tidy", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-xmlrpc", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-xsl", pkgver:"5.2.10.dfsg.1-2ubuntu6.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / libapache2-mod-php5filter / php-pear / php5 / etc");
}
