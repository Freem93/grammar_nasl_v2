#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-628-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33575);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2007-4782", "CVE-2007-4850", "CVE-2007-5898", "CVE-2007-5899", "CVE-2008-0599", "CVE-2008-1384", "CVE-2008-2050", "CVE-2008-2051", "CVE-2008-2107", "CVE-2008-2108", "CVE-2008-2371", "CVE-2008-2829");
  script_bugtraq_id(26403, 29009, 29829);
  script_osvdb_id(38683, 38686, 38688, 38918, 43219, 44057, 44906, 44907, 44908, 44909, 44910, 46641, 46690);
  script_xref(name:"USN", value:"628-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : php5 vulnerabilities (USN-628-1)");
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
"It was discovered that PHP did not properly check the length of the
string parameter to the fnmatch function. An attacker could cause a
denial of service in the PHP interpreter if a script passed untrusted
input to the fnmatch function. (CVE-2007-4782)

Maksymilian Arciemowicz discovered a flaw in the cURL library that
allowed safe_mode and open_basedir restrictions to be bypassed. If a
PHP application were tricked into processing a bad file:// request, an
attacker could read arbitrary files. (CVE-2007-4850)

Rasmus Lerdorf discovered that the htmlentities and htmlspecialchars
functions did not correctly stop when handling partial multibyte
sequences. A remote attacker could exploit this to read certain areas
of memory, possibly gaining access to sensitive information. This
issue affects Ubuntu 8.04 LTS, and an updated fix is included for
Ubuntu 6.06 LTS, 7.04 and 7.10. (CVE-2007-5898)

It was discovered that the output_add_rewrite_var function would
sometimes leak session id information to forms targeting remote URLs.
Malicious remote sites could use this information to gain access to a
PHP application user's login credentials. This issue only affects
Ubuntu 8.04 LTS. (CVE-2007-5899)

It was discovered that PHP did not properly calculate the length of
PATH_TRANSLATED. If a PHP application were tricked into processing a
malicious URI, and attacker may be able to execute arbitrary code with
application privileges. (CVE-2008-0599)

An integer overflow was discovered in the php_sprintf_appendstring
function. Attackers could exploit this to cause a denial of service.
(CVE-2008-1384)

Andrei Nigmatulin discovered stack-based overflows in the FastCGI SAPI
of PHP. An attacker may be able to leverage this issue to perform
attacks against PHP applications. (CVE-2008-2050)

It was discovered that the escapeshellcmd did not properly process
multibyte characters. An attacker may be able to bypass quoting
restrictions and possibly execute arbitrary code with application
privileges. (CVE-2008-2051)

It was discovered that the GENERATE_SEED macro produced a predictable
seed under certain circumstances. Attackers may by able to easily
predict the results of the rand and mt_rand functions. (CVE-2008-2107,
CVE-2008-2108)

Tavis Ormandy discovered that the PCRE library did not correctly
handle certain in-pattern options. An attacker could cause PHP
applications using pcre to crash, leading to a denial of service.
USN-624-1 fixed vulnerabilities in the pcre3 library. This update
provides the corresponding update for PHP. (CVE-2008-2371)

It was discovered that php_imap used obsolete API calls. If a PHP
application were tricked into processing a malicious IMAP request, an
attacker could cause a denial of service or possibly execute code with
application privileges. (CVE-2008-2829).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 119, 189, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-curl");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libapache2-mod-php5", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php-pear", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cgi", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cli", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-common", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-curl", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-dev", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-gd", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-ldap", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mhash", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysql", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysqli", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-odbc", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-pgsql", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-recode", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-snmp", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sqlite", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sybase", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xmlrpc", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xsl", pkgver:"5.1.2-1ubuntu3.12")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libapache2-mod-php5", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php-pear", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-cgi", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-cli", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-common", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-curl", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-dev", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-gd", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-ldap", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-mhash", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-mysql", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-odbc", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-pgsql", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-pspell", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-recode", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-snmp", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-sqlite", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-sybase", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-tidy", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-xmlrpc", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-xsl", pkgver:"5.2.1-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libapache2-mod-php5", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php-pear", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-cgi", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-cli", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-common", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-curl", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-dev", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-gd", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-ldap", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-mhash", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-mysql", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-odbc", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-pgsql", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-pspell", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-recode", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-snmp", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-sqlite", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-sybase", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-tidy", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-xmlrpc", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-xsl", pkgver:"5.2.3-1ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libapache2-mod-php5", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php-pear", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cgi", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cli", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-common", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-curl", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-dev", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-gd", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-gmp", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-ldap", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-mhash", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-mysql", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-odbc", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-pgsql", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-pspell", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-recode", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-snmp", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-sqlite", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-sybase", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-tidy", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-xmlrpc", pkgver:"5.2.4-2ubuntu5.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-xsl", pkgver:"5.2.4-2ubuntu5.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / php-pear / php5 / php5-cgi / php5-cli / etc");
}
