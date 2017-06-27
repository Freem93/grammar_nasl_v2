#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-989-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49306);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2010-0397", "CVE-2010-1128", "CVE-2010-1129", "CVE-2010-1130", "CVE-2010-1866", "CVE-2010-1868", "CVE-2010-1917", "CVE-2010-2094", "CVE-2010-2225", "CVE-2010-2531", "CVE-2010-2950", "CVE-2010-3065");
  script_bugtraq_id(38182, 38430, 38431, 38708, 39877, 40013, 40173, 40948, 41991);
  script_osvdb_id(62582, 62583, 63078, 63323, 64526, 64527, 64607, 65755, 66086, 66798, 66805);
  script_xref(name:"USN", value:"989-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.04 / 9.10 / 10.04 LTS : php5 vulnerabilities (USN-989-1)");
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
"Auke van Slooten discovered that PHP incorrectly handled certain
xmlrpc requests. An attacker could exploit this issue to cause the PHP
server to crash, resulting in a denial of service. This issue only
affected Ubuntu 6.06 LTS, 8.04 LTS, 9.04 and 9.10. (CVE-2010-0397)

It was discovered that the pseudorandom number generator in PHP did
not provide the expected entropy. An attacker could exploit this issue
to predict values that were intended to be random, such as session
cookies. This issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 9.04 and
9.10. (CVE-2010-1128)

It was discovered that PHP did not properly handle directory pathnames
that lacked a trailing slash character. An attacker could exploit this
issue to bypass safe_mode restrictions. This issue only affected
Ubuntu 6.06 LTS, 8.04 LTS, 9.04 and 9.10. (CVE-2010-1129)

Grzegorz Stachowiak discovered that the PHP session extension did not
properly handle semicolon characters. An attacker could exploit this
issue to bypass safe_mode restrictions. This issue only affected
Ubuntu 8.04 LTS, 9.04 and 9.10. (CVE-2010-1130)

Stefan Esser discovered that PHP incorrectly decoded remote HTTP
chunked encoding streams. An attacker could exploit this issue to
cause the PHP server to crash and possibly execute arbitrary code with
application privileges. This issue only affected Ubuntu 10.04 LTS.
(CVE-2010-1866)

Mateusz Kocielski discovered that certain PHP SQLite functions
incorrectly handled empty SQL queries. An attacker could exploit this
issue to possibly execute arbitrary code with application privileges.
(CVE-2010-1868)

Mateusz Kocielski discovered that PHP incorrectly handled certain
arguments to the fnmatch function. An attacker could exploit this flaw
and cause the PHP server to consume all available stack memory,
resulting in a denial of service. (CVE-2010-1917)

Stefan Esser discovered that PHP incorrectly handled certain strings
in the phar extension. An attacker could exploit this flaw to possibly
view sensitive information. This issue only affected Ubuntu 10.04 LTS.
(CVE-2010-2094, CVE-2010-2950)

Stefan Esser discovered that PHP incorrectly handled deserialization
of SPLObjectStorage objects. A remote attacker could exploit this
issue to view sensitive information and possibly execute arbitrary
code with application privileges. This issue only affected Ubuntu 8.04
LTS, 9.04, 9.10 and 10.04 LTS. (CVE-2010-2225)

It was discovered that PHP incorrectly filtered error messages when
limits for memory, execution time, or recursion were exceeded. A
remote attacker could exploit this issue to possibly view sensitive
information. (CVE-2010-2531)

Stefan Esser discovered that the PHP session serializer incorrectly
handled the PS_UNDEF_MARKER marker. An attacker could exploit this
issue to alter arbitrary session variables. (CVE-2010-3065).

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-intl");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libapache2-mod-php5", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php-pear", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cgi", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cli", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-common", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-curl", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-dev", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-gd", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-ldap", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mhash", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysql", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysqli", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-odbc", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-pgsql", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-recode", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-snmp", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sqlite", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sybase", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xmlrpc", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xsl", pkgver:"5.1.2-1ubuntu3.19")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libapache2-mod-php5", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php-pear", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cgi", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cli", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-common", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-curl", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-dev", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-gd", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-gmp", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-ldap", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-mhash", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-mysql", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-odbc", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-pgsql", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-pspell", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-recode", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-snmp", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-sqlite", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-sybase", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-tidy", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-xmlrpc", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-xsl", pkgver:"5.2.4-2ubuntu5.12")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libapache2-mod-php5", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libapache2-mod-php5filter", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php-pear", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-cgi", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-cli", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-common", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-curl", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-dbg", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-dev", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-gd", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-gmp", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-ldap", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-mhash", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-mysql", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-odbc", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-pgsql", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-pspell", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-recode", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-snmp", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-sqlite", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-sybase", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-tidy", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-xmlrpc", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"php5-xsl", pkgver:"5.2.6.dfsg.1-3ubuntu4.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libapache2-mod-php5", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libapache2-mod-php5filter", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php-pear", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-cgi", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-cli", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-common", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-curl", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-dbg", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-dev", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-gd", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-gmp", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-ldap", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-mhash", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-mysql", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-odbc", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-pgsql", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-pspell", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-recode", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-snmp", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-sqlite", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-sybase", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-tidy", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-xmlrpc", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-xsl", pkgver:"5.2.10.dfsg.1-2ubuntu6.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libapache2-mod-php5filter", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php-pear", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cgi", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cli", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-common", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-curl", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-dbg", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-dev", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-enchant", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-gd", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-gmp", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-intl", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-ldap", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-mysql", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-odbc", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-pgsql", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-pspell", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-recode", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-snmp", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-sqlite", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-sybase", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-tidy", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-xmlrpc", pkgver:"5.3.2-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-xsl", pkgver:"5.3.2-1ubuntu4.5")) flag++;

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
