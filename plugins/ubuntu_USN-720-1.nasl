#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-720-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36665);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2007-3996", "CVE-2007-5625", "CVE-2007-5900", "CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660", "CVE-2008-5557", "CVE-2008-5624", "CVE-2008-5625", "CVE-2008-5658");
  script_bugtraq_id(25498, 26403, 30649, 31612, 32625, 32948);
  script_osvdb_id(36870, 38680, 47796, 47797, 47798, 51477);
  script_xref(name:"USN", value:"720-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : php5 vulnerabilities (USN-720-1)");
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
"It was discovered that PHP did not properly enforce php_admin_value
and php_admin_flag restrictions in the Apache configuration file. A
local attacker could create a specially crafted PHP script that would
bypass intended security restrictions. This issue only applied to
Ubuntu 6.06 LTS, 7.10, and 8.04 LTS. (CVE-2007-5900)

It was discovered that PHP did not correctly handle certain malformed
font files. If a PHP application were tricked into processing a
specially crafted font file, an attacker may be able to cause a denial
of service and possibly execute arbitrary code with application
privileges. (CVE-2008-3658)

It was discovered that PHP did not properly check the delimiter
argument to the explode function. If a script passed untrusted input
to the explode function, an attacker could cause a denial of service
and possibly execute arbitrary code with application privileges.
(CVE-2008-3659) 

It was discovered that PHP, when used as FastCGI module, did not
properly sanitize requests. By performing a request with multiple dots
preceding the extension, an attacker could cause a denial of service.
(CVE-2008-3660)

It was discovered that PHP did not properly handle Unicode conversion
in the mbstring extension. If a PHP application were tricked into
processing a specially crafted string containing an HTML entity, an
attacker could execute arbitrary code with application privileges.
(CVE-2008-5557)

It was discovered that PHP did not properly initialize the page_uid
and page_gid global variables for use by the SAPI php_getuid function.
An attacker could exploit this issue to bypass safe_mode restrictions.
(CVE-2008-5624)

It was dicovered that PHP did not properly enforce error_log safe_mode
restrictions when set by php_admin_flag in the Apache configuration
file. A local attacker could create a specially crafted PHP script
that would overwrite arbitrary files. (CVE-2008-5625)

It was discovered that PHP contained a flaw in the
ZipArchive::extractTo function. If a PHP application were tricked into
processing a specially crafted zip file that had filenames containing
'..', an attacker could write arbitrary files within the filesystem.
This issue only applied to Ubuntu 7.10, 8.04 LTS, and 8.10.
(CVE-2008-5658)

USN-557-1 fixed a vulnerability in the GD library. When using the GD
library, PHP did not properly handle the return codes that were added
in the security update. An attacker could exploit this issue with a
specially crafted image file and cause PHP to crash, leading to a
denial of service. This issue only applied to Ubuntu 6.06 LTS, and
7.10. (CVE-2007-3996).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 22, 79, 119, 189, 264);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/30");
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
if (! ereg(pattern:"^(6\.06|7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libapache2-mod-php5", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php-pear", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cgi", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cli", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-common", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-curl", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-dev", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-gd", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-ldap", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mhash", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysql", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysqli", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-odbc", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-pgsql", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-recode", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-snmp", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sqlite", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sybase", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xmlrpc", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xsl", pkgver:"5.1.2-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libapache2-mod-php5", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php-pear", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-cgi", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-cli", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-common", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-curl", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-dev", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-gd", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-ldap", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-mhash", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-mysql", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-odbc", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-pgsql", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-pspell", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-recode", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-snmp", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-sqlite", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-sybase", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-tidy", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-xmlrpc", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-xsl", pkgver:"5.2.3-1ubuntu6.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libapache2-mod-php5", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php-pear", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cgi", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cli", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-common", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-curl", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-dev", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-gd", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-gmp", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-ldap", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-mhash", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-mysql", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-odbc", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-pgsql", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-pspell", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-recode", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-snmp", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-sqlite", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-sybase", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-tidy", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-xmlrpc", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-xsl", pkgver:"5.2.4-2ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libapache2-mod-php5", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libapache2-mod-php5filter", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php-pear", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-cgi", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-cli", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-common", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-curl", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-dbg", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-dev", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-gd", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-gmp", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-ldap", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-mhash", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-mysql", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-odbc", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-pgsql", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-pspell", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-recode", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-snmp", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-sqlite", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-sybase", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-tidy", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-xmlrpc", pkgver:"5.2.6-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"php5-xsl", pkgver:"5.2.6-2ubuntu4.1")) flag++;

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
