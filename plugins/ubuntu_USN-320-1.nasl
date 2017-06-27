#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-320-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27897);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/27 14:21:17 $");

  script_cve_id("CVE-2006-0996", "CVE-2006-1490", "CVE-2006-1494", "CVE-2006-1608", "CVE-2006-1990", "CVE-2006-1991", "CVE-2006-2563", "CVE-2006-2660", "CVE-2006-3011", "CVE-2006-3016", "CVE-2006-3017", "CVE-2006-3018");
  script_osvdb_id(24248, 24484, 24486, 24487, 24944, 24946, 25254, 25255, 25813, 26827, 27080);
  script_xref(name:"USN", value:"320-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : php4, php5 vulnerabilities (USN-320-1)");
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
"The phpinfo() PHP function did not properly sanitize long strings. A
remote attacker could use this to perform cross-site scripting attacks
against sites that have publicly-available PHP scripts that call
phpinfo(). Please note that it is not recommended to publicly expose
phpinfo(). (CVE-2006-0996)

An information disclosure has been reported in the
html_entity_decode() function. A script which uses this function to
process arbitrary user-supplied input could be exploited to expose a
random part of memory, which could potentially reveal sensitive data.
(CVE-2006-1490)

The wordwrap() function did not sufficiently check the validity of the
'break' argument. An attacker who could control the string passed to
the 'break' parameter could cause a heap overflow; however, this
should not happen in practical applications. (CVE-2006-1990)

The substr_compare() function did not sufficiently check the validity
of the 'offset' argument. A script which passes untrusted user-defined
values to this parameter could be exploited to crash the PHP
interpreter. (CVE-2006-1991)

In certain situations, using unset() to delete a hash entry could
cause the deletion of the wrong element, which would leave the
specified variable defined. This could potentially cause information
disclosure in security-relevant operations. (CVE-2006-3017)

In certain situations the session module attempted to close a data
file twice, which led to memory corruption. This could potentially be
exploited to crash the PHP interpreter, though that could not be
verified. (CVE-2006-3018)

This update also fixes various bugs which allowed local scripts to
bypass open_basedir and 'safe mode' restrictions by passing special
arguments to tempnam() (CVE-2006-1494, CVE-2006-2660), copy()
(CVE-2006-1608), the curl module (CVE-2006-2563), or error_log()
(CVE-2006-3011).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mhash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mysqli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04|5\.10|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"libapache2-mod-php4", pkgver:"4:4.3.10-10ubuntu4.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4", pkgver:"4.3.10-10ubuntu4.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-cgi", pkgver:"4:4.3.10-10ubuntu4.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-cli", pkgver:"4:4.3.10-10ubuntu4.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-common", pkgver:"4.3.10-10ubuntu4.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-dev", pkgver:"4.3.10-10ubuntu4.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libapache2-mod-php5", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php-pear", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-cgi", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-cli", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-common", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-curl", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-dev", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-gd", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-ldap", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-mhash", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-mysql", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-odbc", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-pgsql", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-recode", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-snmp", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-sqlite", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-sybase", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-xmlrpc", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-xsl", pkgver:"5.0.5-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libapache2-mod-php5", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php-pear", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cgi", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cli", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-common", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-curl", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-dev", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-gd", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-ldap", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mhash", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysql", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysqli", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-odbc", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-pgsql", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-recode", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-snmp", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sqlite", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sybase", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xmlrpc", pkgver:"5.1.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xsl", pkgver:"5.1.2-1ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php4 / libapache2-mod-php5 / php-pear / php4 / etc");
}
