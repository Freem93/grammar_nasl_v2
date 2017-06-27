#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-455-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28053);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/27 14:29:17 $");

  script_cve_id("CVE-2007-1375", "CVE-2007-1376", "CVE-2007-1380", "CVE-2007-1484", "CVE-2007-1521", "CVE-2007-1583", "CVE-2007-1700", "CVE-2007-1717", "CVE-2007-1718", "CVE-2007-1824", "CVE-2007-1887", "CVE-2007-1888", "CVE-2007-1900");
  script_bugtraq_id(22805, 22851, 22862, 22968, 22990, 23016, 23119, 23145, 23237, 23359);
  script_osvdb_id(32776, 32780, 32781, 33936, 33938, 33940, 33944, 33948, 33958, 33959, 33962, 39177);
  script_xref(name:"USN", value:"455-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 : php5 vulnerabilities (USN-455-1)");
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
"Stefan Esser discovered multiple vulnerabilities in the 'Month of PHP
bugs'.

The substr_compare() function did not sufficiently verify its length
argument. This might be exploited to read otherwise unaccessible
memory, which might lead to information disclosure. (CVE-2007-1375)

The shared memory (shmop) functions did not verify resource types,
thus they could be called with a wrong resource type that might
contain user-supplied data. This could be exploited to read and write
arbitrary memory addresses of the PHP interpreter. This issue does not
affect Ubuntu 7.04. (CVE-2007-1376)

The php_binary handler of the session extension was missing a boundary
check. When unserializing overly long variable names this could be
exploited to read up to 126 bytes of memory, which might lead to
information disclosure. (CVE-2007-1380)

The internal array_user_key_compare() function, as used for example by
the PHP function uksort(), incorrectly handled memory unreferencing of
its arguments. This could have been exploited to execute arbitrary
code with the privileges of the PHP interpreter, and thus
circumventing any disable_functions, open_basedir, or safe_mode
restrictions. (CVE-2007-1484)

The session_regenerate_id() function did not properly clean up the
former session identifier variable. This could be exploited to crash
the PHP interpreter, possibly also remotely. (CVE-2007-1521)

Under certain conditions the mb_parse_str() could cause the
register_globals configuration option to become permanently enabled.
This opened an attack vector for a large and common class of
vulnerabilities. (CVE-2007-1583)

The session extension did not set the correct reference count value
for the session variables. By unsetting _SESSION and HTTP_SESSION_VARS
(or tricking a PHP script into doing that) this could be exploited to
execute arbitrary code with the privileges of the PHP interpreter.
This issue does not affect Ubuntu 7.04. (CVE-2007-1700)

The mail() function did not correctly escape control characters in
multiline email headers. This could be remotely exploited to inject
arbitrary email headers. (CVE-2007-1718)

The php_stream_filter_create() function had an off-by-one buffer
overflow in the handling of wildcards. This could be exploited to
remotely crash the PHP interpreter. This issue does not affect Ubuntu
7.04. (CVE-2007-1824)

When calling the sqlite_udf_decode_binary() with special arguments, a
buffer overflow happened. Depending on the application this could be
locally or remotely exploited to execute arbitrary code with the
privileges of the PHP interpreter. (CVE-2007-1887 CVE-2007-1888)

The FILTER_VALIDATE_EMAIL filter extension used a wrong regular
expression that allowed injecting a newline character at the end of
the email string. This could be exploited to inject arbitrary email
headers. This issue only affects Ubuntu 7.04. (CVE-2007-1900).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libapache2-mod-php5", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php-pear", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cgi", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cli", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-common", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-curl", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-dev", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-gd", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-ldap", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mhash", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysql", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-mysqli", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-odbc", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-pgsql", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-recode", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-snmp", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sqlite", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-sybase", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xmlrpc", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-xsl", pkgver:"5.1.2-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libapache2-mod-php5", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php-pear", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-cgi", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-cli", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-common", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-curl", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-dev", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-gd", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-ldap", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-mhash", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-mysql", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-mysqli", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-odbc", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-pgsql", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-recode", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-snmp", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-sqlite", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-sybase", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-xmlrpc", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"php5-xsl", pkgver:"5.1.6-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libapache2-mod-php5", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php-pear", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-cgi", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-cli", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-common", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-curl", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-dev", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-gd", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-ldap", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-mhash", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-mysql", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-odbc", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-pgsql", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-pspell", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-recode", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-snmp", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-sqlite", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-sybase", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-tidy", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-xmlrpc", pkgver:"5.2.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"php5-xsl", pkgver:"5.2.1-0ubuntu1.1")) flag++;

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
