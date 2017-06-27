#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-232-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20776);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2005-3319", "CVE-2005-3353", "CVE-2005-3388", "CVE-2005-3389", "CVE-2005-3390", "CVE-2005-3391", "CVE-2005-3392", "CVE-2005-3883");
  script_bugtraq_id(15248, 15249, 15250);
  script_osvdb_id(20406, 20407, 20408, 20491, 20897, 20898, 21239, 21492);
  script_xref(name:"USN", value:"232-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : php4, php5 vulnerabilities (USN-232-1)");
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
"Eric Romang discovered a local Denial of Service vulnerability in the
handling of the 'session.save_path' parameter in PHP's Apache 2.0
module. By setting this parameter to an invalid value in an .htaccess
file, a local user could crash the Apache server. (CVE-2005-3319)

A Denial of Service flaw was found in the EXIF module. By sending an
image with specially crafted EXIF data to a PHP program that
automatically evaluates them (e. g. a web gallery), a remote attacker
could cause an infinite recursion in the PHP interpreter, which caused
the web server to crash. (CVE-2005-3353)

Stefan Esser reported a Cross Site Scripting vulnerability in the
phpinfo() function. By tricking a user into retrieving a specially
crafted URL to a PHP page that exposes phpinfo(), a remote attacker
could inject arbitrary HTML or web script into the output page and
possibly steal private data like cookies or session identifiers.
(CVE-2005-3388)

Stefan Esser discovered a vulnerability of the parse_str() function
when it is called with just one argument. By calling such programs
with specially crafted parameters, a remote attacker could enable the
'register_globals' option which is normally turned off for security
reasons. Once this option is enabled, the remote attacker could
exploit other security flaws of PHP programs which are normally
protected by 'register_globals' being deactivated. (CVE-2005-3389)

Stefan Esser discovered that a remote attacker could overwrite the
$GLOBALS array in PHP programs that allow file uploads and run with
'register_globals' enabled. Depending on the particular application,
this can lead to unexpected vulnerabilities. (CVE-2005-3390)

The 'gd' image processing and cURL modules did not properly check
processed file names against the 'open_basedir' and 'safe_mode'
restrictions, which could be exploited to circumvent these
limitations. (CVE-2005-3391)

Another bypass of the 'open_basedir' and 'safe_mode' restrictions was
found in virtual() function. A local attacker could exploit this to
circumvent these restrictions with specially crafted PHP INI files
when virtual Apache 2.0 hosts are used. (CVE-2005-3392)

The mb_send_mail() function did not properly check its arguments for
invalid embedded line breaks. By setting the 'To:' field of an email
to a specially crafted value in a PHP web mail application, a remote
attacker could inject arbitrary headers into the sent email.
(CVE-2005-3883).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache-mod-php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-domxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-mcal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-mhash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-universe-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-xslt");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libapache2-mod-php4", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-cgi", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-curl", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-dev", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-domxml", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-gd", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-ldap", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mcal", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mhash", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mysql", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-odbc", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-pear", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-recode", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-snmp", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-sybase", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-xslt", pkgver:"4.3.8-3ubuntu7.14")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libapache-mod-php4", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libapache2-mod-php4", pkgver:"4.3.10-10ubuntu4.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4", pkgver:"4.3.10-10ubuntu4.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-cgi", pkgver:"4.3.10-10ubuntu4.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-cli", pkgver:"4.3.10-10ubuntu4.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-common", pkgver:"4.3.10-10ubuntu4.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-curl", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-dev", pkgver:"4.3.10-10ubuntu4.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-domxml", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-gd", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-imap", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-ldap", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-mcal", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-mhash", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-mysql", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-odbc", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-pear", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-recode", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-snmp", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-sybase", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-universe-common", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-xslt", pkgver:"4.3.10-10ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libapache-mod-php4", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libapache2-mod-php4", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libapache2-mod-php5", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php-pear", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-cgi", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-cli", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-common", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-curl", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-dev", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-domxml", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-gd", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-ldap", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-mcal", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-mhash", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-mysql", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-odbc", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-pear", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-pgsql", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-recode", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-snmp", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-sybase", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php4-xslt", pkgver:"4.4.0-3ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-cgi", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-cli", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-common", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-curl", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-dev", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-gd", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-ldap", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-mhash", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-mysql", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-odbc", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-pgsql", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-recode", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-snmp", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-sqlite", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-sybase", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-xmlrpc", pkgver:"5.0.5-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-xsl", pkgver:"5.0.5-2ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache-mod-php4 / libapache2-mod-php4 / libapache2-mod-php5 / etc");
}
