#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-261-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21068);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2006-0207", "CVE-2006-0208");
  script_bugtraq_id(16220);
  script_osvdb_id(22478, 22480);
  script_xref(name:"USN", value:"261-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : php4, php5 vulnerabilities (USN-261-1)");
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
"Stefan Esser discovered that the 'session' module did not sufficiently
verify the validity of the user-supplied session ID. A remote attacker
could exploit this to insert arbitrary HTTP headers into the response
sent by the PHP application, which could lead to HTTP Response
Splitting (forging of arbitrary responses on behalf the PHP
application) and Cross Site Scripting (XSS) (execution of arbitrary
web script code in the client's browser) attacks. (CVE-2006-0207)

PHP applications were also vulnerable to several Cross Site Scripting
(XSS) flaws if the options 'display_errors' and 'html_errors' were
enabled. Please note that enabling 'html_errors' is not recommended
for production systems. (CVE-2006-0208).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-mcal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-mhash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-sybase");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"4.10", pkgname:"libapache2-mod-php4", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-cgi", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-curl", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-dev", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-domxml", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-gd", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-ldap", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mcal", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mhash", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mysql", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-odbc", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-pear", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-recode", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-snmp", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-sybase", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-xslt", pkgver:"4.3.8-3ubuntu7.15")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libapache2-mod-php4", pkgver:"4.3.10-10ubuntu4.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4", pkgver:"4.3.10-10ubuntu4.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-cgi", pkgver:"4.3.10-10ubuntu4.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-cli", pkgver:"4.3.10-10ubuntu4.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-common", pkgver:"4.3.10-10ubuntu4.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-dev", pkgver:"4.3.10-10ubuntu4.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libapache2-mod-php5", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php-pear", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-cgi", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-cli", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-common", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-curl", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-dev", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-gd", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-ldap", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-mhash", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-mysql", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-odbc", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-pgsql", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-recode", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-snmp", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-sqlite", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-sybase", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-xmlrpc", pkgver:"5.0.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"php5-xsl", pkgver:"5.0.5-2ubuntu1.2")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
