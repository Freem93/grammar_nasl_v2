#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-549-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29213);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2007-1285", "CVE-2007-2872", "CVE-2007-3799", "CVE-2007-3998", "CVE-2007-4657", "CVE-2007-4658", "CVE-2007-4660", "CVE-2007-4661", "CVE-2007-4662", "CVE-2007-4670", "CVE-2007-5898", "CVE-2007-5899");
  script_bugtraq_id(22764, 24261, 24268, 25498, 26403);
  script_osvdb_id(36855, 45874, 58616);
  script_xref(name:"USN", value:"549-2");

  script_name(english:"Ubuntu 7.10 : php5 regression (USN-549-2)");
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
"USN-549-1 fixed vulnerabilities in PHP. However, some upstream changes
were incomplete, which caused crashes in certain situations with
Ubuntu 7.10. This update fixes the problem.

We apologize for the inconvenience.

It was discovered that the wordwrap function did not correctly check
lengths. Remote attackers could exploit this to cause a crash or
monopolize CPU resources, resulting in a denial of service.
(CVE-2007-3998)

Integer overflows were discovered in the strspn and strcspn
functions. Attackers could exploit this to read arbitrary
areas of memory, possibly gaining access to sensitive
information. (CVE-2007-4657)

Stanislav Malyshev discovered that money_format function did
not correctly handle certain tokens. If a PHP application
were tricked into processing a bad format string, a remote
attacker could execute arbitrary code with application
privileges. (CVE-2007-4658)

It was discovered that the php_openssl_make_REQ function did
not correctly check buffer lengths. A remote attacker could
send a specially crafted message and execute arbitrary code
with application privileges. (CVE-2007-4662)

It was discovered that certain characters in session cookies
were not handled correctly. A remote attacker could
injection values which could lead to altered application
behavior, potentially gaining additional privileges.
(CVE-2007-3799)

Gerhard Wagner discovered that the chunk_split function did
not correctly handle long strings. A remote attacker could
exploit this to execute arbitrary code with application
privileges. (CVE-2007-2872, CVE-2007-4660, CVE-2007-4661)

Stefan Esser discovered that deeply nested arrays could be
made to fill stack space. A remote attacker could exploit
this to cause a crash or monopolize CPU resources, resulting
in a denial of service. (CVE-2007-1285, CVE-2007-4670)

Rasmus Lerdorf discovered that the htmlentities and
htmlspecialchars functions did not correctly stop when
handling partial multibyte sequences. A remote attacker
could exploit this to read certain areas of memory, possibly
gaining access to sensitive information. (CVE-2007-5898)

It was discovered that the output_add_rewrite_var fucntion
would sometimes leak session id information to forms
targeting remote URLs. Malicious remote sites could use this
information to gain access to a PHP application user's login
credentials. (CVE-2007-5899).

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
  script_cwe_id(20, 119, 189, 200, 399);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/01");
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
if (! ereg(pattern:"^(7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.10", pkgname:"libapache2-mod-php5", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php-pear", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-cgi", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-cli", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-common", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-curl", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-dev", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-gd", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-ldap", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-mhash", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-mysql", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-odbc", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-pgsql", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-pspell", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-recode", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-snmp", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-sqlite", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-sybase", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-tidy", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-xmlrpc", pkgver:"5.2.3-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"php5-xsl", pkgver:"5.2.3-1ubuntu6.2")) flag++;

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
