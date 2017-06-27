#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-99-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20726);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/25 16:34:56 $");

  script_cve_id("CVE-2004-1064");
  script_xref(name:"USN", value:"99-2");

  script_name(english:"Ubuntu 4.10 : php4 vulnerabilities (USN-99-2)");
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
"USN-99-1 fixed a safe mode bypass which allowed malicious PHP scripts
to circumvent path restrictions by creating a specially crafted
directory whose length exceeded the capacity of the realpath()
function (CAN-2004-1064). However, this caused severe regressions,
some applications like SquirrelMail and Gallery did not work any more,
and the package 'php4-pear' was empty. The current version repairs
this.

In addition this update fixes a crash of the PHP interpreter if
curl_init() was called with a non-string argument. Please note that
this is not security relevant since this condition usually cannot be
triggered externally.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-cgi");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libapache2-mod-php4", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-cgi", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-curl", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-dev", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-domxml", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-gd", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-ldap", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mcal", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mhash", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mysql", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-odbc", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-pear", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-recode", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-snmp", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-sybase", pkgver:"4.3.8-3ubuntu7.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-xslt", pkgver:"4.3.8-3ubuntu7.6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php4 / php4 / php4-cgi / php4-curl / php4-dev / etc");
}
