#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-171-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20578);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2005-1751", "CVE-2005-1759", "CVE-2005-2498");
  script_xref(name:"USN", value:"171-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : php4 vulnerabilities (USN-171-1)");
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
"CAN-2005-1751 :

The php4-dev package ships a copy of the 'shtool' utility in
/usr/lib/php4/build/, which provides useful functionality for
developers of software packages. Eric Romang discovered that shtool
created temporary files in an insecure manner. This could allow a
symlink attack to create or overwrite arbitrary files with the
privileges of the user invoking the shtool program.

CAN-1005-1759 :

The creation of temporary files in shtool was also vulnerable to a
race condition which allowed a local user to read the contents of the
temporary file. However, this file does not usually contain sensitive
information since shtool is usually used for building software
packages.

CAN-2005-2498 :

Stefan Esser discovered another remote code execution vulnerability in
the XMLRPC module of the PEAR (PHP Extension and Application
Repository) extension of PHP. By sending specially crafted XMLRPC
requests to an affected web server, a remote attacker could exploit
this to execute arbitrary code with the web server's privileges.

In Ubuntu, the PEAR extension is unsupported (it is
contained in the php4-pear package which is part of
universe). However, since this is a highly critical
vulnerability, that package was fixed anyway.

Please note that many applications contain a copy of the
affected XMLRPC code, which must be fixed separately. The
following packages may also be affected, but are unsupported
in Ubuntu :

  - drupal - wordpress - phpwiki - horde3 - ewiki -
    egroupware - phpgroupware

    These packages might be fixed by the community later.

    The following common third-party applications might be
    affected as well, but not packaged for Ubuntu :

  - Serendipity - Postnuke - tikiwiki - phpwebsite

    If you run any affected software, please check whether
    you are affected and upgrade it as soon as possible to
    protect your server.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache-mod-php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php4");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-universe-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php4-xslt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/20");
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
if (! ereg(pattern:"^(4\.10|5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libapache2-mod-php4", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-cgi", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-curl", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-dev", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-domxml", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-gd", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-ldap", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mcal", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mhash", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-mysql", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-odbc", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-pear", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-recode", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-snmp", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-sybase", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"php4-xslt", pkgver:"4.3.8-3ubuntu7.12")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libapache-mod-php4", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libapache2-mod-php4", pkgver:"4.3.10-10ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4", pkgver:"4.3.10-10ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-cgi", pkgver:"4.3.10-10ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-cli", pkgver:"4.3.10-10ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-common", pkgver:"4.3.10-10ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-curl", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-dev", pkgver:"4.3.10-10ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-domxml", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-gd", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-imap", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-ldap", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-mcal", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-mhash", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-mysql", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-odbc", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-pear", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-recode", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-snmp", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-sybase", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-universe-common", pkgver:"4.3.10-10ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"php4-xslt", pkgver:"4.3.10-10ubuntu3.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache-mod-php4 / libapache2-mod-php4 / php4 / php4-cgi / etc");
}
