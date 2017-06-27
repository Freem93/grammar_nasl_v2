#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-584-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31406);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_cve_id("CVE-2007-6698", "CVE-2008-0658");
  script_osvdb_id(41948, 43306);
  script_xref(name:"USN", value:"584-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : openldap2.2, openldap2.3 vulnerabilities (USN-584-1)");
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
"Jonathan Clarke discovered that the OpenLDAP slapd server did not
properly handle modify requests when using the Berkeley DB backend and
specifying the NOOP control. An authenticated user with modify
permissions could send a crafted modify request and cause a denial of
service via application crash. Ubuntu 7.10 is not affected by this
issue. (CVE-2007-6698)

Ralf Haferkamp discovered that the OpenLDAP slapd server did not
properly handle modrdn requests when using the Berkeley DB backend and
specifying the NOOP control. An authenticated user with modrdn
permissions could send a crafted modrdn request and possibly cause a
denial of service via application crash. (CVE-2007-6698).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ldap-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap-2.2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap-2.3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slapd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/07");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"ldap-utils", pkgver:"2.2.26-5ubuntu2.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libldap-2.2-7", pkgver:"2.2.26-5ubuntu2.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"slapd", pkgver:"2.2.26-5ubuntu2.6")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ldap-utils", pkgver:"2.2.26-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libldap-2.2-7", pkgver:"2.2.26-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"slapd", pkgver:"2.2.26-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ldap-utils", pkgver:"2.3.30-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libldap-2.3-0", pkgver:"2.3.30-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"slapd", pkgver:"2.3.30-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ldap-utils", pkgver:"2.3.35-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libldap-2.3-0", pkgver:"2.3.35-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"slapd", pkgver:"2.3.35-1ubuntu0.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldap-utils / libldap-2.2-7 / libldap-2.3-0 / slapd");
}
