#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-965-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48282);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2010-0211", "CVE-2010-0212");
  script_bugtraq_id(41770);
  script_osvdb_id(66469, 66470);
  script_xref(name:"USN", value:"965-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.04 / 9.10 / 10.04 LTS : openldap, openldap2.2, openldap2.3 vulnerabilities (USN-965-1)");
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
"Using the Codenomicon LDAPv3 test suite, Ilkka Mattila and Tuomas
Salomaki discovered that the slap_modrdn2mods function in modrdn.c in
OpenLDAP does not check the return value from a call to the
smr_normalize function. A remote attacker could use specially crafted
modrdn requests to crash the slapd daemon or possibly execute
arbitrary code. (CVE-2010-0211)

Using the Codenomicon LDAPv3 test suite, Ilkka Mattila and Tuomas
Salomaki discovered that OpenLDAP does not properly handle empty RDN
strings. A remote attacker could use specially crafted modrdn requests
to crash the slapd daemon. (CVE-2010-0212)

In the default installation under Ubuntu 8.04 LTS and later, attackers
would be isolated by the OpenLDAP AppArmor profile for the slapd
daemon.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ldap-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap-2.2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap-2.4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap-2.4-2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slapd-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/10");
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

if (ubuntu_check(osver:"6.06", pkgname:"ldap-utils", pkgver:"2.2.26-5ubuntu2.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libldap-2.2-7", pkgver:"2.2.26-5ubuntu2.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"slapd", pkgver:"2.2.26-5ubuntu2.10")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ldap-utils", pkgver:"2.4.9-0ubuntu0.8.04.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libldap-2.4-2", pkgver:"2.4.9-0ubuntu0.8.04.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libldap-2.4-2-dbg", pkgver:"2.4.9-0ubuntu0.8.04.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libldap2-dev", pkgver:"2.4.9-0ubuntu0.8.04.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"slapd", pkgver:"2.4.9-0ubuntu0.8.04.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"slapd-dbg", pkgver:"2.4.9-0ubuntu0.8.04.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ldap-utils", pkgver:"2.4.15-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libldap-2.4-2", pkgver:"2.4.15-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libldap-2.4-2-dbg", pkgver:"2.4.15-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libldap2-dev", pkgver:"2.4.15-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"slapd", pkgver:"2.4.15-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"slapd-dbg", pkgver:"2.4.15-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ldap-utils", pkgver:"2.4.18-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libldap-2.4-2", pkgver:"2.4.18-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libldap-2.4-2-dbg", pkgver:"2.4.18-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libldap2-dev", pkgver:"2.4.18-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"slapd", pkgver:"2.4.18-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"slapd-dbg", pkgver:"2.4.18-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ldap-utils", pkgver:"2.4.21-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libldap-2.4-2", pkgver:"2.4.21-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libldap-2.4-2-dbg", pkgver:"2.4.21-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libldap2-dev", pkgver:"2.4.21-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"slapd", pkgver:"2.4.21-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"slapd-dbg", pkgver:"2.4.21-0ubuntu5.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldap-utils / libldap-2.2-7 / libldap-2.4-2 / libldap-2.4-2-dbg / etc");
}
