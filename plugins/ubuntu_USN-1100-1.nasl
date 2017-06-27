#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1100-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53257);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2011-1024", "CVE-2011-1025", "CVE-2011-1081");
  script_bugtraq_id(46363, 46831);
  script_osvdb_id(72528, 72529, 72530);
  script_xref(name:"USN", value:"1100-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : openldap, openldap2.3 vulnerabilities (USN-1100-1)");
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
"It was discovered that OpenLDAP did not properly check forwarded
authentication failures when using a slave server and chain overlay.
If OpenLDAP were configured in this manner, an attacker could bypass
authentication checks by sending an invalid password to a slave
server. (CVE-2011-1024)

It was discovered that OpenLDAP did not properly perform
authentication checks to the rootdn when using the back-ndb backend.
An attacker could exploit this to access the directory by sending an
arbitrary password. Ubuntu does not ship OpenLDAP with back-ndb
support by default. This issue did not affect Ubuntu 8.04 LTS.
(CVE-2011-1025)

It was discovered that OpenLDAP did not properly validate modrdn
requests. An unauthenticated remote user could use this to cause a
denial of service via application crash. (CVE-2011-1081).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ldap-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap-2.4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap-2.4-2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slapd-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"ldap-utils", pkgver:"2.4.9-0ubuntu0.8.04.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libldap-2.4-2", pkgver:"2.4.9-0ubuntu0.8.04.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libldap-2.4-2-dbg", pkgver:"2.4.9-0ubuntu0.8.04.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libldap2-dev", pkgver:"2.4.9-0ubuntu0.8.04.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"slapd", pkgver:"2.4.9-0ubuntu0.8.04.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"slapd-dbg", pkgver:"2.4.9-0ubuntu0.8.04.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ldap-utils", pkgver:"2.4.18-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libldap-2.4-2", pkgver:"2.4.18-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libldap-2.4-2-dbg", pkgver:"2.4.18-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libldap2-dev", pkgver:"2.4.18-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"slapd", pkgver:"2.4.18-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"slapd-dbg", pkgver:"2.4.18-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ldap-utils", pkgver:"2.4.21-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libldap-2.4-2", pkgver:"2.4.21-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libldap-2.4-2-dbg", pkgver:"2.4.21-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libldap2-dev", pkgver:"2.4.21-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"slapd", pkgver:"2.4.21-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"slapd-dbg", pkgver:"2.4.21-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"ldap-utils", pkgver:"2.4.23-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libldap-2.4-2", pkgver:"2.4.23-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libldap-2.4-2-dbg", pkgver:"2.4.23-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libldap2-dev", pkgver:"2.4.23-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"slapd", pkgver:"2.4.23-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"slapd-dbg", pkgver:"2.4.23-0ubuntu3.5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldap-utils / libldap-2.4-2 / libldap-2.4-2-dbg / libldap2-dev / etc");
}
