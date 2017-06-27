#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1520-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61379);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/25 16:19:24 $");

  script_cve_id("CVE-2012-1012", "CVE-2012-1013", "CVE-2012-1014", "CVE-2012-1015");
  script_bugtraq_id(53784);
  script_osvdb_id(82650, 82816, 84423, 84424);
  script_xref(name:"USN", value:"1520-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : krb5 vulnerabilities (USN-1520-1)");
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
"Emmanuel Bouillon discovered that the MIT krb5 Key Distribution Center
(KDC) daemon could free an uninitialized pointer when handling a
malformed AS-REQ message. A remote unauthenticated attacker could use
this to cause a denial of service or possibly execute arbitrary code.
(CVE-2012-1015)

Emmanuel Bouillon discovered that the MIT krb5 Key Distribution Center
(KDC) daemon could dereference an uninitialized pointer while handling
a malformed AS-REQ message. A remote unauthenticated attacker could
use this to cause a denial of service or possibly execute arbitrary
code. This issue only affected Ubuntu 12.04 LTS. (CVE-2012-1014)

Simo Sorce discovered that the MIT krb5 Key Distribution Center (KDC)
daemon could dereference a NULL pointer when handling a malformed
TGS-REQ message. A remote authenticated attacker could use this to
cause a denial of service. (CVE-2012-1013)

It was discovered that the kadmin protocol implementation in MIT krb5
did not properly restrict access to the SET_STRING and GET_STRINGS
operations. A remote authenticated attacker could use this to expose
or modify sensitive information. This issue only affected Ubuntu 12.04
LTS. (CVE-2012-1012).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected krb5-admin-server, krb5-kdc and / or krb5-kdc-ldap
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"krb5-admin-server", pkgver:"1.8.1+dfsg-2ubuntu0.11")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-kdc", pkgver:"1.8.1+dfsg-2ubuntu0.11")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-kdc-ldap", pkgver:"1.8.1+dfsg-2ubuntu0.11")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"krb5-admin-server", pkgver:"1.8.3+dfsg-5ubuntu2.3")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"krb5-kdc", pkgver:"1.8.3+dfsg-5ubuntu2.3")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"krb5-kdc-ldap", pkgver:"1.8.3+dfsg-5ubuntu2.3")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"krb5-admin-server", pkgver:"1.9.1+dfsg-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"krb5-kdc", pkgver:"1.9.1+dfsg-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"krb5-kdc-ldap", pkgver:"1.9.1+dfsg-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"krb5-admin-server", pkgver:"1.10+dfsg~beta1-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"krb5-kdc", pkgver:"1.10+dfsg~beta1-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"krb5-kdc-ldap", pkgver:"1.10+dfsg~beta1-2ubuntu0.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-admin-server / krb5-kdc / krb5-kdc-ldap");
}
