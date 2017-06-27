#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1233-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56556);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/26 16:22:49 $");

  script_cve_id("CVE-2011-1527", "CVE-2011-1528", "CVE-2011-1529");
  script_bugtraq_id(50273);
  script_xref(name:"USN", value:"1233-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 / 11.04 / 11.10 : krb5 vulnerabilities (USN-1233-1)");
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
"Nalin Dahyabhai, Andrej Ota and Kyle Moffett discovered a NULL pointer
dereference in the KDC LDAP backend. An unauthenticated remote
attacker could use this to cause a denial of service. This issue
affected Ubuntu 11.10. (CVE-2011-1527)

Mark Deneen discovered that an assert() could be triggered in the
krb5_ldap_lockout_audit() function in the KDC LDAP backend and the
krb5_db2_lockout_audit() function in the KDC DB2 backend. An
unauthenticated remote attacker could use this to cause a denial of
service. (CVE-2011-1528)

It was discovered that a NULL pointer dereference could occur in the
lookup_lockout_policy() function in the KDC LDAP and DB2 backends. An
unauthenticated remote attacker could use this to cause a denial of
service. (CVE-2011-1529).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected krb5-kdc and / or krb5-kdc-ldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/19");
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
if (! ereg(pattern:"^(10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"krb5-kdc", pkgver:"1.8.1+dfsg-2ubuntu0.10")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-kdc-ldap", pkgver:"1.8.1+dfsg-2ubuntu0.10")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-kdc", pkgver:"1.8.1+dfsg-5ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-kdc-ldap", pkgver:"1.8.1+dfsg-5ubuntu0.8")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"krb5-kdc", pkgver:"1.8.3+dfsg-5ubuntu2.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"krb5-kdc-ldap", pkgver:"1.8.3+dfsg-5ubuntu2.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"krb5-kdc", pkgver:"1.9.1+dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"krb5-kdc-ldap", pkgver:"1.9.1+dfsg-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-kdc / krb5-kdc-ldap");
}
