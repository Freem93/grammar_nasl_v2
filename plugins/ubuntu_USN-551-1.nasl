#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-551-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29215);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_cve_id("CVE-2007-5707", "CVE-2007-5708");
  script_bugtraq_id(26245);
  script_osvdb_id(38484, 38485);
  script_xref(name:"USN", value:"551-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : openldap vulnerabilities (USN-551-1)");
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
"Thomas Sesselmann discovered that the OpenLDAP slapd server did not
properly handle certain modify requests. A remote attacker could send
malicious modify requests to the server and cause a denial of service.
(CVE-2007-5707)

Toby Blake discovered that slapd did not properly terminate an array
while running as a proxy-caching server. A remote attacker may be able
to send crafted search requests to the server and cause a denial of
service. This issue only affects Ubuntu 7.04 and 7.10. (CVE-2007-5708).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/26");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"ldap-utils", pkgver:"2.2.26-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libldap-2.2-7", pkgver:"2.2.26-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"slapd", pkgver:"2.2.26-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ldap-utils", pkgver:"2.2.26-5ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libldap-2.2-7", pkgver:"2.2.26-5ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"slapd", pkgver:"2.2.26-5ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ldap-utils", pkgver:"2.3.30-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libldap-2.3-0", pkgver:"2.3.30-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"slapd", pkgver:"2.3.30-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ldap-utils", pkgver:"2.3.35-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libldap-2.3-0", pkgver:"2.3.35-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"slapd", pkgver:"2.3.35-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldap-utils / libldap-2.2-7 / libldap-2.3-0 / slapd");
}
