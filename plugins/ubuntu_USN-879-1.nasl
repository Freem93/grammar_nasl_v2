#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-879-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65120);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:45:43 $");

  script_cve_id("CVE-2009-3295");
  script_bugtraq_id(37486);
  script_osvdb_id(61423);
  script_xref(name:"USN", value:"879-1");

  script_name(english:"Ubuntu 9.10 : krb5 vulnerability (USN-879-1)");
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
"Jeff Blaine, Radoslav Bodo, Jakob Haufe, and Jorgen Wahlsten
discovered that the Kerberos Key Distribution Center service did not
correctly verify certain network traffic. An unauthenticated remote
attacker could send a specially crafted request that would cause the
KDC to crash, leading to a denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-ftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-rsh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-telnetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssapi-krb5-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssrpc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libk5crypto3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5support0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.10", pkgname:"krb5-admin-server", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-clients", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-doc", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-ftpd", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-kdc", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-kdc-ldap", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-pkinit", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-rsh-server", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-telnetd", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-user", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgssapi-krb5-2", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgssrpc4", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libk5crypto3", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkadm5clnt6", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkadm5srv6", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkdb5-4", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5-3", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5-dbg", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5-dev", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5support0", pkgver:"1.7dfsg~beta3-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-admin-server / krb5-clients / krb5-doc / krb5-ftpd / krb5-kdc / etc");
}
