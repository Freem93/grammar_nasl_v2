#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2810-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86872);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2002-2443", "CVE-2014-5355", "CVE-2015-2694", "CVE-2015-2695", "CVE-2015-2696", "CVE-2015-2697", "CVE-2015-2698");
  script_osvdb_id(93240, 118567, 118568, 118569, 118570, 121429, 129480, 129481, 129482, 130191);
  script_xref(name:"USN", value:"2810-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 / 15.10 : krb5 vulnerabilities (USN-2810-1)");
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
"It was discovered that the Kerberos kpasswd service incorrectly
handled certain UDP packets. A remote attacker could possibly use this
issue to cause resource consumption, resulting in a denial of service.
This issue only affected Ubuntu 12.04 LTS. (CVE-2002-2443)

It was discovered that Kerberos incorrectly handled null bytes in
certain data fields. A remote attacker could possibly use this issue
to cause a denial of service. This issue only affected Ubuntu 12.04
LTS and Ubuntu 14.04 LTS. (CVE-2014-5355)

It was discovered that the Kerberos kdcpreauth modules incorrectly
tracked certain client requests. A remote attacker could possibly use
this issue to bypass intended preauthentication requirements. This
issue only affected Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-2694)

It was discovered that Kerberos incorrectly handled certain SPNEGO
packets. A remote attacker could possibly use this issue to cause a
denial of service. (CVE-2015-2695)

It was discovered that Kerberos incorrectly handled certain IAKERB
packets. A remote attacker could possibly use this issue to cause a
denial of service. (CVE-2015-2696, CVE-2015-2698)

It was discovered that Kerberos incorrectly handled certain TGS
requests. A remote attacker could possibly use this issue to cause a
denial of service. (CVE-2015-2697).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-k5tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssapi-krb5-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssrpc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libk5crypto3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt-mit8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt-mit9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrad0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5support0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"krb5-admin-server", pkgver:"1.10+dfsg~beta1-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"krb5-kdc", pkgver:"1.10+dfsg~beta1-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"krb5-kdc-ldap", pkgver:"1.10+dfsg~beta1-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"krb5-pkinit", pkgver:"1.10+dfsg~beta1-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"krb5-user", pkgver:"1.10+dfsg~beta1-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgssapi-krb5-2", pkgver:"1.10+dfsg~beta1-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgssrpc4", pkgver:"1.10+dfsg~beta1-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libk5crypto3", pkgver:"1.10+dfsg~beta1-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libkadm5clnt-mit8", pkgver:"1.10+dfsg~beta1-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libkdb5-6", pkgver:"1.10+dfsg~beta1-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libkrb5-3", pkgver:"1.10+dfsg~beta1-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libkrb53", pkgver:"1.10+dfsg~beta1-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libkrb5support0", pkgver:"1.10+dfsg~beta1-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"krb5-admin-server", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"krb5-kdc", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"krb5-kdc-ldap", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"krb5-otp", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"krb5-pkinit", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"krb5-user", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libgssapi-krb5-2", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libgssrpc4", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libk5crypto3", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libkadm5clnt-mit9", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libkdb5-7", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libkrad0", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libkrb5-3", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libkrb5support0", pkgver:"1.12+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"krb5-admin-server", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"krb5-kdc", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"krb5-kdc-ldap", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"krb5-otp", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"krb5-pkinit", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"krb5-user", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libgssapi-krb5-2", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libgssrpc4", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libk5crypto3", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libkadm5clnt-mit9", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libkdb5-7", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libkrad0", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libkrb5-3", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libkrb5support0", pkgver:"1.12.1+dfsg-18ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"krb5-admin-server", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"krb5-k5tls", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"krb5-kdc", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"krb5-kdc-ldap", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"krb5-otp", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"krb5-pkinit", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"krb5-user", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libgssapi-krb5-2", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libgssrpc4", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libk5crypto3", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libkadm5clnt-mit9", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libkdb5-8", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libkrad0", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libkrb5-3", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libkrb5support0", pkgver:"1.13.2+dfsg-2ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-admin-server / krb5-k5tls / krb5-kdc / krb5-kdc-ldap / etc");
}
