#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1088-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52682);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2011-0284");
  script_bugtraq_id(46881);
  script_osvdb_id(71183);
  script_xref(name:"USN", value:"1088-1");

  script_name(english:"Ubuntu 9.10 / 10.04 LTS / 10.10 : krb5 vulnerability (USN-1088-1)");
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
"Cameron Meadors discovered that the MIT Kerberos 5 Key Distribution
Center (KDC) daemon is vulnerable to a double-free condition if the
Public Key Cryptography for Initial Authentication (PKINIT) capability
is enabled. This could allow a remote attacker to cause a denial of
service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-ftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-multidev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-rsh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-telnetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssapi-krb5-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssrpc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libk5crypto3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt-mit7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv-mit7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5support0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/16");
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
if (! ereg(pattern:"^(9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.10", pkgname:"krb5-admin-server", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-clients", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-doc", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-ftpd", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-kdc", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-kdc-ldap", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-pkinit", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-rsh-server", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-telnetd", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-user", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgssapi-krb5-2", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgssrpc4", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libk5crypto3", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkadm5clnt6", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkadm5srv6", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkdb5-4", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5-3", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5-dbg", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5-dev", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5support0", pkgver:"1.7dfsg~beta3-1ubuntu0.12")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-admin-server", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-doc", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-kdc", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-kdc-ldap", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-multidev", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-pkinit", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-user", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libgssapi-krb5-2", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libgssrpc4", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libk5crypto3", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkadm5clnt-mit7", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkadm5srv-mit7", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkdb5-4", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkrb5-3", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkrb5-dbg", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkrb5-dev", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkrb5support0", pkgver:"1.8.1+dfsg-2ubuntu0.8")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-admin-server", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-doc", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-kdc", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-kdc-ldap", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-multidev", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-pkinit", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-user", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libgssapi-krb5-2", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libgssrpc4", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libk5crypto3", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkadm5clnt-mit7", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkadm5srv-mit7", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkdb5-4", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkrb5-3", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkrb5-dbg", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkrb5-dev", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkrb5support0", pkgver:"1.8.1+dfsg-5ubuntu0.6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-admin-server / krb5-clients / krb5-doc / krb5-ftpd / krb5-kdc / etc");
}
