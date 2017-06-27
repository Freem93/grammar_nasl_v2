#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1030-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51116);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

  script_cve_id("CVE-2010-1323", "CVE-2010-1324", "CVE-2010-4020", "CVE-2010-4021");
  script_bugtraq_id(45116, 45117, 45118, 45122);
  script_osvdb_id(69607, 69608, 69609, 69610);
  script_xref(name:"USN", value:"1030-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : krb5 vulnerabilities (USN-1030-1)");
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
"It was discovered that Kerberos did not properly determine the
acceptability of certain checksums. A remote attacker could use
certain checksums to alter the prompt message, modify a response to a
Key Distribution Center (KDC) or forge a KRB-SAFE message.
(CVE-2010-1323)

It was discovered that Kerberos did not properly determine the
acceptability of certain checksums. A remote attacker could use
certain checksums to forge GSS tokens or gain privileges. This issue
only affected Ubuntu 9.10, 10.04 LTS and 10.10. (CVE-2010-1324)

It was discovered that Kerberos did not reject RC4 key-derivation
checksums. An authenticated remote user could use this issue to forge
AD-SIGNEDPATH or AD-KDC-ISSUED signatures and possibly gain
privileges. This issue only affected Ubuntu 10.04 LTS and 10.10.
(CVE-2010-4020)

It was discovered that Kerberos did not properly restrict the use of
TGT credentials for armoring TGS requests. A remote authenticated user
could use this flaw to impersonate a client. This issue only affected
Ubuntu 9.10. (CVE-2010-4021).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt-mit7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv-mit7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5support0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/10");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"krb5-admin-server", pkgver:"1.4.3-5ubuntu0.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-clients", pkgver:"1.4.3-5ubuntu0.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-doc", pkgver:"1.4.3-5ubuntu0.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-ftpd", pkgver:"1.4.3-5ubuntu0.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-kdc", pkgver:"1.4.3-5ubuntu0.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-rsh-server", pkgver:"1.4.3-5ubuntu0.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-telnetd", pkgver:"1.4.3-5ubuntu0.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-user", pkgver:"1.4.3-5ubuntu0.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkadm55", pkgver:"1.4.3-5ubuntu0.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkrb5-dev", pkgver:"1.4.3-5ubuntu0.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkrb53", pkgver:"1.4.3-5ubuntu0.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-admin-server", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-clients", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-doc", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-ftpd", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-kdc", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-pkinit", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-rsh-server", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-telnetd", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-user", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkadm55", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkrb5-dbg", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkrb5-dev", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkrb53", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-admin-server", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-clients", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-doc", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-ftpd", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-kdc", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-kdc-ldap", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-pkinit", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-rsh-server", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-telnetd", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-user", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgssapi-krb5-2", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgssrpc4", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libk5crypto3", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkadm5clnt6", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkadm5srv6", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkdb5-4", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5-3", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5-dbg", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5-dev", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5support0", pkgver:"1.7dfsg~beta3-1ubuntu0.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-admin-server", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-doc", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-kdc", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-kdc-ldap", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-multidev", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-pkinit", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krb5-user", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libgssapi-krb5-2", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libgssrpc4", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libk5crypto3", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkadm5clnt-mit7", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkadm5srv-mit7", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkdb5-4", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkrb5-3", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkrb5-dbg", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkrb5-dev", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkrb5support0", pkgver:"1.8.1+dfsg-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-admin-server", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-doc", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-kdc", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-kdc-ldap", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-multidev", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-pkinit", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"krb5-user", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libgssapi-krb5-2", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libgssrpc4", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libk5crypto3", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkadm5clnt-mit7", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkadm5srv-mit7", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkdb5-4", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkrb5-3", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkrb5-dbg", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkrb5-dev", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libkrb5support0", pkgver:"1.8.1+dfsg-5ubuntu0.2")) flag++;

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
