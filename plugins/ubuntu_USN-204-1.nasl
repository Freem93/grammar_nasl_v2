#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-204-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20620);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/26 16:22:49 $");

  script_cve_id("CVE-2005-2969");
  script_osvdb_id(19919);
  script_xref(name:"USN", value:"204-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : openssl vulnerability (USN-204-1)");
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
"Yutaka Oiwa discovered a possible cryptographic weakness in OpenSSL
applications. Applications using the OpenSSL library can use the
SSL_OP_MSIE_SSLV2_RSA_PADDING option (or SSL_OP_ALL, which implies the
former) to maintain compatibility with third-party products, which is
achieved by working around known bugs in them.

The SSL_OP_MSIE_SSLV2_RSA_PADDING option disabled a verification step
in the SSL 2.0 server supposed to prevent active protocol-version
rollback attacks. With this verification step disabled, an attacker
acting as a 'man in the middle' could force a client and a server to
negotiate the SSL 2.0 protocol even if these parties both supported
SSL 3.0 or TLS 1.0. The SSL 2.0 protocol is known to have severe
cryptographic weaknesses and is supported as a fallback only.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libssl-dev, libssl0.9.7 and / or openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libssl-dev", pkgver:"0.9.7d-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libssl0.9.7", pkgver:"0.9.7d-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"openssl", pkgver:"0.9.7d-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libssl-dev", pkgver:"0.9.7e-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libssl0.9.7", pkgver:"0.9.7e-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openssl", pkgver:"0.9.7e-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libssl-dev", pkgver:"0.9.7g-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libssl0.9.7", pkgver:"0.9.7g-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openssl", pkgver:"0.9.7g-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssl-dev / libssl0.9.7 / openssl");
}
