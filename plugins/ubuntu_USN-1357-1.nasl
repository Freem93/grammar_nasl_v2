#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1357-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57887);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/25 16:11:45 $");

  script_cve_id("CVE-2011-1945", "CVE-2011-3210", "CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4354", "CVE-2011-4576", "CVE-2011-4577", "CVE-2011-4619", "CVE-2012-0027", "CVE-2012-0050");
  script_bugtraq_id(47888, 49471, 50882, 51281, 51563);
  script_osvdb_id(74632, 75230, 77650, 78186, 78187, 78188, 78189, 78190, 78191, 78320);
  script_xref(name:"USN", value:"1357-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 / 11.10 : openssl vulnerabilities (USN-1357-1)");
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
"It was discovered that the elliptic curve cryptography (ECC) subsystem
in OpenSSL, when using the Elliptic Curve Digital Signature Algorithm
(ECDSA) for the ECDHE_ECDSA cipher suite, did not properly implement
curves over binary fields. This could allow an attacker to determine
private keys via a timing attack. This issue only affected Ubuntu 8.04
LTS, Ubuntu 10.04 LTS, Ubuntu 10.10 and Ubuntu 11.04. (CVE-2011-1945)

Adam Langley discovered that the ephemeral Elliptic Curve
Diffie-Hellman (ECDH) functionality in OpenSSL did not ensure thread
safety while processing handshake messages from clients. This could
allow a remote attacker to cause a denial of service via out-of-order
messages that violate the TLS protocol. This issue only affected
Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10 and Ubuntu 11.04.
(CVE-2011-3210)

Nadhem Alfardan and Kenny Paterson discovered that the Datagram
Transport Layer Security (DTLS) implementation in OpenSSL performed a
MAC check only if certain padding is valid. This could allow a remote
attacker to recover plaintext. (CVE-2011-4108)

Antonio Martin discovered that a flaw existed in the fix to address
CVE-2011-4108, the DTLS MAC check failure. This could allow a remote
attacker to cause a denial of service. (CVE-2012-0050)

Ben Laurie discovered a double free vulnerability in OpenSSL that
could be triggered when the X509_V_FLAG_POLICY_CHECK flag is enabled.
This could allow a remote attacker to cause a denial of service. This
issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10
and Ubuntu 11.04. (CVE-2011-4109)

It was discovered that OpenSSL, in certain circumstances involving
ECDH or ECDHE cipher suites, used an incorrect modular reduction
algorithm in its implementation of the P-256 and P-384 NIST elliptic
curves. This could allow a remote attacker to obtain the private key
of a TLS server via multiple handshake attempts. This issue only
affected Ubuntu 8.04 LTS. (CVE-2011-4354)

Adam Langley discovered that the SSL 3.0 implementation in OpenSSL did
not properly initialize data structures for block cipher padding. This
could allow a remote attacker to obtain sensitive information.
(CVE-2011-4576)

Andrew Chi discovered that OpenSSL, when RFC 3779 support is enabled,
could trigger an assert when handling an X.509 certificate containing
certificate-extension data associated with IP address blocks or
Autonomous System (AS) identifiers. This could allow a remote attacker
to cause a denial of service. (CVE-2011-4577)

Adam Langley discovered that the Server Gated Cryptography (SGC)
implementation in OpenSSL did not properly handle handshake restarts.
This could allow a remote attacker to cause a denial of service.
(CVE-2011-4619)

Andrey Kulikov discovered that the GOST block cipher engine in OpenSSL
did not properly handle invalid parameters. This could allow a remote
attacker to cause a denial of service via crafted data from a TLS
client. This issue only affected Ubuntu 11.10. (CVE-2012-0027).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libssl0.9.8, libssl1.0.0 and / or openssl
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/10");
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
if (! ereg(pattern:"^(8\.04|10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libssl0.9.8", pkgver:"0.9.8g-4ubuntu3.15")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openssl", pkgver:"0.9.8g-4ubuntu3.15")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libssl0.9.8", pkgver:"0.9.8k-7ubuntu8.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openssl", pkgver:"0.9.8k-7ubuntu8.8")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libssl0.9.8", pkgver:"0.9.8o-1ubuntu4.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openssl", pkgver:"0.9.8o-1ubuntu4.6")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libssl0.9.8", pkgver:"0.9.8o-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openssl", pkgver:"0.9.8o-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libssl1.0.0", pkgver:"1.0.0e-2ubuntu4.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openssl", pkgver:"1.0.0e-2ubuntu4.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssl0.9.8 / libssl1.0.0 / openssl");
}
