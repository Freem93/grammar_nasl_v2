#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2459-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80471);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/24 17:37:07 $");

  script_cve_id("CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206");
  script_bugtraq_id(71935, 71936, 71937, 71939, 71940, 71941, 71942);
  script_osvdb_id(116790, 116791, 116792, 116793, 116794, 116795, 116796);
  script_xref(name:"USN", value:"2459-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 14.04 LTS / 14.10 : openssl vulnerabilities (USN-2459-1) (FREAK)");
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
"Pieter Wuille discovered that OpenSSL incorrectly handled Bignum
squaring. (CVE-2014-3570)

Markus Stenberg discovered that OpenSSL incorrectly handled certain
crafted DTLS messages. A remote attacker could use this issue to cause
OpenSSL to crash, resulting in a denial of service. (CVE-2014-3571)

Karthikeyan Bhargavan discovered that OpenSSL incorrectly handled
certain handshakes. A remote attacker could possibly use this issue to
downgrade to ECDH, removing forward secrecy from the ciphersuite.
(CVE-2014-3572)

Antti Karjalainen, Tuomo Untinen and Konrad Kraszewski discovered that
OpenSSL incorrectly handled certain certificate fingerprints. A remote
attacker could possibly use this issue to trick certain applications
that rely on the uniqueness of fingerprints. (CVE-2014-8275)

Karthikeyan Bhargavan discovered that OpenSSL incorrectly handled
certain key exchanges. A remote attacker could possibly use this issue
to downgrade the security of the session to EXPORT_RSA.
(CVE-2015-0204)

Karthikeyan Bhargavan discovered that OpenSSL incorrectly handled
client authentication. A remote attacker could possibly use this issue
to authenticate without the use of a private key in certain limited
scenarios. This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10.
(CVE-2015-0205)

Chris Mueller discovered that OpenSSL incorrect handled memory when
processing DTLS records. A remote attacker could use this issue to
cause OpenSSL to consume resources, resulting in a denial of service.
This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu
14.10. (CVE-2015-0206).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libssl0.9.8 and / or libssl1.0.0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");
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
if (! ereg(pattern:"^(10\.04|12\.04|14\.04|14\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 14.04 / 14.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libssl0.9.8", pkgver:"0.9.8k-7ubuntu8.23")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libssl1.0.0", pkgver:"1.0.1-4ubuntu5.21")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libssl1.0.0", pkgver:"1.0.1f-1ubuntu2.8")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"libssl1.0.0", pkgver:"1.0.1f-1ubuntu9.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssl0.9.8 / libssl1.0.0");
}
