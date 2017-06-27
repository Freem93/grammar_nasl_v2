#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2308-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77085);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508", "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3511", "CVE-2014-3512", "CVE-2014-5139");
  script_bugtraq_id(69075, 69076, 69077, 69078, 69079, 69081, 69082, 69083, 69084);
  script_osvdb_id(109891, 109892, 109893, 109894, 109895, 109896, 109897, 109898, 109902);
  script_xref(name:"USN", value:"2308-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 14.04 LTS : openssl vulnerabilities (USN-2308-1)");
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
"Adam Langley and Wan-Teh Chang discovered that OpenSSL incorrectly
handled certain DTLS packets. A remote attacker could use this issue
to cause OpenSSL to crash, resulting in a denial of service.
(CVE-2014-3505)

Adam Langley discovered that OpenSSL incorrectly handled memory when
processing DTLS handshake messages. A remote attacker could use this
issue to cause OpenSSL to consume memory, resulting in a denial of
service. (CVE-2014-3506)

Adam Langley discovered that OpenSSL incorrectly handled memory when
processing DTLS fragments. A remote attacker could use this issue to
cause OpenSSL to leak memory, resulting in a denial of service. This
issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2014-3507)

Ivan Fratric discovered that OpenSSL incorrectly leaked information in
the pretty printing functions. When OpenSSL is used with certain
applications, an attacker may use this issue to possibly gain access
to sensitive information. (CVE-2014-3508)

Gabor Tyukasz discovered that OpenSSL contained a race condition when
processing serverhello messages. A malicious server could use this
issue to cause clients to crash, resulting in a denial of service.
This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2014-3509)

Felix Grobert discovered that OpenSSL incorrectly handled certain
DTLS handshake messages. A malicious server could use this issue to
cause clients to crash, resulting in a denial of service.
(CVE-2014-3510)

David Benjamin and Adam Langley discovered that OpenSSL incorrectly
handled fragmented ClientHello messages. If a remote attacker were
able to perform a man-in-the-middle attack, this flaw could be used to
force a protocol downgrade to TLS 1.0. This issue only affected Ubuntu
12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-3511)

Sean Devlin and Watson Ladd discovered that OpenSSL incorrectly
handled certain SRP parameters. A remote attacker could use this with
applications that use SRP to cause a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2014-3512)

Joonas Kuorilehto and Riku Hietamaki discovered that OpenSSL
incorrectly handled certain Server Hello messages that specify an SRP
ciphersuite. A malicious server could use this issue to cause clients
to crash, resulting in a denial of service. This issue only affected
Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-5139).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libssl0.9.8 and / or libssl1.0.0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|12\.04|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libssl0.9.8", pkgver:"0.9.8k-7ubuntu8.20")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libssl1.0.0", pkgver:"1.0.1-4ubuntu5.17")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libssl1.0.0", pkgver:"1.0.1f-1ubuntu2.5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssl0.9.8 / libssl1.0.0");
}
