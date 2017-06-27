#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2537-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81971);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293");
  script_bugtraq_id(73225, 73227, 73228, 73231, 73232, 73237, 73239);
  script_osvdb_id(116794, 118817, 119328, 119743, 119755, 119756, 119757, 119761);
  script_xref(name:"USN", value:"2537-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 14.04 LTS / 14.10 : openssl vulnerabilities (USN-2537-1)");
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
"It was discovered that OpenSSL incorrectly handled malformed EC
private key files. A remote attacker could possibly use this issue to
cause OpenSSL to crash, resulting in a denial of service, or execute
arbitrary code. (CVE-2015-0209)

Stephen Henson discovered that OpenSSL incorrectly handled comparing
ASN.1 boolean types. A remote attacker could possibly use this issue
to cause OpenSSL to crash, resulting in a denial of service.
(CVE-2015-0286)

Emilia Kasper discovered that OpenSSL incorrectly handled ASN.1
structure reuse. A remote attacker could possibly use this issue to
cause OpenSSL to crash, resulting in a denial of service, or execute
arbitrary code. (CVE-2015-0287)

Brian Carpenter discovered that OpenSSL incorrectly handled invalid
certificate keys. A remote attacker could possibly use this issue to
cause OpenSSL to crash, resulting in a denial of service.
(CVE-2015-0288)

Michal Zalewski discovered that OpenSSL incorrectly handled missing
outer ContentInfo when parsing PKCS#7 structures. A remote attacker
could possibly use this issue to cause OpenSSL to crash, resulting in
a denial of service, or execute arbitrary code. (CVE-2015-0289)

Robert Dugal and David Ramos discovered that OpenSSL incorrectly
handled decoding Base64 encoded data. A remote attacker could possibly
use this issue to cause OpenSSL to crash, resulting in a denial of
service, or execute arbitrary code. (CVE-2015-0292)

Sean Burford and Emilia Kasper discovered that OpenSSL incorrectly
handled specially crafted SSLv2 CLIENT-MASTER-KEY messages. A remote
attacker could possibly use this issue to cause OpenSSL to crash,
resulting in a denial of service. (CVE-2015-0293).

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/20");
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

if (ubuntu_check(osver:"10.04", pkgname:"libssl0.9.8", pkgver:"0.9.8k-7ubuntu8.27")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libssl1.0.0", pkgver:"1.0.1-4ubuntu5.25")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libssl1.0.0", pkgver:"1.0.1f-1ubuntu2.11")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"libssl1.0.0", pkgver:"1.0.1f-1ubuntu9.4")) flag++;

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
