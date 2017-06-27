#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-792-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39534);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379", "CVE-2009-1386", "CVE-2009-1387");
  script_bugtraq_id(35001, 35138, 35174, 35417);
  script_xref(name:"USN", value:"792-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : openssl vulnerabilities (USN-792-1)");
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
"It was discovered that OpenSSL did not limit the number of DTLS
records it would buffer when they arrived with a future epoch. A
remote attacker could cause a denial of service via memory resource
consumption by sending a large number of crafted requests.
(CVE-2009-1377)

It was discovered that OpenSSL did not properly free memory when
processing DTLS fragments. A remote attacker could cause a denial of
service via memory resource consumption by sending a large number of
crafted requests. (CVE-2009-1378)

It was discovered that OpenSSL did not properly handle certain server
certificates when processing DTLS packets. A remote DTLS server could
cause a denial of service by sending a message containing a specially
crafted server certificate. (CVE-2009-1379)

It was discovered that OpenSSL did not properly handle a DTLS
ChangeCipherSpec packet when it occured before ClientHello. A remote
attacker could cause a denial of service by sending a specially
crafted request. (CVE-2009-1386)

It was discovered that OpenSSL did not properly handle out of sequence
DTLS handshake messages. A remote attacker could cause a denial of
service by sending a specially crafted request. (CVE-2009-1387).

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
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.8-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libssl-dev", pkgver:"0.9.8a-7ubuntu0.9")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libssl0.9.8", pkgver:"0.9.8a-7ubuntu0.9")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8a-7ubuntu0.9")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openssl", pkgver:"0.9.8a-7ubuntu0.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libssl-dev", pkgver:"0.9.8g-4ubuntu3.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libssl0.9.8", pkgver:"0.9.8g-4ubuntu3.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8g-4ubuntu3.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openssl", pkgver:"0.9.8g-4ubuntu3.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openssl-doc", pkgver:"0.9.8g-4ubuntu3.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libssl-dev", pkgver:"0.9.8g-10.1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libssl0.9.8", pkgver:"0.9.8g-10.1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8g-10.1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openssl", pkgver:"0.9.8g-10.1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openssl-doc", pkgver:"0.9.8g-10.1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libssl-dev", pkgver:"0.9.8g-15ubuntu3.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libssl0.9.8", pkgver:"0.9.8g-15ubuntu3.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8g-15ubuntu3.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openssl", pkgver:"0.9.8g-15ubuntu3.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openssl-doc", pkgver:"0.9.8g-15ubuntu3.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssl-dev / libssl0.9.8 / libssl0.9.8-dbg / openssl / openssl-doc");
}
