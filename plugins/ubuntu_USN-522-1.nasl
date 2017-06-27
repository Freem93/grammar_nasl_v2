#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-522-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28127);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:07:51 $");

  script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343", "CVE-2007-3108", "CVE-2007-5135");
  script_osvdb_id(29260, 29261, 29262, 29263);
  script_xref(name:"USN", value:"522-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 : openssl vulnerabilities (USN-522-1)");
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
"It was discovered that OpenSSL did not correctly perform Montgomery
multiplications. Local attackers might be able to reconstruct RSA
private keys by examining another user's OpenSSL processes.
(CVE-2007-3108)

Moritz Jodeit discovered that OpenSSL's SSL_get_shared_ciphers
function did not correctly check the size of the buffer it was writing
to. A remote attacker could exploit this to write one NULL byte past
the end of an application's cipher list buffer, possibly leading to
arbitrary code execution or a denial of service. (CVE-2007-5135).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.8-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libssl-dev", pkgver:"0.9.8a-7ubuntu0.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libssl0.9.8", pkgver:"0.9.8a-7ubuntu0.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8a-7ubuntu0.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openssl", pkgver:"0.9.8a-7ubuntu0.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libssl-dev", pkgver:"0.9.8b-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libssl0.9.8", pkgver:"0.9.8b-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8b-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"openssl", pkgver:"0.9.8b-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libssl-dev", pkgver:"0.9.8c-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libssl0.9.8", pkgver:"0.9.8c-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8c-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"openssl", pkgver:"0.9.8c-4ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssl-dev / libssl0.9.8 / libssl0.9.8-dbg / openssl");
}
