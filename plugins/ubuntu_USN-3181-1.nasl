#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3181-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96927);
  script_version("$Revision: 3.7 $");
  script_cvs_date("$Date: 2017/03/03 14:52:26 $");

  script_cve_id("CVE-2016-2177", "CVE-2016-7055", "CVE-2016-7056", "CVE-2016-8610", "CVE-2017-3731", "CVE-2017-3732");
  script_osvdb_id(139313, 146198, 147021, 149425, 151018, 151020);
  script_xref(name:"USN", value:"3181-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : openssl vulnerabilities (USN-3181-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Guido Vranken discovered that OpenSSL used undefined behaviour when
performing pointer arithmetic. A remote attacker could possibly use
this issue to cause OpenSSL to crash, resulting in a denial of
service. This issue only applied to Ubuntu 12.04 LTS and Ubuntu 14.04
LTS as other releases were fixed in a previous security update.
(CVE-2016-2177)

It was discovered that OpenSSL did not properly handle Montgomery
multiplication, resulting in incorrect results leading to transient
failures. This issue only applied to Ubuntu 16.04 LTS, and Ubuntu
16.10. (CVE-2016-7055)

It was discovered that OpenSSL did not properly use constant-time
operations when performing ECDSA P-256 signing. A remote attacker
could possibly use this issue to perform a timing attack and recover
private ECDSA keys. This issue only applied to Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2016-7056)

Shi Lei discovered that OpenSSL incorrectly handled certain warning
alerts. A remote attacker could possibly use this issue to cause
OpenSSL to stop responding, resulting in a denial of service.
(CVE-2016-8610)

Robert Swiecki discovered that OpenSSL incorrectly handled certain
truncated packets. A remote attacker could possibly use this issue to
cause OpenSSL to crash, resulting in a denial of service.
(CVE-2017-3731)

It was discovered that OpenSSL incorrectly performed the x86_64
Montgomery squaring procedure. While unlikely, a remote attacker could
possibly use this issue to recover private keys. This issue only
applied to Ubuntu 16.04 LTS, and Ubuntu 16.10. (CVE-2017-3732).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libssl1.0.0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libssl1.0.0", pkgver:"1.0.1-4ubuntu5.39")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libssl1.0.0", pkgver:"1.0.1f-1ubuntu2.22")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libssl1.0.0", pkgver:"1.0.2g-1ubuntu4.6")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libssl1.0.0", pkgver:"1.0.2g-1ubuntu9.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssl1.0.0");
}
