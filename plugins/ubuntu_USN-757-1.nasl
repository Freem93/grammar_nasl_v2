#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-757-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37438);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2007-6725", "CVE-2008-6679", "CVE-2009-0196", "CVE-2009-0583", "CVE-2009-0584", "CVE-2009-0792");
  script_bugtraq_id(34184, 34337, 34340, 34445);
  script_xref(name:"USN", value:"757-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 : ghostscript, gs-esp, gs-gpl vulnerabilities (USN-757-1)");
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
"It was discovered that Ghostscript contained a buffer underflow in its
CCITTFax decoding filter. If a user or automated system were tricked
into opening a crafted PDF file, an attacker could cause a denial of
service or execute arbitrary code with privileges of the user invoking
the program. (CVE-2007-6725)

It was discovered that Ghostscript contained a buffer overflow in the
BaseFont writer module. If a user or automated system were tricked
into opening a crafted Postscript file, an attacker could cause a
denial of service or execute arbitrary code with privileges of the
user invoking the program. (CVE-2008-6679)

It was discovered that Ghostscript contained additional integer
overflows in its ICC color management library. If a user or automated
system were tricked into opening a crafted Postscript or PDF file, an
attacker could cause a denial of service or execute arbitrary code
with privileges of the user invoking the program. (CVE-2009-0792)

Alin Rad Pop discovered that Ghostscript contained a buffer overflow
in the jbig2dec library. If a user or automated system were tricked
into opening a crafted PDF file, an attacker could cause a denial of
service or execute arbitrary code with privileges of the user invoking
the program. (CVE-2009-0196)

USN-743-1 provided updated ghostscript and gs-gpl packages to fix two
security vulnerabilities. This update corrects the same
vulnerabilities in the gs-esp package.

It was discovered that Ghostscript contained multiple integer
overflows in its ICC color management library. If a user or automated
system were tricked into opening a crafted Postscript file, an
attacker could cause a denial of service or execute arbitrary code
with privileges of the user invoking the program. (CVE-2009-0583)

It was discovered that Ghostscript did not properly perform
bounds checking in its ICC color management library. If a
user or automated system were tricked into opening a crafted
Postscript file, an attacker could cause a denial of service
or execute arbitrary code with privileges of the user
invoking the program. (CVE-2009-0584).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-aladdin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-esp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-esp-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-gpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs-esp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"gs", pkgver:"8.15-4ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gs-esp", pkgver:"8.15.2.dfsg.0ubuntu1-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gs-gpl", pkgver:"8.15-4ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ghostscript", pkgver:"8.61.dfsg.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ghostscript-doc", pkgver:"8.61.dfsg.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ghostscript-x", pkgver:"8.61.dfsg.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gs", pkgver:"8.61.dfsg.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gs-aladdin", pkgver:"8.61.dfsg.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gs-common", pkgver:"8.61.dfsg.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gs-esp", pkgver:"8.61.dfsg.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gs-esp-x", pkgver:"8.61.dfsg.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gs-gpl", pkgver:"8.61.dfsg.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgs-dev", pkgver:"8.61.dfsg.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgs-esp-dev", pkgver:"8.61.dfsg.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgs8", pkgver:"8.61.dfsg.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ghostscript", pkgver:"8.63.dfsg.1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ghostscript-doc", pkgver:"8.63.dfsg.1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ghostscript-x", pkgver:"8.63.dfsg.1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gs", pkgver:"8.63.dfsg.1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gs-aladdin", pkgver:"8.63.dfsg.1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gs-common", pkgver:"8.63.dfsg.1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gs-esp", pkgver:"8.63.dfsg.1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gs-esp-x", pkgver:"8.63.dfsg.1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gs-gpl", pkgver:"8.63.dfsg.1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgs-dev", pkgver:"8.63.dfsg.1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgs-esp-dev", pkgver:"8.63.dfsg.1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgs8", pkgver:"8.63.dfsg.1-0ubuntu6.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-doc / ghostscript-x / gs / gs-aladdin / etc");
}
