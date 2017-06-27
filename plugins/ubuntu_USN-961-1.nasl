#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-961-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47734);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2009-4270", "CVE-2009-4897", "CVE-2010-1628", "CVE-2010-1869");
  script_bugtraq_id(37410, 40103, 40107, 41593);
  script_osvdb_id(66277);
  script_xref(name:"USN", value:"961-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.04 / 9.10 / 10.04 LTS : ghostscript vulnerabilities (USN-961-1)");
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
"David Srbecky discovered that Ghostscript incorrectly handled debug
logging. If a user or automated system were tricked into opening a
crafted PDF file, an attacker could cause a denial of service or
execute arbitrary code with privileges of the user invoking the
program. This issue only affected Ubuntu 9.04 and Ubuntu 9.10. The
default compiler options for affected releases should reduce the
vulnerability to a denial of service. (CVE-2009-4270)

It was discovered that Ghostscript incorrectly handled certain
malformed files. If a user or automated system were tricked into
opening a crafted Postscript or PDF file, an attacker could cause a
denial of service or execute arbitrary code with privileges of the
user invoking the program. This issue only affected Ubuntu 8.04 LTS
and Ubuntu 9.04. (CVE-2009-4897)

Dan Rosenberg discovered that Ghostscript incorrectly handled certain
recursive Postscript files. If a user or automated system were tricked
into opening a crafted Postscript file, an attacker could cause a
denial of service or execute arbitrary code with privileges of the
user invoking the program. (CVE-2010-1628)

Rodrigo Rubira Branco and Dan Rosenberg discovered that Ghostscript
incorrectly handled certain malformed Postscript files. If a user or
automated system were tricked into opening a crafted Postscript file,
an attacker could cause a denial of service or execute arbitrary code
with privileges of the user invoking the program. This issue only
affected Ubuntu 8.04 LTS, 9.04 and 9.10. (CVE-2010-1869).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript-cups");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/14");
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
if (! ereg(pattern:"^(8\.04|9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"ghostscript", pkgver:"8.61.dfsg.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ghostscript-doc", pkgver:"8.61.dfsg.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ghostscript-x", pkgver:"8.61.dfsg.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gs", pkgver:"8.61.dfsg.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gs-aladdin", pkgver:"8.61.dfsg.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gs-common", pkgver:"8.61.dfsg.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gs-esp", pkgver:"8.61.dfsg.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gs-esp-x", pkgver:"8.61.dfsg.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gs-gpl", pkgver:"8.61.dfsg.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgs-dev", pkgver:"8.61.dfsg.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgs-esp-dev", pkgver:"8.61.dfsg.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgs8", pkgver:"8.61.dfsg.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ghostscript", pkgver:"8.64.dfsg.1-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ghostscript-doc", pkgver:"8.64.dfsg.1-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ghostscript-x", pkgver:"8.64.dfsg.1-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"gs", pkgver:"8.64.dfsg.1-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"gs-aladdin", pkgver:"8.64.dfsg.1-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"gs-common", pkgver:"8.64.dfsg.1-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"gs-esp", pkgver:"8.64.dfsg.1-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"gs-esp-x", pkgver:"8.64.dfsg.1-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"gs-gpl", pkgver:"8.64.dfsg.1-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libgs-dev", pkgver:"8.64.dfsg.1-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libgs-esp-dev", pkgver:"8.64.dfsg.1-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libgs8", pkgver:"8.64.dfsg.1-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ghostscript", pkgver:"8.70.dfsg.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ghostscript-cups", pkgver:"8.70.dfsg.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ghostscript-doc", pkgver:"8.70.dfsg.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ghostscript-x", pkgver:"8.70.dfsg.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"gs", pkgver:"8.70.dfsg.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"gs-aladdin", pkgver:"8.70.dfsg.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"gs-common", pkgver:"8.70.dfsg.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"gs-esp", pkgver:"8.70.dfsg.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"gs-esp-x", pkgver:"8.70.dfsg.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"gs-gpl", pkgver:"8.70.dfsg.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgs-dev", pkgver:"8.70.dfsg.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgs-esp-dev", pkgver:"8.70.dfsg.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgs8", pkgver:"8.70.dfsg.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ghostscript", pkgver:"8.71.dfsg.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ghostscript-cups", pkgver:"8.71.dfsg.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ghostscript-doc", pkgver:"8.71.dfsg.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ghostscript-x", pkgver:"8.71.dfsg.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"gs", pkgver:"8.71.dfsg.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"gs-aladdin", pkgver:"8.71.dfsg.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"gs-common", pkgver:"8.71.dfsg.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"gs-esp", pkgver:"8.71.dfsg.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"gs-esp-x", pkgver:"8.71.dfsg.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"gs-gpl", pkgver:"8.71.dfsg.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libgs-dev", pkgver:"8.71.dfsg.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libgs-esp-dev", pkgver:"8.71.dfsg.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libgs8", pkgver:"8.71.dfsg.1-0ubuntu5.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-cups / ghostscript-doc / ghostscript-x / etc");
}
