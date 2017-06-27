#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1175-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55699);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/26 16:14:08 $");

  script_cve_id("CVE-2011-2501", "CVE-2011-2690", "CVE-2011-2692");
  script_bugtraq_id(48474, 48618, 48660);
  script_osvdb_id(73493, 73982, 73984);
  script_xref(name:"USN", value:"1175-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 : libpng vulnerabilities (USN-1175-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Frank Busse discovered that libpng did not properly handle certain
malformed PNG images. If a user or automated system were tricked into
opening a crafted PNG file, an attacker could cause libpng to crash,
resulting in a denial of service. This issue only affected Ubuntu
10.04 LTS, 10.10, and 11.04. (CVE-2011-2501)

It was discovered that libpng did not properly handle certain
malformed PNG images. If a user or automated system were tricked into
opening a crafted PNG file, an attacker could cause a denial of
service or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2011-2690)

Frank Busse discovered that libpng did not properly handle certain PNG
images with invalid sCAL chunks. If a user or automated system were
tricked into opening a crafted PNG file, an attacker could cause a
denial of service or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2011-2692).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng12-0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpng12-0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|10\.04|10\.10|11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libpng12-0", pkgver:"1.2.15~beta5-3ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpng12-0", pkgver:"1.2.42-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libpng12-0", pkgver:"1.2.44-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libpng12-0", pkgver:"1.2.44-1ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng12-0");
}
