#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-960-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47695);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2010-1205", "CVE-2010-2249");
  script_bugtraq_id(41174);
  script_xref(name:"USN", value:"960-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.04 / 9.10 / 10.04 LTS : libpng vulnerabilities (USN-960-1)");
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
"It was discovered that libpng did not properly handle certain
malformed PNG images. If a user or automated system were tricked into
opening a crafted PNG file, an attacker could cause a denial of
service or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2010-1205)

It was discovered that libpng did not properly handle certain
malformed PNG images. If a user or automated system were tricked into
processing a crafted PNG image, an attacker could possibly use this
flaw to consume all available resources, resulting in a denial of
service. (CVE-2010-2249).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpng12-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpng12-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpng3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/09");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libpng12-0", pkgver:"1.2.8rel-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpng12-dev", pkgver:"1.2.8rel-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpng3", pkgver:"1.2.8rel-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpng12-0", pkgver:"1.2.15~beta5-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpng12-dev", pkgver:"1.2.15~beta5-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpng3", pkgver:"1.2.15~beta5-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpng12-0", pkgver:"1.2.27-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpng12-dev", pkgver:"1.2.27-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpng3", pkgver:"1.2.27-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpng12-0", pkgver:"1.2.37-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpng12-dev", pkgver:"1.2.37-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpng3", pkgver:"1.2.37-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpng", pkgver:"1.2.42-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpng12-0", pkgver:"1.2.42-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpng12-dev", pkgver:"1.2.42-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpng3", pkgver:"1.2.42-1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng / libpng12-0 / libpng12-dev / libpng3");
}
