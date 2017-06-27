#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1082-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52529);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2010-0421", "CVE-2011-0020", "CVE-2011-0064");
  script_bugtraq_id(38760, 45842, 46632);
  script_xref(name:"USN", value:"1082-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : pango1.0 vulnerabilities (USN-1082-1)");
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
"Marc Schoenefeld discovered that Pango incorrectly handled certain
Glyph Definition (GDEF) tables. If a user were tricked into displaying
text with a specially crafted font, an attacker could cause Pango to
crash, resulting in a denial of service. This issue only affected
Ubuntu 8.04 LTS and 9.10. (CVE-2010-0421)

Dan Rosenberg discovered that Pango incorrectly handled certain
FT_Bitmap objects. If a user were tricked into displaying text with a
specially- crafted font, an attacker could cause a denial of service
or execute arbitrary code with privileges of the user invoking the
program. The default compiler options for affected releases should
reduce the vulnerability to a denial of service. (CVE-2011-0020)

It was discovered that Pango incorrectly handled certain memory
reallocation failures. If a user were tricked into displaying text in
a way that would cause a reallocation failure, an attacker could cause
a denial of service or execute arbitrary code with privileges of the
user invoking the program. This issue only affected Ubuntu 9.10, 10.04
LTS and 10.10. (CVE-2011-0064).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.0-pango-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpango1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpango1.0-0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpango1.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpango1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpango1.0-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/03");
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
if (! ereg(pattern:"^(8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libpango1.0-0", pkgver:"1.20.5-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpango1.0-0-dbg", pkgver:"1.20.5-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpango1.0-common", pkgver:"1.20.5-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpango1.0-dev", pkgver:"1.20.5-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpango1.0-doc", pkgver:"1.20.5-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpango1.0-0", pkgver:"1.26.0-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpango1.0-0-dbg", pkgver:"1.26.0-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpango1.0-common", pkgver:"1.26.0-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpango1.0-dev", pkgver:"1.26.0-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpango1.0-doc", pkgver:"1.26.0-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"gir1.0-pango-1.0", pkgver:"1.28.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpango1.0-0", pkgver:"1.28.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpango1.0-0-dbg", pkgver:"1.28.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpango1.0-common", pkgver:"1.28.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpango1.0-dev", pkgver:"1.28.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpango1.0-doc", pkgver:"1.28.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"gir1.0-pango-1.0", pkgver:"1.28.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libpango1.0-0", pkgver:"1.28.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libpango1.0-0-dbg", pkgver:"1.28.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libpango1.0-common", pkgver:"1.28.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libpango1.0-dev", pkgver:"1.28.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libpango1.0-doc", pkgver:"1.28.2-0ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gir1.0-pango-1.0 / libpango1.0-0 / libpango1.0-0-dbg / etc");
}
