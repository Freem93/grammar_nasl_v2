#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1013-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50491);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2010-3311", "CVE-2010-3814", "CVE-2010-3855");
  script_bugtraq_id(43700, 44214);
  script_xref(name:"USN", value:"1013-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : freetype vulnerabilities (USN-1013-1)");
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
"Marc Schoenefeld discovered that FreeType did not correctly handle
certain malformed font files. If a user were tricked into using a
specially crafted font file, a remote attacker could cause FreeType to
crash or possibly execute arbitrary code with user privileges. This
issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 9.10 and 10.04 LTS.
(CVE-2010-3311)

Chris Evans discovered that FreeType did not correctly handle certain
malformed TrueType font files. If a user were tricked into using a
specially crafted TrueType file, a remote attacker could cause
FreeType to crash or possibly execute arbitrary code with user
privileges. This issue only affected Ubuntu 8.04 LTS, 9.10, 10.04 LTS
and 10.10. (CVE-2010-3814)

It was discovered that FreeType did not correctly handle certain
malformed TrueType font files. If a user were tricked into using a
specially crafted TrueType file, a remote attacker could cause
FreeType to crash or possibly execute arbitrary code with user
privileges. (CVE-2010-3855).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected freetype2-demos, libfreetype6 and / or
libfreetype6-dev packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freetype2-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreetype6-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/05");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"freetype2-demos", pkgver:"2.1.10-1ubuntu2.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libfreetype6", pkgver:"2.1.10-1ubuntu2.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libfreetype6-dev", pkgver:"2.1.10-1ubuntu2.10")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"freetype2-demos", pkgver:"2.3.5-1ubuntu4.8.04.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libfreetype6", pkgver:"2.3.5-1ubuntu4.8.04.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libfreetype6-dev", pkgver:"2.3.5-1ubuntu4.8.04.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"freetype2-demos", pkgver:"2.3.9-5ubuntu0.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libfreetype6", pkgver:"2.3.9-5ubuntu0.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libfreetype6-dev", pkgver:"2.3.9-5ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"freetype2-demos", pkgver:"2.3.11-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libfreetype6", pkgver:"2.3.11-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libfreetype6-dev", pkgver:"2.3.11-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"freetype2-demos", pkgver:"2.4.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libfreetype6", pkgver:"2.4.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libfreetype6-dev", pkgver:"2.4.2-2ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype2-demos / libfreetype6 / libfreetype6-dev");
}
