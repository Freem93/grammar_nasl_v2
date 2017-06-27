#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-767-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38196);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:37:18 $");

  script_cve_id("CVE-2009-0946");
  script_bugtraq_id(34550);
  script_xref(name:"USN", value:"767-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : freetype vulnerability (USN-767-1)");
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
"Tavis Ormandy discovered that FreeType did not correctly handle
certain large values in font files. If a user were tricked into using
a specially crafted font file, a remote attacker could execute
arbitrary code with user privileges.

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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freetype2-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreetype6-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/28");
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

if (ubuntu_check(osver:"6.06", pkgname:"freetype2-demos", pkgver:"2.1.10-1ubuntu2.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libfreetype6", pkgver:"2.1.10-1ubuntu2.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libfreetype6-dev", pkgver:"2.1.10-1ubuntu2.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"freetype2-demos", pkgver:"2.3.5-1ubuntu4.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libfreetype6", pkgver:"2.3.5-1ubuntu4.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libfreetype6-dev", pkgver:"2.3.5-1ubuntu4.8.04.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"freetype2-demos", pkgver:"2.3.7-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libfreetype6", pkgver:"2.3.7-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libfreetype6-dev", pkgver:"2.3.7-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"freetype2-demos", pkgver:"2.3.9-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libfreetype6", pkgver:"2.3.9-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libfreetype6-dev", pkgver:"2.3.9-4ubuntu0.1")) flag++;

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
