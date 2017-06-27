#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1206-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56194);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/07/08 14:36:38 $");

  script_cve_id("CVE-2011-3146");
  script_osvdb_id(75270);
  script_xref(name:"USN", value:"1206-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 / 11.04 : librsvg vulnerability (USN-1206-1)");
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
"Sauli Pahlman discovered that librsvg did not correctly handle
malformed filter names. If a user or automated system were tricked
into processing a specially crafted SVG image, a remote attacker could
gain user privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librsvg2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librsvg2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librsvg2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librsvg2-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");
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
if (! ereg(pattern:"^(10\.04|10\.10|11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10 / 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"librsvg2-2", pkgver:"2.26.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"librsvg2-bin", pkgver:"2.26.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"librsvg2-common", pkgver:"2.26.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"librsvg2-dev", pkgver:"2.26.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"librsvg2-2", pkgver:"2.32.0-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"librsvg2-bin", pkgver:"2.32.0-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"librsvg2-common", pkgver:"2.32.0-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"librsvg2-dev", pkgver:"2.32.0-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"librsvg2-2", pkgver:"2.32.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"librsvg2-bin", pkgver:"2.32.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"librsvg2-common", pkgver:"2.32.1-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"librsvg2-dev", pkgver:"2.32.1-0ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "librsvg2-2 / librsvg2-bin / librsvg2-common / librsvg2-dev");
}
