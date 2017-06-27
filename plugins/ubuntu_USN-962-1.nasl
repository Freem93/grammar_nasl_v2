#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-962-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47742);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2003-0070", "CVE-2010-2713");
  script_osvdb_id(60458);
  script_xref(name:"USN", value:"962-1");

  script_name(english:"Ubuntu 9.04 / 9.10 / 10.04 LTS : vte vulnerability (USN-962-1)");
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
"Janne Snabb discovered that applications using VTE, such as
gnome-terminal, did not correctly filter window and icon title request
escape codes. If a user were tricked into viewing specially crafted
output in their terminal, a remote attacker could execute arbitrary
commands with user privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvte-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvte-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvte-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvte9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-vte");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-vte-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/16");
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
if (! ereg(pattern:"^(9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.04", pkgname:"libvte-common", pkgver:"0.20.0-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libvte-dev", pkgver:"0.20.0-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libvte-doc", pkgver:"0.20.0-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libvte9", pkgver:"1:0.20.0-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-vte", pkgver:"0.20.0-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-vte-dbg", pkgver:"0.20.0-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libvte-common", pkgver:"0.22.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libvte-dev", pkgver:"0.22.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libvte-doc", pkgver:"0.22.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libvte9", pkgver:"1:0.22.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-vte", pkgver:"0.22.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-vte-dbg", pkgver:"0.22.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libvte-common", pkgver:"0.23.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libvte-dev", pkgver:"0.23.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libvte-doc", pkgver:"0.23.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libvte9", pkgver:"1:0.23.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"python-vte", pkgver:"0.23.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"python-vte-dbg", pkgver:"0.23.5-0ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvte-common / libvte-dev / libvte-doc / libvte9 / python-vte / etc");
}
