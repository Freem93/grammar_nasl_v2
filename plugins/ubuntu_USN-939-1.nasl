#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-939-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46672);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2009-1573", "CVE-2010-1166");
  script_bugtraq_id(34828, 39758);
  script_osvdb_id(54680, 64246);
  script_xref(name:"USN", value:"939-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.04 / 9.10 : xorg-server vulnerabilities (USN-939-1)");
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
"Loic Minier discovered that xvfb-run did not correctly keep the X.org
session cookie private. A local attacker could gain access to any
local sessions started by xvfb-run. Ubuntu 9.10 was not affected.
(CVE-2009-1573)

It was discovered that the X.org server did not correctly handle
certain calculations. A remote attacker could exploit this to crash
the X.org session or possibly run arbitrary code with root privileges.
(CVE-2010-1166).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xfbdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/19");
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
if (! ereg(pattern:"^(8\.04|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"xnest", pkgver:"1.4.1~git20080131-1ubuntu9.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xserver-xephyr", pkgver:"1.4.1~git20080131-1ubuntu9.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xserver-xorg-core", pkgver:"2:1.4.1~git20080131-1ubuntu9.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xserver-xorg-core-dbg", pkgver:"1.4.1~git20080131-1ubuntu9.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xserver-xorg-dev", pkgver:"1.4.1~git20080131-1ubuntu9.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xvfb", pkgver:"2:1.4.1~git20080131-1ubuntu9.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xdmx", pkgver:"1.6.0-0ubuntu14.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xdmx-tools", pkgver:"1.6.0-0ubuntu14.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xnest", pkgver:"1.6.0-0ubuntu14.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xserver-common", pkgver:"1.6.0-0ubuntu14.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xserver-xephyr", pkgver:"1.6.0-0ubuntu14.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xserver-xfbdev", pkgver:"1.6.0-0ubuntu14.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xserver-xorg-core", pkgver:"2:1.6.0-0ubuntu14.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xserver-xorg-core-dbg", pkgver:"1.6.0-0ubuntu14.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xserver-xorg-dev", pkgver:"1.6.0-0ubuntu14.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xvfb", pkgver:"2:1.6.0-0ubuntu14.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xdmx", pkgver:"1.6.4-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xdmx-tools", pkgver:"1.6.4-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xnest", pkgver:"1.6.4-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xserver-common", pkgver:"1.6.4-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xserver-xephyr", pkgver:"1.6.4-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xserver-xfbdev", pkgver:"1.6.4-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xserver-xorg-core", pkgver:"2:1.6.4-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xserver-xorg-core-dbg", pkgver:"1.6.4-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xserver-xorg-dev", pkgver:"1.6.4-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xvfb", pkgver:"1.6.4-2ubuntu4.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xdmx / xdmx-tools / xnest / xserver-common / xserver-xephyr / etc");
}
