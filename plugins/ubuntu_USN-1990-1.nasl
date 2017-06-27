#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1990-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70492);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/25 16:34:53 $");

  script_cve_id("CVE-2013-1056", "CVE-2013-4396");
  script_bugtraq_id(62892);
  script_osvdb_id(98314, 98683);
  script_xref(name:"USN", value:"1990-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.04 : xorg-server, xorg-server-lts-quantal, xorg-server-lts-raring vulnerabilities (USN-1990-1)");
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
"Pedro Ribeiro discovered that the X.Org X server incorrectly handled
memory operations when handling ImageText requests. An attacker could
use this issue to cause X.Org to crash, or to possibly execute
arbitrary code. (CVE-2013-4396)

It was discovered that non-root X.Org X servers such as Xephyr
incorrectly used cached xkb files. A local attacker could use this
flaw to cause a xkb cache file to be loaded by another user, resulting
in a denial of service. (CVE-2013-1056).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected xserver-xorg-core, xserver-xorg-core-lts-quantal
and / or xserver-xorg-core-lts-raring packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core-lts-raring");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|12\.10|13\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"xserver-xorg-core", pkgver:"2:1.11.4-0ubuntu10.14")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"xserver-xorg-core-lts-quantal", pkgver:"2:1.13.0-0ubuntu6.1~precise4")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"xserver-xorg-core-lts-raring", pkgver:"2:1.13.3-0ubuntu6~precise3")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"xserver-xorg-core", pkgver:"2:1.13.0-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"xserver-xorg-core", pkgver:"2:1.13.3-0ubuntu6.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xserver-xorg-core / xserver-xorg-core-lts-quantal / etc");
}
