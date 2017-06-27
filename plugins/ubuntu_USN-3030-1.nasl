#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3030-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92011);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2013-7456", "CVE-2016-5116", "CVE-2016-5766", "CVE-2016-6128", "CVE-2016-6161");
  script_osvdb_id(139004, 139194, 140390, 140766, 141222);
  script_xref(name:"USN", value:"3030-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 / 16.04 LTS : libgd2 vulnerabilities (USN-3030-1)");
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
"It was discovered that the GD library incorrectly handled memory when
using gdImageScaleTwoPass(). A remote attacker could possibly use this
issue to cause a denial of service. This issue only affected Ubuntu
14.04 LTS. (CVE-2013-7456)

It was discovered that the GD library incorrectly handled certain
malformed XBM images. If a user or automated system were tricked into
processing a specially crafted XBM image, an attacker could cause a
denial of service. This issue only affected Ubuntu 14.04 LTS, Ubuntu
15.10 and Ubuntu 16.04 LTS. (CVE-2016-5116)

It was discovered that the GD library incorrectly handled memory when
using _gd2GetHeader(). A remote attacker could possibly use this issue
to cause a denial of service or possibly execute arbitrary code.
(CVE-2016-5766)

It was discovered that the GD library incorrectly handled certain
color indexes. A remote attacker could possibly use this issue to
cause a denial of service. This issue only affected Ubuntu 14.04 LTS,
Ubuntu 15.10 and Ubuntu 16.04 LTS. (CVE-2016-6128)

It was discovered that the GD library incorrectly handled memory when
encoding a GIF image. A remote attacker could possibly use this issue
to cause a denial of service. (CVE-2016-6161).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgd2-noxpm, libgd2-xpm and / or libgd3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd2-noxpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd2-xpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.10|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.10 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libgd2-noxpm", pkgver:"2.0.36~rc1~dfsg-6ubuntu2.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgd2-xpm", pkgver:"2.0.36~rc1~dfsg-6ubuntu2.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libgd3", pkgver:"2.1.0-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libgd3", pkgver:"2.1.1-4ubuntu0.15.10.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libgd3", pkgver:"2.1.1-4ubuntu0.16.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgd2-noxpm / libgd2-xpm / libgd3");
}
