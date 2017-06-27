#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1888-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66961);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/25 16:27:06 $");

  script_cve_id("CVE-2013-1872", "CVE-2013-1993");
  script_bugtraq_id(60149, 60285);
  script_osvdb_id(93678, 93856);
  script_xref(name:"USN", value:"1888-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.04 : mesa, mesa-lts-quantal vulnerabilities (USN-1888-1)");
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
"It was discovered that Mesa incorrectly handled certain memory
calculations. An attacker could use this flaw to cause an application
to crash, or possibly execute arbitrary code. (CVE-2013-1872)

Ilja van Sprundel discovered that Mesa incorrectly handled certain
memory calculations. An attacker could use this flaw to cause an
application to crash, or possibly execute arbitrary code.
(CVE-2013-1993).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libegl1-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libegl1-mesa-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgbm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgbm1-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgl1-mesa-dri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgl1-mesa-dri-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgl1-mesa-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgl1-mesa-glx-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgl1-mesa-swx11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglapi-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglapi-mesa-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgles1-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgles1-mesa-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgles2-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgles2-mesa-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglu1-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenvg1-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenvg1-mesa-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libosmesa6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxatracker1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxatracker1-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/21");
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

if (ubuntu_check(osver:"12.04", pkgname:"libegl1-mesa", pkgver:"8.0.4-0ubuntu0.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libegl1-mesa-lts-quantal", pkgver:"9.0.3-0ubuntu0.1~precise3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgbm1", pkgver:"8.0.4-0ubuntu0.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgbm1-lts-quantal", pkgver:"9.0.3-0ubuntu0.1~precise3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgl1-mesa-dri", pkgver:"8.0.4-0ubuntu0.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgl1-mesa-dri-lts-quantal", pkgver:"9.0.3-0ubuntu0.1~precise3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgl1-mesa-glx", pkgver:"8.0.4-0ubuntu0.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgl1-mesa-glx-lts-quantal", pkgver:"9.0.3-0ubuntu0.1~precise3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgl1-mesa-swx11", pkgver:"8.0.4-0ubuntu0.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libglapi-mesa", pkgver:"8.0.4-0ubuntu0.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libglapi-mesa-lts-quantal", pkgver:"9.0.3-0ubuntu0.1~precise3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgles1-mesa", pkgver:"8.0.4-0ubuntu0.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgles1-mesa-lts-quantal", pkgver:"9.0.3-0ubuntu0.1~precise3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgles2-mesa", pkgver:"8.0.4-0ubuntu0.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgles2-mesa-lts-quantal", pkgver:"9.0.3-0ubuntu0.1~precise3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libglu1-mesa", pkgver:"8.0.4-0ubuntu0.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libopenvg1-mesa", pkgver:"8.0.4-0ubuntu0.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libopenvg1-mesa-lts-quantal", pkgver:"9.0.3-0ubuntu0.1~precise3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libosmesa6", pkgver:"8.0.4-0ubuntu0.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libxatracker1", pkgver:"8.0.4-0ubuntu0.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libxatracker1-lts-quantal", pkgver:"9.0.3-0ubuntu0.1~precise3")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libegl1-mesa", pkgver:"9.0.3-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libgbm1", pkgver:"9.0.3-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libgl1-mesa-dri", pkgver:"9.0.3-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libgl1-mesa-glx", pkgver:"9.0.3-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libglapi-mesa", pkgver:"9.0.3-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libgles1-mesa", pkgver:"9.0.3-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libgles2-mesa", pkgver:"9.0.3-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libopenvg1-mesa", pkgver:"9.0.3-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libosmesa6", pkgver:"9.0.3-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libxatracker1", pkgver:"9.0.3-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libegl1-mesa", pkgver:"9.1.3-0ubuntu0.3")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libgbm1", pkgver:"9.1.3-0ubuntu0.3")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libgl1-mesa-dri", pkgver:"9.1.3-0ubuntu0.3")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libgl1-mesa-glx", pkgver:"9.1.3-0ubuntu0.3")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libglapi-mesa", pkgver:"9.1.3-0ubuntu0.3")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libgles1-mesa", pkgver:"9.1.3-0ubuntu0.3")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libgles2-mesa", pkgver:"9.1.3-0ubuntu0.3")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libopenvg1-mesa", pkgver:"9.1.3-0ubuntu0.3")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libosmesa6", pkgver:"9.1.3-0ubuntu0.3")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libxatracker1", pkgver:"9.1.3-0ubuntu0.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libegl1-mesa / libegl1-mesa-lts-quantal / libgbm1 / etc");
}
