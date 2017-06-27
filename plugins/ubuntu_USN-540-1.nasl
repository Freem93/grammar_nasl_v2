#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-540-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28208);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_cve_id("CVE-2007-4619");
  script_osvdb_id(41694);
  script_xref(name:"USN", value:"540-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : flac vulnerability (USN-540-1)");
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
"Sean de Regge discovered that flac did not properly perform bounds
checking in many situations. An attacker could send a specially
crafted FLAC audio file and execute arbitrary code as the user or
cause a denial of service in flac or applications that link against
flac.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflac++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflac++5c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflac++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflac-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflac7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflac8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboggflac++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboggflac++2c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboggflac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboggflac3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xmms-flac");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"flac", pkgver:"1.1.2-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libflac++-dev", pkgver:"1.1.2-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libflac++5c2", pkgver:"1.1.2-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libflac-dev", pkgver:"1.1.2-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libflac-doc", pkgver:"1.1.2-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libflac7", pkgver:"1.1.2-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"liboggflac++-dev", pkgver:"1.1.2-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"liboggflac++2c2", pkgver:"1.1.2-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"liboggflac-dev", pkgver:"1.1.2-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"liboggflac3", pkgver:"1.1.2-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xmms-flac", pkgver:"1.1.2-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"flac", pkgver:"1.1.2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libflac++-dev", pkgver:"1.1.2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libflac++5c2", pkgver:"1.1.2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libflac-dev", pkgver:"1.1.2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libflac-doc", pkgver:"1.1.2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libflac7", pkgver:"1.1.2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"liboggflac++-dev", pkgver:"1.1.2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"liboggflac++2c2", pkgver:"1.1.2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"liboggflac-dev", pkgver:"1.1.2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"liboggflac3", pkgver:"1.1.2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xmms-flac", pkgver:"1.1.2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"flac", pkgver:"1.1.2-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libflac++-dev", pkgver:"1.1.2-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libflac++5c2", pkgver:"1.1.2-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libflac-dev", pkgver:"1.1.2-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libflac-doc", pkgver:"1.1.2-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libflac7", pkgver:"1.1.2-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"liboggflac++-dev", pkgver:"1.1.2-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"liboggflac++2c2", pkgver:"1.1.2-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"liboggflac-dev", pkgver:"1.1.2-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"liboggflac3", pkgver:"1.1.2-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xmms-flac", pkgver:"1.1.2-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"flac", pkgver:"1.1.4-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libflac++-dev", pkgver:"1.1.4-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libflac++6", pkgver:"1.1.4-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libflac-dev", pkgver:"1.1.4-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libflac-doc", pkgver:"1.1.4-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libflac8", pkgver:"1.1.4-3ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flac / libflac++-dev / libflac++5c2 / libflac++6 / libflac-dev / etc");
}
