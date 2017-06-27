#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-934-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46192);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2009-4274");
  script_bugtraq_id(38164);
  script_osvdb_id(62270);
  script_xref(name:"USN", value:"934-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.04 / 9.10 : netpbm-free vulnerability (USN-934-1)");
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
"Marc Schoenefeld discovered a buffer overflow in Netpbm when loading
certain images. If a user or automated system were tricked into
opening a specially crafted XPM image, a remote attacker could crash
Netpbm. The default compiler options for affected releases should
reduce the vulnerability to a denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnetpbm10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnetpbm10-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnetpbm9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnetpbm9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:netpbm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");
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

if (ubuntu_check(osver:"8.04", pkgname:"libnetpbm10", pkgver:"10.0-11.1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libnetpbm10-dev", pkgver:"10.0-11.1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libnetpbm9", pkgver:"10.0-11.1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libnetpbm9-dev", pkgver:"10.0-11.1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"netpbm", pkgver:"2:10.0-11.1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libnetpbm10", pkgver:"10.0-12ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libnetpbm10-dev", pkgver:"10.0-12ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libnetpbm9", pkgver:"10.0-12ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libnetpbm9-dev", pkgver:"10.0-12ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"netpbm", pkgver:"2:10.0-12ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libnetpbm10", pkgver:"10.0-12ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libnetpbm10-dev", pkgver:"10.0-12ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libnetpbm9", pkgver:"10.0-12ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libnetpbm9-dev", pkgver:"10.0-12ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"netpbm", pkgver:"2:10.0-12ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnetpbm10 / libnetpbm10-dev / libnetpbm9 / libnetpbm9-dev / etc");
}
