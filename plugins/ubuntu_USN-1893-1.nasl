#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1893-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67016);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/25 16:27:06 $");

  script_cve_id("CVE-2013-1845", "CVE-2013-1846", "CVE-2013-1847", "CVE-2013-1849", "CVE-2013-1884", "CVE-2013-1968", "CVE-2013-2112");
  script_bugtraq_id(58323, 58895, 58896, 58897, 58898, 60264, 60267);
  script_osvdb_id(93795, 93796);
  script_xref(name:"USN", value:"1893-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.04 : subversion vulnerabilities (USN-1893-1)");
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
"Alexander Klink discovered that the Subversion mod_dav_svn module for
Apache did not properly handle a large number of properties. A remote
authenticated attacker could use this flaw to cause memory
consumption, leading to a denial of service. (CVE-2013-1845)

Ben Reser discovered that the Subversion mod_dav_svn module for Apache
did not properly handle certain LOCKs. A remote authenticated attacker
could use this flaw to cause Subversion to crash, leading to a denial
of service. (CVE-2013-1846)

Philip Martin and Ben Reser discovered that the Subversion mod_dav_svn
module for Apache did not properly handle certain LOCKs. A remote
attacker could use this flaw to cause Subversion to crash, leading to
a denial of service. (CVE-2013-1847)

It was discovered that the Subversion mod_dav_svn module for Apache
did not properly handle certain PROPFIND requests. A remote attacker
could use this flaw to cause Subversion to crash, leading to a denial
of service. (CVE-2013-1849)

Greg McMullin, Stefan Fuhrmann, Philip Martin, and Ben Reser
discovered that the Subversion mod_dav_svn module for Apache did not
properly handle certain log REPORT requests. A remote attacker could
use this flaw to cause Subversion to crash, leading to a denial of
service. This issue only affected Ubuntu 12.10 and Ubuntu 13.04.
(CVE-2013-1884)

Stefan Sperling discovered that Subversion incorrectly handled newline
characters in filenames. A remote authenticated attacker could use
this flaw to corrupt FSFS repositories. (CVE-2013-1968)

Boris Lytochkin discovered that Subversion incorrectly handled TCP
connections that were closed early. A remote attacker could use this
flaw to cause Subversion to crash, leading to a denial of service.
(CVE-2013-2112).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libapache2-svn and / or libsvn1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");
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

if (ubuntu_check(osver:"12.04", pkgname:"libapache2-svn", pkgver:"1.6.17dfsg-3ubuntu3.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libsvn1", pkgver:"1.6.17dfsg-3ubuntu3.3")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libapache2-svn", pkgver:"1.7.5-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libsvn1", pkgver:"1.7.5-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libapache2-svn", pkgver:"1.7.5-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libsvn1", pkgver:"1.7.5-1ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-svn / libsvn1");
}
