#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2721-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85579);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/24 17:44:50 $");

  script_cve_id("CVE-2014-3580", "CVE-2014-8108", "CVE-2015-0202", "CVE-2015-0248", "CVE-2015-0251", "CVE-2015-3184", "CVE-2015-3187");
  script_osvdb_id(115921, 115922, 120098, 120099, 120121, 125798, 125799);
  script_xref(name:"USN", value:"2721-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 : subversion vulnerabilities (USN-2721-1)");
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
"It was discovered that the Subversion mod_dav_svn module incorrectly
handled REPORT requests for a resource that does not exist. A remote
attacker could use this issue to cause the server to crash, resulting
in a denial of service. This issue only affected Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2014-3580)

It was discovered that the Subversion mod_dav_svn module incorrectly
handled requests requiring a lookup for a virtual transaction name
that does not exist. A remote attacker could use this issue to cause
the server to crash, resulting in a denial of service. This issue only
affected Ubuntu 14.04 LTS. (CVE-2014-8108)

Evgeny Kotkov discovered that the Subversion mod_dav_svn module
incorrectly handled large numbers of REPORT requests. A remote
attacker could use this issue to cause the server to crash, resulting
in a denial of service. This issue only affected Ubuntu 14.04 LTS and
Ubuntu 15.04. (CVE-2015-0202)

Evgeny Kotkov discovered that the Subversion mod_dav_svn and svnserve
modules incorrectly certain crafted parameter combinations. A remote
attacker could use this issue to cause the server to crash, resulting
in a denial of service. (CVE-2015-0248)

Ivan Zhakov discovered that the Subversion mod_dav_svn module
incorrectly handled crafted v1 HTTP protocol request sequences. A
remote attacker could use this issue to spoof the svn:author property.
(CVE-2015-0251)

C. Michael Pilato discovered that the Subversion mod_dav_svn module
incorrectly restricted anonymous access. A remote attacker could use
this issue to read hidden files via the path name. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-3184)

C. Michael Pilato discovered that Subversion incorrectly handled
path-based authorization. A remote attacker could use this issue to
obtain sensitive path information. (CVE-2015-3187).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libapache2-svn, libsvn1 and / or subversion
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libapache2-svn", pkgver:"1.6.17dfsg-3ubuntu3.5")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libsvn1", pkgver:"1.6.17dfsg-3ubuntu3.5")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"subversion", pkgver:"1.6.17dfsg-3ubuntu3.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libapache2-svn", pkgver:"1.8.8-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libsvn1", pkgver:"1.8.8-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"subversion", pkgver:"1.8.8-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libapache2-svn", pkgver:"1.8.10-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libsvn1", pkgver:"1.8.10-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"subversion", pkgver:"1.8.10-5ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-svn / libsvn1 / subversion");
}
