#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2793-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86784);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/05/24 17:44:51 $");

  script_cve_id("CVE-2015-4551", "CVE-2015-5212", "CVE-2015-5213", "CVE-2015-5214");
  script_osvdb_id(129856, 129857, 129858, 129859);
  script_xref(name:"USN", value:"2793-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 : libreoffice vulnerabilities (USN-2793-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Federico Scrinzi discovered that LibreOffice incorrectly handled
documents inserted into Writer or Calc via links. If a user were
tricked into opening a specially crafted document, a remote attacker
could possibly obtain the contents of arbitrary files. (CVE-2015-4551)

It was discovered that LibreOffice incorrectly handled PrinterSetup
data stored in ODF files. If a user were tricked into opening a
specially crafted ODF document, a remote attacker could cause
LibreOffice to crash, and possibly execute arbitrary code.
(CVE-2015-5212)

It was discovered that LibreOffice incorrectly handled the number of
pieces in DOC files. If a user were tricked into opening a specially
crafted DOC document, a remote attacker could cause LibreOffice to
crash, and possibly execute arbitrary code. (CVE-2015-5213)

It was discovered that LibreOffice incorrectly handled bookmarks in
DOC files. If a user were tricked into opening a specially crafted DOC
document, a remote attacker could cause LibreOffice to crash, and
possibly execute arbitrary code. (CVE-2015-5214).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreoffice-core package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/06");
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

if (ubuntu_check(osver:"12.04", pkgname:"libreoffice-core", pkgver:"1:3.5.7-0ubuntu9")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libreoffice-core", pkgver:"1:4.2.8-0ubuntu3")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libreoffice-core", pkgver:"1:4.4.6~rc3-0ubuntu1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreoffice-core");
}
