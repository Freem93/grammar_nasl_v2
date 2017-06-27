#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1284-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56971);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/25 16:11:44 $");

  script_cve_id("CVE-2011-3152", "CVE-2011-3154");
  script_osvdb_id(77641, 77642);
  script_xref(name:"USN", value:"1284-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 / 11.10 : update-manager vulnerabilities (USN-1284-1)");
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
"David Black discovered that Update Manager incorrectly extracted the
downloaded upgrade tarball before verifying its GPG signature. If a
remote attacker were able to perform a man-in-the-middle attack, this
flaw could potentially be used to replace arbitrary files.
(CVE-2011-3152)

David Black discovered that Update Manager created a temporary
directory in an insecure fashion. A local attacker could possibly use
this flaw to read the XAUTHORITY file of the user performing the
upgrade. (CVE-2011-3154)

This update also adds a hotfix to Update Notifier to handle cases
where the upgrade is being performed from CD media.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected auto-upgrade-tester, update-manager and / or
update-notifier packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:auto-upgrade-tester");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:update-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:update-notifier");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"update-manager", pkgver:"1:0.87.31.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"auto-upgrade-tester", pkgver:"1:0.134.11.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"update-notifier", pkgver:"0.99.3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"update-manager", pkgver:"1:0.142.23.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"update-notifier", pkgver:"0.105ubuntu1.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"update-manager", pkgver:"1:0.150.5.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"update-notifier", pkgver:"0.111ubuntu2.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"update-manager", pkgver:"1:0.152.25.5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "auto-upgrade-tester / update-manager / update-notifier");
}
