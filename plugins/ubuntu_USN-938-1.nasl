#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-938-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46336);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2010-1000", "CVE-2010-1511");
  script_bugtraq_id(40141);
  script_osvdb_id(64689, 64690);
  script_xref(name:"USN", value:"938-1");

  script_name(english:"Ubuntu 9.04 / 9.10 / 10.04 LTS : kdenetwork vulnerabilities (USN-938-1)");
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
"It was discovered that KGet did not properly perform input validation
when processing metalink files. If a user were tricked into opening a
crafted metalink file, a remote attacker could overwrite files via
directory traversal, which could eventually lead to arbitrary code
execution. (CVE-2010-1000)

It was discovered that KGet would not always wait for user
confirmation when downloading metalink files. If a user selected a
file to download but did not confirm or cancel the download, KGet
would proceed with the download, overwriting any file with the same
name. This issue only affected Ubuntu 10.04 LTS. (CVE-2010-1511).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kde-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdenetwork-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdenetwork-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdenetwork-filesharing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopete-plugin-otr-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkopete-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkopete4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/14");
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
if (! ereg(pattern:"^(9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.04", pkgname:"kde-zeroconf", pkgver:"4.2.2-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdenetwork", pkgver:"4.2.2-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdenetwork-dbg", pkgver:"4.2.2-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdenetwork-dev", pkgver:"4.2.2-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdenetwork-filesharing", pkgver:"4.2.2-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kget", pkgver:"4:4.2.2-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kopete", pkgver:"4.2.2-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kopete-plugin-otr-kde4", pkgver:"4.2.2-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kppp", pkgver:"4.2.2-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krdc", pkgver:"4.2.2-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krfb", pkgver:"4.2.2-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kde-zeroconf", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdenetwork", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdenetwork-dbg", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdenetwork-filesharing", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kget", pkgver:"4:4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kopete", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kopete-plugin-otr-kde4", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kppp", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krdc", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krfb", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkopete-dev", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkopete4", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kde-zeroconf", pkgver:"4.4.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kdenetwork", pkgver:"4.4.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kdenetwork-dbg", pkgver:"4.4.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kdenetwork-filesharing", pkgver:"4.4.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kget", pkgver:"4:4.4.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kopete", pkgver:"4.4.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kopete-plugin-otr-kde4", pkgver:"4.4.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kppp", pkgver:"4.4.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krdc", pkgver:"4.4.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"krfb", pkgver:"4.4.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkopete-dev", pkgver:"4.4.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkopete4", pkgver:"4.4.2-0ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kde-zeroconf / kdenetwork / kdenetwork-dbg / kdenetwork-dev / etc");
}
