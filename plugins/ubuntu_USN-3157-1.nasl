#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3157-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95873);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2017/03/21 13:39:52 $");

  script_cve_id("CVE-2016-9949", "CVE-2016-9950", "CVE-2016-9951");
  script_osvdb_id(148859, 148860, 148965);
  script_xref(name:"USN", value:"3157-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : apport vulnerabilities (USN-3157-1)");
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
"Donncha O Cearbhaill discovered that the crash file parser in Apport
improperly treated the CrashDB field as python code. An attacker could
use this to convince a user to open a maliciously crafted crash file
and execute arbitrary code with the privileges of that user. This
issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-9949)

Donncha O Cearbhaill discovered that Apport did not properly sanitize
the Package and SourcePackage fields in crash files before processing
package specific hooks. An attacker could use this to convince a user
to open a maliciously crafted crash file and execute arbitrary code
with the privileges of that user. (CVE-2016-9950)

Donncha O Cearbhaill discovered that Apport would offer to restart an
application based on the contents of the RespawnCommand or ProcCmdline
fields in a crash file. An attacker could use this to convince a user
to open a maliciously crafted crash file and execute arbitrary code
with the privileges of that user. (CVE-2016-9951).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-apport");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016-2017 Canonical, Inc. / NASL script (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"apport", pkgver:"2.0.1-0ubuntu17.15")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"apport-gtk", pkgver:"2.0.1-0ubuntu17.15")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"apport-kde", pkgver:"2.0.1-0ubuntu17.15")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python-apport", pkgver:"2.0.1-0ubuntu17.15")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"apport", pkgver:"2.14.1-0ubuntu3.23")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"apport-gtk", pkgver:"2.14.1-0ubuntu3.23")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"apport-kde", pkgver:"2.14.1-0ubuntu3.23")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python-apport", pkgver:"2.14.1-0ubuntu3.23")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python3-apport", pkgver:"2.14.1-0ubuntu3.23")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"apport", pkgver:"2.20.1-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"apport-gtk", pkgver:"2.20.1-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"apport-kde", pkgver:"2.20.1-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python-apport", pkgver:"2.20.1-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python3-apport", pkgver:"2.20.1-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"apport", pkgver:"2.20.3-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"apport-gtk", pkgver:"2.20.3-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"apport-kde", pkgver:"2.20.3-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"python-apport", pkgver:"2.20.3-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"python3-apport", pkgver:"2.20.3-0ubuntu8.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apport / apport-gtk / apport-kde / python-apport / python3-apport");
}
