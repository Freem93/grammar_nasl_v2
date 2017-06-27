#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-768-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38647);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:37:18 $");

  script_cve_id("CVE-2009-1295");
  script_osvdb_id(54173);
  script_xref(name:"USN", value:"768-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : Apport vulnerability (USN-768-1)");
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
"Stephane Chazelas discovered that Apport did not safely remove files
from its crash report directory. If Apport had been enabled at some
point, a local attacker could remove arbitrary files from the system.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-retrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-problem-report");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"apport", pkgver:"0.108.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apport-gtk", pkgver:"0.108.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apport-qt", pkgver:"0.108.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apport-retrace", pkgver:"0.108.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-apport", pkgver:"0.108.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-problem-report", pkgver:"0.108.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apport", pkgver:"0.119.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apport-gtk", pkgver:"0.119.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apport-qt", pkgver:"0.119.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"apport-retrace", pkgver:"0.119.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-apport", pkgver:"0.119.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-problem-report", pkgver:"0.119.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apport", pkgver:"1.0-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apport-gtk", pkgver:"1.0-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apport-qt", pkgver:"1.0-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apport-retrace", pkgver:"1.0-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-apport", pkgver:"1.0-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-problem-report", pkgver:"1.0-0ubuntu5.2")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apport / apport-gtk / apport-qt / apport-retrace / python-apport / etc");
}
