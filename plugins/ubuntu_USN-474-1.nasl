#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-474-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28075);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/27 14:29:17 $");

  script_cve_id("CVE-2007-1859", "CVE-2008-0887");
  script_osvdb_id(35531);
  script_xref(name:"USN", value:"474-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 : xscreensaver vulnerability (USN-474-1)");
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
"It was discovered that xscreensaver did not correctly validate the
return values from network authentication systems such as LDAP or NIS.
A local attacker could bypass a locked screen if they were able to
interrupt network connectivity.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xscreensaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xscreensaver-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xscreensaver-data-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xscreensaver-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xscreensaver-gl-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/03");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"xscreensaver", pkgver:"4.23-4ubuntu8.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xscreensaver-data", pkgver:"4.23-4ubuntu8.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xscreensaver-data-extra", pkgver:"4.23-4ubuntu8.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xscreensaver-gl", pkgver:"4.23-4ubuntu8.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xscreensaver-gl-extra", pkgver:"4.23-4ubuntu8.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xscreensaver", pkgver:"4.24-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xscreensaver-data", pkgver:"4.24-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xscreensaver-data-extra", pkgver:"4.24-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xscreensaver-gl", pkgver:"4.24-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xscreensaver-gl-extra", pkgver:"4.24-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xscreensaver", pkgver:"4.24-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xscreensaver-data", pkgver:"4.24-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xscreensaver-data-extra", pkgver:"4.24-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xscreensaver-gl", pkgver:"4.24-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xscreensaver-gl-extra", pkgver:"4.24-5ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xscreensaver / xscreensaver-data / xscreensaver-data-extra / etc");
}
