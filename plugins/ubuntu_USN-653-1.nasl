#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-653-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36805);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-0595", "CVE-2008-3834");
  script_xref(name:"USN", value:"653-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : dbus vulnerabilities (USN-653-1)");
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
"Havoc Pennington discovered that the D-Bus daemon did not correctly
validate certain security policies. If a local user sent a specially
crafted D-Bus request, they could bypass security policies that had a
'send_interface' defined. (CVE-2008-0595)

It was discovered that the D-Bus library did not correctly validate
certain corrupted signatures. If a local user sent a specially crafted
D-Bus request, they could crash applications linked against the D-Bus
library, leading to a denial of service. (CVE-2008-3834).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus-1-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus-1-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-1-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-1-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-1-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-glib-1-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-glib-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-qt-1-1c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-qt-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:monodoc-dbus-1-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-dbus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"dbus", pkgver:"0.60-6ubuntu8.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dbus-1-doc", pkgver:"0.60-6ubuntu8.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dbus-1-utils", pkgver:"0.60-6ubuntu8.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-1-2", pkgver:"0.60-6ubuntu8.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-1-cil", pkgver:"0.60-6ubuntu8.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-1-dev", pkgver:"0.60-6ubuntu8.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-glib-1-2", pkgver:"0.60-6ubuntu8.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-glib-1-dev", pkgver:"0.60-6ubuntu8.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-qt-1-1c2", pkgver:"0.60-6ubuntu8.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-qt-1-dev", pkgver:"0.60-6ubuntu8.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"monodoc-dbus-1-manual", pkgver:"0.60-6ubuntu8.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-dbus", pkgver:"0.60-6ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"dbus", pkgver:"1.0.2-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"dbus-1-doc", pkgver:"1.0.2-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"dbus-1-utils", pkgver:"1.0.2-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libdbus-1-3", pkgver:"1.0.2-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libdbus-1-dev", pkgver:"1.0.2-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"dbus", pkgver:"1.1.1-3ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"dbus-1-doc", pkgver:"1.1.1-3ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"dbus-x11", pkgver:"1.1.1-3ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libdbus-1-3", pkgver:"1.1.1-3ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libdbus-1-dev", pkgver:"1.1.1-3ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dbus", pkgver:"1.1.20-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dbus-1-doc", pkgver:"1.1.20-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dbus-x11", pkgver:"1.1.20-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libdbus-1-3", pkgver:"1.1.20-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libdbus-1-dev", pkgver:"1.1.20-1ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus / dbus-1-doc / dbus-1-utils / dbus-x11 / libdbus-1-2 / etc");
}
