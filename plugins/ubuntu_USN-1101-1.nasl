#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1101-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53287);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_xref(name:"USN", value:"1101-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : qt4-x11 vulnerabilities (USN-1101-1)");
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
"It was discovered that several invalid HTTPS certificates were issued
and revoked. An attacker could exploit these to perform a man in the
middle attack to view sensitive information or alter encrypted
communications. These were placed on the certificate blacklist to
prevent their misuse.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphonon-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphonon4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-declarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-declarative-folderlistmodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-declarative-gestures");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-declarative-particles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-dev-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-multimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-opengl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-phonon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-phonon-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-scripttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-sqlite2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-tds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-svg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-webkit-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-xmlpatterns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-xmlpatterns-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqtcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqtgui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:phonon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:phonon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-demos-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-dev-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-dev-tools-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-qmake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-qmlviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-qtconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/04");
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
if (! ereg(pattern:"^(8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libqt4-core", pkgver:"4.3.4-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libqt4-debug", pkgver:"4.3.4-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libqt4-dev", pkgver:"4.3.4-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libqt4-gui", pkgver:"4.3.4-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libqt4-qt3support", pkgver:"4.3.4-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libqt4-sql", pkgver:"4.3.4-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"qt4-designer", pkgver:"4.3.4-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"qt4-dev-tools", pkgver:"4.3.4-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"qt4-doc", pkgver:"4.3.4-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"qt4-qtconfig", pkgver:"4.3.4-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-assistant", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-core", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-dbg", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-dbus", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-designer", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-dev", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-dev-dbg", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-gui", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-help", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-network", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-opengl", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-opengl-dev", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-phonon", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-phonon-dev", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-qt3support", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-script", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-scripttools", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-sql", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-sql-mysql", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-sql-odbc", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-sql-psql", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-sql-sqlite", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-sql-sqlite2", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-svg", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-test", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-webkit", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-webkit-dbg", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-xml", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-xmlpatterns", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqt4-xmlpatterns-dbg", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqtcore4", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libqtgui4", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"qt4-demos", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"qt4-demos-dbg", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"qt4-designer", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"qt4-dev-tools", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"qt4-dev-tools-dbg", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"qt4-doc", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"qt4-doc-html", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"qt4-qmake", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"qt4-qtconfig", pkgver:"4.5.3really4.5.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libphonon-dev", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libphonon4", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-assistant", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-core", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-dbg", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-dbus", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-designer", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-dev", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-gui", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-help", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-multimedia", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-network", pkgver:"4:4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-opengl", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-opengl-dev", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-phonon", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-phonon-dev", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-qt3support", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-script", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-scripttools", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-sql", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-sql-mysql", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-sql-odbc", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-sql-psql", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-sql-sqlite", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-sql-sqlite2", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-sql-tds", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-svg", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-test", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-webkit", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-webkit-dbg", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-xml", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-xmlpatterns", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqt4-xmlpatterns-dbg", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqtcore4", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libqtgui4", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"phonon", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"phonon-dbg", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qt4-demos", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qt4-demos-dbg", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qt4-designer", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qt4-dev-tools", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qt4-doc", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qt4-doc-html", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qt4-qmake", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qt4-qtconfig", pkgver:"4.6.2-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-assistant", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-core", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-dbg", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-dbus", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-declarative", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-declarative-folderlistmodel", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-declarative-gestures", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-declarative-particles", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-designer", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-dev", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-gui", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-help", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-network", pkgver:"4:4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-opengl", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-opengl-dev", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-qt3support", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-script", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-scripttools", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-sql", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-sql-mysql", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-sql-odbc", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-sql-psql", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-sql-sqlite", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-sql-sqlite2", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-sql-tds", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-svg", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-test", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-webkit", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-webkit-dbg", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-xml", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-xmlpatterns", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqt4-xmlpatterns-dbg", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqtcore4", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libqtgui4", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qt4-demos", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qt4-demos-dbg", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qt4-designer", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qt4-dev-tools", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qt4-doc", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qt4-doc-html", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qt4-qmake", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qt4-qmlviewer", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qt4-qtconfig", pkgver:"4.7.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qt4-x11", pkgver:"4.7.0-0ubuntu4.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libphonon-dev / libphonon4 / libqt4-assistant / libqt4-core / etc");
}
