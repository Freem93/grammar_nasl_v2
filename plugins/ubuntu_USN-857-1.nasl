#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-857-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42467);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-0945", "CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698", "CVE-2009-1699", "CVE-2009-1711", "CVE-2009-1712", "CVE-2009-1713", "CVE-2009-1725");
  script_bugtraq_id(34924, 35271, 35309, 35318);
  script_osvdb_id(54455, 54500, 54972, 54975, 54985, 55006, 55015, 55022, 55414, 55417, 55418, 55739);
  script_xref(name:"USN", value:"857-1");

  script_name(english:"Ubuntu 8.10 / 9.04 : qt4-x11 vulnerabilities (USN-857-1)");
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
"It was discovered that QtWebKit did not properly handle certain
SVGPathList data structures. If a user were tricked into viewing a
malicious website, an attacker could exploit this to execute arbitrary
code with the privileges of the user invoking the program.
(CVE-2009-0945)

Several flaws were discovered in the QtWebKit browser and JavaScript
engines. If a user were tricked into viewing a malicious website, a
remote attacker could cause a denial of service or possibly execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2009-1687, CVE-2009-1690, CVE-2009-1698, CVE-2009-1711,
CVE-2009-1725)

It was discovered that QtWebKit did not properly handle certain XSL
stylesheets. If a user were tricked into viewing a malicious website,
an attacker could exploit this to read arbitrary local files, and
possibly files from different security zones. (CVE-2009-1699,
CVE-2009-1713)

It was discovered that QtWebKit did not prevent the loading of local
Java applets. If a user were tricked into viewing a malicious website,
an attacker could exploit this to execute arbitrary code with the
privileges of the user invoking the program. (CVE-2009-1712).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 189, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-dev-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-opengl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-scripttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-sql-sqlite2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-svg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-webkit-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-xmlpatterns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt4-xmlpatterns-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqtcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqtgui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-demos-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-dev-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-dev-tools-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-qmake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt4-qtconfig");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/11");
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
if (! ereg(pattern:"^(8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.10", pkgname:"libqt4-assistant", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-core", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-dbg", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-dbus", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-designer", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-dev", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-gui", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-help", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-network", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-opengl", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-opengl-dev", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-qt3support", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-script", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-sql", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-sql-mysql", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-sql-odbc", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-sql-psql", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-sql-sqlite", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-sql-sqlite2", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-svg", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-test", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-webkit", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-webkit-dbg", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-xml", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-xmlpatterns", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqt4-xmlpatterns-dbg", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqtcore4", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libqtgui4", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"qt4-demos", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"qt4-designer", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"qt4-dev-tools", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"qt4-doc", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"qt4-doc-html", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"qt4-qtconfig", pkgver:"4.4.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-assistant", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-core", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-dbg", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-dbus", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-designer", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-dev", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-dev-dbg", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-gui", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-help", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-network", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-opengl", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-opengl-dev", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-qt3support", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-script", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-scripttools", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-sql", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-sql-mysql", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-sql-odbc", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-sql-psql", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-sql-sqlite", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-sql-sqlite2", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-svg", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-test", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-webkit", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-webkit-dbg", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-xml", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-xmlpatterns", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqt4-xmlpatterns-dbg", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqtcore4", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libqtgui4", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"qt4-demos", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"qt4-demos-dbg", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"qt4-designer", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"qt4-dev-tools", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"qt4-dev-tools-dbg", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"qt4-doc", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"qt4-doc-html", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"qt4-qmake", pkgver:"4.5.0-0ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"qt4-qtconfig", pkgver:"4.5.0-0ubuntu4.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqt4-assistant / libqt4-core / libqt4-dbg / libqt4-dbus / etc");
}
