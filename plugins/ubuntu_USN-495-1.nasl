#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-495-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28097);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:29:17 $");

  script_cve_id("CVE-2007-3388");
  script_bugtraq_id(25154);
  script_osvdb_id(39385);
  script_xref(name:"USN", value:"495-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 : qt-x11-free vulnerability (USN-495-1)");
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
"Several format string vulnerabilities have been discovered in Qt
warning messages. By causing an application to process specially
crafted input data which triggered Qt warnings, this could be
exploited to execute arbitrary code with the privilege of the user
running the application.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt3-compat-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt3-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt3-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt3-mt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt3-mt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt3-mt-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt3-mt-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt3-mt-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt3-mt-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt-x11-free-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt3-apps-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt3-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt3-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt3-dev-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt3-dev-tools-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt3-dev-tools-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt3-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt3-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt3-qtconfig");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
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

if (ubuntu_check(osver:"6.06", pkgname:"libqt3-compat-headers", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libqt3-headers", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libqt3-i18n", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libqt3-mt", pkgver:"3:3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libqt3-mt-dev", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libqt3-mt-mysql", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libqt3-mt-odbc", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libqt3-mt-psql", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libqt3-mt-sqlite", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"qt-x11-free-dbg", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"qt3-apps-dev", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"qt3-assistant", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"qt3-designer", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"qt3-dev-tools", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"qt3-dev-tools-compat", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"qt3-dev-tools-embedded", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"qt3-doc", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"qt3-examples", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"qt3-linguist", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"qt3-qtconfig", pkgver:"3.3.6-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libqt3-compat-headers", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libqt3-headers", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libqt3-i18n", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libqt3-mt", pkgver:"3:3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libqt3-mt-dev", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libqt3-mt-mysql", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libqt3-mt-odbc", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libqt3-mt-psql", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libqt3-mt-sqlite", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"qt-x11-free-dbg", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"qt3-apps-dev", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"qt3-assistant", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"qt3-designer", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"qt3-dev-tools", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"qt3-dev-tools-compat", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"qt3-dev-tools-embedded", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"qt3-doc", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"qt3-examples", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"qt3-linguist", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"qt3-qtconfig", pkgver:"3.3.6-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libqt3-compat-headers", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libqt3-headers", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libqt3-i18n", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libqt3-mt", pkgver:"3:3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libqt3-mt-dev", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libqt3-mt-mysql", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libqt3-mt-odbc", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libqt3-mt-psql", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libqt3-mt-sqlite", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"qt-x11-free-dbg", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"qt3-apps-dev", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"qt3-assistant", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"qt3-designer", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"qt3-dev-tools", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"qt3-dev-tools-compat", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"qt3-dev-tools-embedded", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"qt3-doc", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"qt3-examples", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"qt3-linguist", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"qt3-qtconfig", pkgver:"3.3.8really3.3.7-0ubuntu5.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqt3-compat-headers / libqt3-headers / libqt3-i18n / libqt3-mt / etc");
}
