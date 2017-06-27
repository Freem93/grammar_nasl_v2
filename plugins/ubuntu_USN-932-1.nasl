#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-932-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45576);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2010-0436");
  script_osvdb_id(63814);
  script_xref(name:"USN", value:"932-1");

  script_name(english:"Ubuntu 8.10 / 9.04 / 9.10 : kdebase-workspace vulnerability (USN-932-1)");
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
"Sebastian Krahmer discovered a race condition in the KDE Display
Manager (KDM). A local attacker could exploit this to change the
permissions on arbitrary files, thus allowing privilege escalation.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kde-window-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-workspace-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-workspace-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-workspace-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-workspace-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-workspace-kgreet-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-workspace-libs4+5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-workspace-wallpapers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:klipper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksysguard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksysguardd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kwin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdecorations4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkwineffects1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libplasma-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libplasma2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:plasma-dataengines-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:plasma-scriptengine-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:plasma-scriptengine-qedje");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:plasma-scriptengine-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:plasma-scriptengine-webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:plasma-scriptengines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:plasma-widgets-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-plasma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-plasma-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemsettings");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/20");
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
if (! ereg(pattern:"^(8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.10", pkgname:"kde-window-manager", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdebase-workspace", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdebase-workspace-bin", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdebase-workspace-data", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdebase-workspace-dbg", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdebase-workspace-dev", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdebase-workspace-libs4+5", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdebase-workspace-wallpapers", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdm", pkgver:"4:4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"klipper", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ksysguard", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ksysguardd", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kwin", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libkdecorations4", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libkwineffects1", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libplasma-dev", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libplasma2", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-plasma", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-plasma-examples", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"systemsettings", pkgver:"4.1.4-0ubuntu1~intrepid3.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kde-window-manager", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdebase-workspace", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdebase-workspace-bin", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdebase-workspace-data", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdebase-workspace-dbg", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdebase-workspace-dev", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdebase-workspace-libs4+5", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdebase-workspace-wallpapers", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdm", pkgver:"4:4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"klipper", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ksysguard", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ksysguardd", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kwin", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkdecorations4", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkwineffects1", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-plasma", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"systemsettings", pkgver:"4.2.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kde-window-manager", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdebase-workspace", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdebase-workspace-bin", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdebase-workspace-data", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdebase-workspace-dbg", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdebase-workspace-dev", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdebase-workspace-kgreet-plugins", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdebase-workspace-libs4+5", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdebase-workspace-wallpapers", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdm", pkgver:"4:4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"klipper", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ksysguard", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ksysguardd", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kwin", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkdecorations4", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkwineffects1", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"plasma-dataengines-workspace", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"plasma-scriptengine-python", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"plasma-scriptengine-qedje", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"plasma-scriptengine-ruby", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"plasma-scriptengine-webkit", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"plasma-scriptengines", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"plasma-widgets-workspace", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"systemsettings", pkgver:"4.3.2-0ubuntu7.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kde-window-manager / kdebase-workspace / kdebase-workspace-bin / etc");
}
