#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-727-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37740);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:37:18 $");

  script_cve_id("CVE-2009-0365", "CVE-2009-0578");
  script_osvdb_id(53653, 53654);
  script_xref(name:"USN", value:"727-2");

  script_name(english:"Ubuntu 6.06 LTS / 8.10 : network-manager vulnerability (USN-727-2)");
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
"USN-727-1 fixed vulnerabilities in network-manager-applet. This
advisory provides the corresponding updates for NetworkManager.

It was discovered that NetworkManager did not properly enforce
permissions when responding to dbus requests. A local user could
perform dbus queries to view system and user network connection
passwords and pre-shared keys.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnm-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnm-glib0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnm-glib0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnm-util-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnm-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnm-util0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:network-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:network-manager-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:network-manager-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:network-manager-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:network-manager-gnome-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! ereg(pattern:"^(6\.06|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libnm-glib-dev", pkgver:"0.6.2-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnm-glib0", pkgver:"0.6.2-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnm-glib0-dbg", pkgver:"0.6.2-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnm-util-dev", pkgver:"0.6.2-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnm-util0", pkgver:"0.6.2-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnm-util0-dbg", pkgver:"0.6.2-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"network-manager", pkgver:"0.6.2-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"network-manager-dbg", pkgver:"0.6.2-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"network-manager-dev", pkgver:"0.6.2-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"network-manager-gnome", pkgver:"0.6.2-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"network-manager-gnome-dbg", pkgver:"0.6.2-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libnm-glib-dev", pkgver:"0.7~~svn20081018t105859-0ubuntu1.8.10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libnm-glib0", pkgver:"0.7~~svn20081018t105859-0ubuntu1.8.10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libnm-util-dev", pkgver:"0.7~~svn20081018t105859-0ubuntu1.8.10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libnm-util0", pkgver:"0.7~~svn20081018t105859-0ubuntu1.8.10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"network-manager", pkgver:"0.7~~svn20081018t105859-0ubuntu1.8.10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"network-manager-dev", pkgver:"0.7~~svn20081018t105859-0ubuntu1.8.10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnm-glib-dev / libnm-glib0 / libnm-glib0-dbg / libnm-util-dev / etc");
}
