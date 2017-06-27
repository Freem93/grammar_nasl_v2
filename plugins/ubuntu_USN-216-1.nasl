#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-216-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20634);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/04 15:13:58 $");

  script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
  script_osvdb_id(20840, 20841);
  script_xref(name:"USN", value:"216-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : gtk+2.0, gdk-pixbuf vulnerabilities (USN-216-1)");
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
"Two integer overflows have been discovered in the XPM image loader of
the GDK pixbuf library. By tricking an user into opening a specially
crafted XPM image with any Gnome desktop application that uses this
library, this could be exploited to execute arbitrary code with the
privileges of the user running the application. (CVE-2005-2976,
CVE-2005-3186)

Additionally, specially crafted XPM images could cause an endless loop
in the image loader, which could be exploited to cause applications
trying to open that image to hang. (CVE-2005-2975).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gtk2-engines-pixbuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gtk2.0-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdk-pixbuf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdk-pixbuf-gnome-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdk-pixbuf-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdk-pixbuf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk2.0-0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk2.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk2.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk2.0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk2.0-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2017 Canonical, Inc. / NASL script (C) 2006-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"gtk2.0-examples", pkgver:"2.4.10-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgdk-pixbuf-dev", pkgver:"0.22.0-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgdk-pixbuf-gnome-dev", pkgver:"0.22.0-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgdk-pixbuf-gnome2", pkgver:"0.22.0-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgdk-pixbuf2", pkgver:"0.22.0-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgtk2.0-0", pkgver:"2.4.10-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgtk2.0-bin", pkgver:"2.4.10-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgtk2.0-common", pkgver:"2.4.10-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgtk2.0-dbg", pkgver:"2.4.10-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgtk2.0-dev", pkgver:"2.4.10-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgtk2.0-doc", pkgver:"2.4.10-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gtk2-engines-pixbuf", pkgver:"2.6.4-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gtk2.0-examples", pkgver:"2.6.4-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgdk-pixbuf-dev", pkgver:"0.22.0-7ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgdk-pixbuf-gnome-dev", pkgver:"0.22.0-7ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgdk-pixbuf-gnome2", pkgver:"0.22.0-7ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgdk-pixbuf2", pkgver:"0.22.0-7ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgtk2.0-0", pkgver:"2.6.4-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgtk2.0-0-dbg", pkgver:"2.6.4-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgtk2.0-bin", pkgver:"2.6.4-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgtk2.0-common", pkgver:"2.6.4-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgtk2.0-dev", pkgver:"2.6.4-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgtk2.0-doc", pkgver:"2.6.4-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gtk2-engines-pixbuf", pkgver:"2.8.6-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gtk2.0-examples", pkgver:"2.8.6-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgdk-pixbuf-dev", pkgver:"0.22.0-8ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgdk-pixbuf-gnome-dev", pkgver:"0.22.0-8ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgdk-pixbuf-gnome2", pkgver:"0.22.0-8ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgdk-pixbuf2", pkgver:"0.22.0-8ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgtk2.0-0", pkgver:"2.8.6-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgtk2.0-0-dbg", pkgver:"2.8.6-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgtk2.0-bin", pkgver:"2.8.6-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgtk2.0-common", pkgver:"2.8.6-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgtk2.0-dev", pkgver:"2.8.6-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgtk2.0-doc", pkgver:"2.8.6-0ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gtk2-engines-pixbuf / gtk2.0-examples / libgdk-pixbuf-dev / etc");
}
