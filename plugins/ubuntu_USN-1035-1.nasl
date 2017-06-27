#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1035-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51421);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2010-2640", "CVE-2010-2641", "CVE-2010-2642", "CVE-2010-2643");
  script_osvdb_id(70300, 70301, 70302, 70303);
  script_xref(name:"USN", value:"1035-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : evince vulnerabilities (USN-1035-1)");
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
"Jon Larimer discovered that Evince's font parsers incorrectly handled
certain buffer lengths when rendering a DVI file. By tricking a user
into opening or previewing a DVI file that uses a specially crafted
font file, an attacker could crash evince or execute arbitrary code
with the user's privileges.

In the default installation of Ubuntu 9.10 and later, attackers would
be isolated by the Evince AppArmor profile.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evince-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evince-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evince-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evince-gtk-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.0-evince-2.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libevdocument-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libevdocument1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libevdocument2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libevdocument3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libevview-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libevview1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libevview2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libevview3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/06");
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

if (ubuntu_check(osver:"8.04", pkgname:"evince", pkgver:"2.22.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"evince-dbg", pkgver:"2.22.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"evince-gtk", pkgver:"2.22.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"evince-gtk-dbg", pkgver:"2.22.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"evince", pkgver:"2.28.1-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"evince-dbg", pkgver:"2.28.1-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libevdocument-dev", pkgver:"2.28.1-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libevdocument1", pkgver:"2.28.1-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libevview-dev", pkgver:"2.28.1-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libevview1", pkgver:"2.28.1-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"evince", pkgver:"2.30.3-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"evince-dbg", pkgver:"2.30.3-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libevdocument-dev", pkgver:"2.30.3-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libevdocument2", pkgver:"2.30.3-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libevview-dev", pkgver:"2.30.3-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libevview2", pkgver:"2.30.3-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"evince", pkgver:"2.32.0-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"evince-common", pkgver:"2.32.0-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"evince-dbg", pkgver:"2.32.0-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"evince-gtk", pkgver:"2.32.0-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"gir1.0-evince-2.32", pkgver:"2.32.0-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libevdocument-dev", pkgver:"2.32.0-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libevdocument3", pkgver:"2.32.0-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libevview-dev", pkgver:"2.32.0-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libevview3", pkgver:"2.32.0-0ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evince / evince-common / evince-dbg / evince-gtk / evince-gtk-dbg / etc");
}
