#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-115-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20503);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/26 16:14:08 $");

  script_cve_id("CVE-2005-0754");
  script_xref(name:"USN", value:"115-1");

  script_name(english:"Ubuntu 5.04 : kdewebdev vulnerability (USN-115-1)");
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
"Eckhart Worner discovered that Kommander opens files from remote and
possibly untrusted locations without user confirmation. Since
Kommander files can contain scripts, this would allow an attacker to
execute arbitrary code with the privileges of the user opening the
file.

The updated Kommander will not automatically open files from remote
locations, and files which do not end with '.kmdr' any more.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdewebdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdewebdev-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kfilereplace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kimagemapeditor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:klinkstatus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kommander");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kommander-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kxsldbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:quanta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:quanta-data");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"kdewebdev", pkgver:"3.4.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdewebdev-doc-html", pkgver:"3.4.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kfilereplace", pkgver:"3.4.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kimagemapeditor", pkgver:"3.4.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"klinkstatus", pkgver:"3.4.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kommander", pkgver:"3.4.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kommander-dev", pkgver:"3.4.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kxsldbg", pkgver:"3.4.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"quanta", pkgver:"3.4.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"quanta-data", pkgver:"3.4.0-0ubuntu2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdewebdev / kdewebdev-doc-html / kfilereplace / kimagemapeditor / etc");
}
