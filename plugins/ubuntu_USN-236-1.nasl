#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-236-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20781);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627");
  script_xref(name:"USN", value:"236-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : xpdf, poppler, cupsys, tetex-bin vulnerabilities (USN-236-1)");
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
"Chris Evans discovered several integer overflows in the XPDF code,
which is present in xpdf, the Poppler library, and tetex-bin. By
tricking an user into opening a specially crafted PDF file, an
attacker could exploit this to execute arbitrary code with the
privileges of the application that processes the document.

The CUPS printing system also uses XPDF code to convert PDF files to
PostScript. By attempting to print such a crafted PDF file, a remote
attacker could execute arbitrary code with the privileges of the
printer server (user 'cupsys').

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-gnutls10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler0c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler0c2-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler0c2-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xpdf-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xpdf-reader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xpdf-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"4.10", pkgname:"cupsys", pkgver:"1.1.20final+cvs20040330-4ubuntu16.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cupsys-bsd", pkgver:"1.1.20final+cvs20040330-4ubuntu16.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cupsys-client", pkgver:"1.1.20final+cvs20040330-4ubuntu16.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsimage2", pkgver:"1.1.20final+cvs20040330-4ubuntu16.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsimage2-dev", pkgver:"1.1.20final+cvs20040330-4ubuntu16.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsys2-dev", pkgver:"1.1.20final+cvs20040330-4ubuntu16.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsys2-gnutls10", pkgver:"1.1.20final+cvs20040330-4ubuntu16.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkpathsea-dev", pkgver:"2.0.2-21ubuntu0.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkpathsea3", pkgver:"2.0.2-21ubuntu0.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"tetex-bin", pkgver:"2.0.2-21ubuntu0.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf", pkgver:"3.00-8ubuntu1.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf-common", pkgver:"3.00-8ubuntu1.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf-reader", pkgver:"3.00-8ubuntu1.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf-utils", pkgver:"3.00-8ubuntu1.10")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkpathsea-dev", pkgver:"2.0.2-25ubuntu0.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkpathsea3", pkgver:"2.0.2-25ubuntu0.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"tetex-bin", pkgver:"2.0.2-25ubuntu0.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf", pkgver:"3.00-11ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf-common", pkgver:"3.00-11ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf-reader", pkgver:"3.00-11ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf-utils", pkgver:"3.00-11ubuntu3.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkpathsea-dev", pkgver:"2.0.2-30ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkpathsea3", pkgver:"2.0.2-30ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler-dev", pkgver:"0.4.2-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler-glib-dev", pkgver:"0.4.2-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler-qt-dev", pkgver:"0.4.2-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler0c2", pkgver:"0.4.2-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler0c2-glib", pkgver:"0.4.2-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler0c2-qt", pkgver:"0.4.2-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"poppler-utils", pkgver:"0.4.2-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"tetex-bin", pkgver:"2.0.2-30ubuntu3.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cupsys / cupsys-bsd / cupsys-client / libcupsimage2 / etc");
}
