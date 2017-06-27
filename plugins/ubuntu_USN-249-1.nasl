#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-249-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21058);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2006-0301");
  script_osvdb_id(22833);
  script_xref(name:"USN", value:"249-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : xpdf, poppler, kdegraphics vulnerabilities (USN-249-1)");
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
"The splash image handler in xpdf did not check the validity of
coordinates. By tricking a user into opening a specially crafted PDF
file, an attacker could exploit this to trigger a buffer overflow
which could lead to arbitrary code execution with the privileges of
the user.

The poppler library and kpdf also contain xpdf code, and thus are
affected by the same vulnerability.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kcoloredit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-kfile-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kgamma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kghostview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kiconedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kmrml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kolourpaint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kooka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpovmodeler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kruler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksnapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kuickshow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kviewshell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkscan-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkscan1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler0c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler0c2-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler0c2-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xpdf-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xpdf-reader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xpdf-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/01");
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

if (ubuntu_check(osver:"4.10", pkgname:"xpdf", pkgver:"3.00-8ubuntu1.11")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf-common", pkgver:"3.00-8ubuntu1.11")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf-reader", pkgver:"3.00-8ubuntu1.11")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf-utils", pkgver:"3.00-8ubuntu1.11")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kamera", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kcoloredit", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdegraphics", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdegraphics-dev", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdegraphics-kfile-plugins", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdvi", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kfax", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kgamma", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kghostview", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kiconedit", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kmrml", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kolourpaint", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kooka", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kpdf", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kpovmodeler", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kruler", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ksnapshot", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ksvg", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kuickshow", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kview", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kviewshell", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkscan-dev", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkscan1", pkgver:"3.4.0-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf", pkgver:"3.00-11ubuntu3.7")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf-common", pkgver:"3.00-11ubuntu3.7")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf-reader", pkgver:"3.00-11ubuntu3.7")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf-utils", pkgver:"3.00-11ubuntu3.7")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kamera", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kcoloredit", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdegraphics", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdegraphics-dev", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdegraphics-doc-html", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdegraphics-kfile-plugins", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdvi", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kfax", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kgamma", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kghostview", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kiconedit", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kmrml", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kolourpaint", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kooka", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kpdf", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kpovmodeler", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kruler", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ksnapshot", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ksvg", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kuickshow", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kview", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kviewshell", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkscan-dev", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkscan1", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler-dev", pkgver:"0.4.2-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler-glib-dev", pkgver:"0.4.2-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler-qt-dev", pkgver:"0.4.2-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler0c2", pkgver:"0.4.2-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler0c2-glib", pkgver:"0.4.2-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler0c2-qt", pkgver:"0.4.2-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"poppler-utils", pkgver:"0.4.2-0ubuntu6.6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kamera / kcoloredit / kdegraphics / kdegraphics-dev / etc");
}
