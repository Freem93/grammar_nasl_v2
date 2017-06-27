#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-163-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20569);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2005-2097");
  script_xref(name:"USN", value:"163-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : xpdf vulnerability (USN-163-1)");
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
"xpdf and kpdf did not sufficiently verify the validity of the 'loca'
table in PDF files, a table that contains glyph description
information for embedded TrueType fonts. After detecting the broken
table, xpdf attempted to reconstruct the information in it, which
caused the generation of a huge temporary file that quickly filled up
available disk space and rendered the application unresponsive.

The CUPS printing system in Ubuntu 5.04 uses the xpdf-utils package to
convert PDF files to PostScript. By attempting to print such a crafted
PDF file, a remote attacker could cause a Denial of Service in a print
server. The CUPS system in Ubuntu 4.10 is not vulnerable against this
attack.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kcoloredit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-dev");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xpdf-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xpdf-reader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xpdf-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/09");
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
if (! ereg(pattern:"^(4\.10|5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"xpdf", pkgver:"3.00-11ubuntu3.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf-common", pkgver:"3.00-11ubuntu3.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf-reader", pkgver:"3.00-11ubuntu3.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf-utils", pkgver:"3.00-11ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kamera", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kcoloredit", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdegraphics", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdegraphics-dev", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdegraphics-kfile-plugins", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdvi", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kfax", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kgamma", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kghostview", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kiconedit", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kmrml", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kolourpaint", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kooka", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kpdf", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kpovmodeler", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kruler", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ksnapshot", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ksvg", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kuickshow", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kview", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kviewshell", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkscan-dev", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkscan1", pkgver:"3.4.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf", pkgver:"3.00-8ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf-common", pkgver:"3.00-8ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf-reader", pkgver:"3.00-8ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf-utils", pkgver:"3.00-8ubuntu1.5")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
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
