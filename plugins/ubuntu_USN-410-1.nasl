#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-410-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27998);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_cve_id("CVE-2007-0103", "CVE-2007-0104");
  script_osvdb_id(32870, 32871);
  script_xref(name:"USN", value:"410-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS / 6.10 : kdegraphics, koffice, poppler vulnerability (USN-410-1)");
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
"The poppler PDF loader library did not limit the recursion depth of
the page model tree. By tricking a user into opening a specially
crafter PDF file, this could be exploited to trigger an infinite loop
and eventually crash an application that uses this library.

kpdf in Ubuntu 5.10, and KOffice in all Ubuntu releases contains a
copy of this code and thus is affected as well.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kchart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kcoloredit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-kfile-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kexi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kformula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kgamma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kghostview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kiconedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kivio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kivio-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kmrml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kolourpaint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kooka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koshell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kplato");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpovmodeler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpresenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpresenter-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krita");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krita-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kruler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksnapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kspread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kthesaurus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kuickshow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kviewshell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kword-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkscan-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkscan1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler0c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler0c2-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler0c2-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler1-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler1-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler1-qt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/17");
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
if (! ereg(pattern:"^(5\.10|6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"kamera", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"karbon", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kchart", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kcoloredit", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdegraphics", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdegraphics-dev", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdegraphics-doc-html", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdegraphics-kfile-plugins", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdvi", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kfax", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kformula", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kgamma", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kghostview", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kiconedit", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kivio", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kivio-data", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kmrml", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"koffice", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"koffice-data", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"koffice-dev", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"koffice-doc-html", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"koffice-libs", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kolourpaint", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kooka", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"koshell", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kpdf", pkgver:"4:3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kpovmodeler", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kpresenter", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"krita", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kruler", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ksnapshot", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kspread", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ksvg", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kthesaurus", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kugar", pkgver:"1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kuickshow", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kview", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kviewshell", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kword", pkgver:"1:1.4.1-0ubuntu7.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkscan-dev", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkscan1", pkgver:"3.4.3-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler-dev", pkgver:"0.4.2-0ubuntu6.8")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler-glib-dev", pkgver:"0.4.2-0ubuntu6.8")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler-qt-dev", pkgver:"0.4.2-0ubuntu6.8")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler0c2", pkgver:"0.4.2-0ubuntu6.8")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler0c2-glib", pkgver:"0.4.2-0ubuntu6.8")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler0c2-qt", pkgver:"0.4.2-0ubuntu6.8")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"poppler-utils", pkgver:"0.4.2-0ubuntu6.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"karbon", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kchart", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kexi", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kformula", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kivio", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kivio-data", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice-data", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice-dbg", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice-dev", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice-doc", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice-doc-html", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice-libs", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koshell", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kplato", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kpresenter", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kpresenter-data", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krita", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krita-data", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kspread", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kthesaurus", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kugar", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kword", pkgver:"1:1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kword-data", pkgver:"1.5.0-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpoppler-dev", pkgver:"0.5.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpoppler-glib-dev", pkgver:"0.5.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpoppler-qt-dev", pkgver:"0.5.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpoppler1", pkgver:"0.5.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpoppler1-glib", pkgver:"0.5.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpoppler1-qt", pkgver:"0.5.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"poppler-utils", pkgver:"0.5.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"karbon", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kchart", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kexi", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kformula", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kivio", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kivio-data", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice-data", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice-dbg", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice-dev", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice-doc", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice-doc-html", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice-libs", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koshell", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kplato", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kpresenter", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kpresenter-data", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krita", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krita-data", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kspread", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kthesaurus", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kugar", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kword", pkgver:"1:1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kword-data", pkgver:"1.5.2-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpoppler-dev", pkgver:"0.5.4-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpoppler-glib-dev", pkgver:"0.5.4-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpoppler-qt-dev", pkgver:"0.5.4-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpoppler-qt4-dev", pkgver:"0.5.4-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpoppler1", pkgver:"0.5.4-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpoppler1-glib", pkgver:"0.5.4-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpoppler1-qt", pkgver:"0.5.4-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpoppler1-qt4", pkgver:"0.5.4-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"poppler-utils", pkgver:"0.5.4-0ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kamera / karbon / kchart / kcoloredit / kdegraphics / etc");
}
