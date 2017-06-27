#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-227-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20770);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193");
  script_bugtraq_id(15721, 15725, 15726, 15727);
  script_xref(name:"USN", value:"227-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : xpdf/cupsys/tetex-bin/kdegraphics/koffice vulnerabilities (USN-227-1)");
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
"infamous41md discovered several integer overflows in the XPDF code,
which is present in xpdf, the Poppler library, tetex-bin, KOffice, and
kpdf. By tricking an user into opening a specially crafted PDF file,
an attacker could exploit this to execute arbitrary code with the
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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kchart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kcoloredit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-kfile-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdvi");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kolourpaint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kooka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koshell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpovmodeler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpresenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krita");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-gnutls10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkscan-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkscan1");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/21");
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
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"cupsys", pkgver:"1.1.20final+cvs20040330-4ubuntu16.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cupsys-bsd", pkgver:"1.1.20final+cvs20040330-4ubuntu16.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cupsys-client", pkgver:"1.1.20final+cvs20040330-4ubuntu16.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsimage2", pkgver:"1.1.20final+cvs20040330-4ubuntu16.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsimage2-dev", pkgver:"1.1.20final+cvs20040330-4ubuntu16.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsys2-dev", pkgver:"1.1.20final+cvs20040330-4ubuntu16.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsys2-gnutls10", pkgver:"1.1.20final+cvs20040330-4ubuntu16.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkpathsea-dev", pkgver:"2.0.2-21ubuntu0.7")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkpathsea3", pkgver:"2.0.2-21ubuntu0.7")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"tetex-bin", pkgver:"2.0.2-21ubuntu0.7")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf", pkgver:"3.00-8ubuntu1.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf-common", pkgver:"3.00-8ubuntu1.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf-reader", pkgver:"3.00-8ubuntu1.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"xpdf-utils", pkgver:"3.00-8ubuntu1.9")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kamera", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"karbon", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kchart", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kcoloredit", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdegraphics", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdegraphics-dev", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdegraphics-kfile-plugins", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdvi", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kfax", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kformula", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kgamma", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kghostview", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kiconedit", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kivio", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kivio-data", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kmrml", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"koffice", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"koffice-data", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"koffice-dev", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"koffice-doc-html", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"koffice-libs", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kolourpaint", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kooka", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"koshell", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kpdf", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kpovmodeler", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kpresenter", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kruler", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ksnapshot", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kspread", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ksvg", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kugar", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kuickshow", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kview", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kviewshell", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kword", pkgver:"1.3.5-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkpathsea-dev", pkgver:"2.0.2-25ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkpathsea3", pkgver:"2.0.2-25ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkscan-dev", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkscan1", pkgver:"3.4.0-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"tetex-bin", pkgver:"2.0.2-25ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf", pkgver:"3.00-11ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf-common", pkgver:"3.00-11ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf-reader", pkgver:"3.00-11ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xpdf-utils", pkgver:"3.00-11ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kamera", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"karbon", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kchart", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kcoloredit", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdegraphics", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdegraphics-dev", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdegraphics-doc-html", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdegraphics-kfile-plugins", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdvi", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kfax", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kformula", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kgamma", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kghostview", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kiconedit", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kivio", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kivio-data", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kmrml", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"koffice", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"koffice-data", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"koffice-dev", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"koffice-doc-html", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"koffice-libs", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kolourpaint", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kooka", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"koshell", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kpdf", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kpovmodeler", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kpresenter", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"krita", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kruler", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ksnapshot", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kspread", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ksvg", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kthesaurus", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kugar", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kuickshow", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kview", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kviewshell", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kword", pkgver:"1.4.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkpathsea-dev", pkgver:"2.0.2-30ubuntu3.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkpathsea3", pkgver:"2.0.2-30ubuntu3.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkscan-dev", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkscan1", pkgver:"3.4.3-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler-dev", pkgver:"0.4.2-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler-glib-dev", pkgver:"0.4.2-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler-qt-dev", pkgver:"0.4.2-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler0c2", pkgver:"0.4.2-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler0c2-glib", pkgver:"0.4.2-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpoppler0c2-qt", pkgver:"0.4.2-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"poppler-utils", pkgver:"0.4.2-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"tetex-bin", pkgver:"2.0.2-30ubuntu3.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cupsys / cupsys-bsd / cupsys-client / kamera / karbon / kchart / etc");
}
