#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-973-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48362);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609");
  script_bugtraq_id(34568, 34791, 36703);
  script_xref(name:"USN", value:"973-1");

  script_name(english:"Ubuntu 9.04 : koffice vulnerabilities (USN-973-1)");
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
"Will Dormann, Alin Rad Pop, Braden Thomas, and Drew Yao discovered
that the Xpdf used in KOffice contained multiple security issues in
its JBIG2 decoder. If a user or automated system were tricked into
opening a crafted PDF file, an attacker could cause a denial of
service or execute arbitrary code with privileges of the user invoking
the program. (CVE-2009-0146, CVE-2009-0147, CVE-2009-0166,
CVE-2009-0799, CVE-2009-0800, CVE-2009-1179, CVE-2009-1180,
CVE-2009-1181)

It was discovered that the Xpdf used in KOffice contained multiple
security issues when parsing malformed PDF documents. If a user or
automated system were tricked into opening a crafted PDF file, an
attacker could cause a denial of service or execute arbitrary code
with privileges of the user invoking the program. (CVE-2009-3606,
CVE-2009-3608, CVE-2009-3609)

KOffice in Ubuntu 9.04 uses a very old version of Xpdf to import PDFs
into KWord. Upstream KDE no longer supports PDF import in KOffice and
as a result it was dropped in Ubuntu 9.10. While an attempt was made
to fix the above issues, the maintenance burden for supporting this
very old version of Xpdf outweighed its utility, and PDF import is now
also disabled in Ubuntu 9.04.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kchart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kexi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kformula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kivio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kivio-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koshell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kplato");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpresenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpresenter-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krita");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krita-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kspread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kthesaurus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kword-data");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/18");
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
if (! ereg(pattern:"^(9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.04", pkgname:"karbon", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kchart", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kexi", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kformula", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kivio", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kivio-data", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"koffice", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"koffice-data", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"koffice-dbg", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"koffice-dev", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"koffice-doc", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"koffice-doc-html", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"koffice-libs", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"koshell", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kplato", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kpresenter", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kpresenter-data", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krita", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krita-data", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kspread", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kthesaurus", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kugar", pkgver:"1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kword", pkgver:"1:1.6.3-7ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kword-data", pkgver:"1.6.3-7ubuntu6.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "karbon / kchart / kexi / kformula / kivio / kivio-data / koffice / etc");
}
