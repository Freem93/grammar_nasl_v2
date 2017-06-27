#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1020-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51115);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2010-3768", "CVE-2010-3776", "CVE-2010-3777", "CVE-2010-3778");
  script_bugtraq_id(45322);
  script_osvdb_id(69770, 69778, 69779, 69780);
  script_xref(name:"USN", value:"1020-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 : thunderbird, thunderbird-locales vulnerabilities (USN-1020-1)");
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
"Jesse Ruderman, Andreas Gal, Nils, Brian Hackett, and Igor Bukanov
discovered several memory issues in the browser engine. An attacker
could exploit these to crash THunderbird or possibly run arbitrary
code as the user invoking the program. (CVE-2010-3776, CVE-2010-3777,
CVE-2010-3778)

Marc Schoenefeld and Christoph Diehl discovered several problems when
handling downloadable fonts. The new OTS font sanitizing library was
added to mitigate these issues. (CVE-2010-3768).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ta-lk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-tw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/10");
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
if (! ereg(pattern:"^(10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"thunderbird", pkgver:"3.1.7+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-dbg", pkgver:"3.1.7+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-dev", pkgver:"3.1.7+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-gnome-support", pkgver:"3.1.7+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-gnome-support-dbg", pkgver:"3.1.7+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-af", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-ar", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-be", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-bg", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-bn-bd", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-ca", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-cs", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-da", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-de", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-el", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-en-gb", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-es-ar", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-es-es", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-et", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-eu", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-fi", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-fr", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-fy-nl", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-ga-ie", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-gl", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-he", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-hu", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-id", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-is", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-it", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-ja", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-ka", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-ko", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-lt", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-mk", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-nb-no", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-nl", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-nn-no", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-pa-in", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-pl", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-pt-br", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-pt-pt", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-ro", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-ru", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-si", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-sk", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-sl", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-sq", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-sr", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-sv-se", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-ta-lk", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-tr", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-uk", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-vi", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-zh-cn", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-locale-zh-tw", pkgver:"3.1.2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird", pkgver:"3.1.7+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird-dbg", pkgver:"3.1.7+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird-dev", pkgver:"3.1.7+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird-gnome-support", pkgver:"3.1.7+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird-gnome-support-dbg", pkgver:"3.1.7+build3+nobinonly-0ubuntu0.10.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-dbg / thunderbird-dev / etc");
}
