#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-921-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45484);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:43 $");

  script_cve_id("CVE-2010-0173", "CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-0178", "CVE-2010-0179", "CVE-2010-0181", "CVE-2010-0182");
  script_bugtraq_id(39122, 39123, 39124, 39125, 39128, 39133, 39137);
  script_xref(name:"USN", value:"921-1");

  script_name(english:"Ubuntu 9.10 : firefox-3.5, xulrunner-1.9.1 vulnerabilities (USN-921-1)");
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
"Martijn Wargers, Josh Soref, Jesse Ruderman, and Ehsan Akhgari
discovered flaws in the browser engine of Firefox. If a user were
tricked into viewing a malicious website, a remote attacker could
cause a denial of service or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2010-0173,
CVE-2010-0174)

It was discovered that Firefox could be made to access previously
freed memory. If a user were tricked into viewing a malicious website,
a remote attacker could cause a denial of service or possibly execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2010-0175, CVE-2010-0176, CVE-2010-0177)

Paul Stone discovered that Firefox could be made to change a mouse
click into a drag and drop event. If the user could be tricked into
performing this action twice on a crafted website, an attacker could
execute arbitrary JavaScript with chrome privileges. (CVE-2010-0178)

It was discovered that the XMLHttpRequestSpy module as used by the
Firebug add-on could be used to escalate privileges within the
browser. If the user had the Firebug add-on installed and were tricked
into viewing a malicious website, an attacker could potentially run
arbitrary JavaScript. (CVE-2010-0179)

Henry Sudhof discovered that an image tag could be used as a redirect
to a mailto: URL to launch an external mail handler. (CVE-2010-0181)

Wladimir Palant discovered that Firefox did not always perform
security checks on XML content. An attacker could exploit this to
bypass security policies to load certain resources. (CVE-2010-0182).

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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.0-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.1-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.5-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.1-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.1-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.1-testsuite-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/12");
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
if (! ereg(pattern:"^(9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.10", pkgname:"abrowser", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.0", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.0-branding", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.1", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.1-branding", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.5", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.5-branding", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-branding", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-dev", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-dom-inspector", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-gnome-support", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-venkman", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-branding", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-dbg", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-dev", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-gnome-support", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-branding", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-dbg", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-dev", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-gnome-support", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-dom-inspector", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-gnome-support", pkgver:"3.5.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.1", pkgver:"1.9.1.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.1-dbg", pkgver:"1.9.1.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.1-dev", pkgver:"1.9.1.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.1-gnome-support", pkgver:"1.9.1.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.1-testsuite", pkgver:"1.9.1.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.1-testsuite-dev", pkgver:"1.9.1.9+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-dev", pkgver:"1.9.1.9+nobinonly-0ubuntu0.9.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrowser / abrowser-3.0 / abrowser-3.0-branding / abrowser-3.1 / etc");
}
