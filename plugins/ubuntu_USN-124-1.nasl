#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-124-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20513);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 16:22:49 $");

  script_cve_id("CVE-2005-1153", "CVE-2005-1154", "CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1157", "CVE-2005-1158", "CVE-2005-1159", "CVE-2005-1160");
  script_xref(name:"USN", value:"124-1");

  script_name(english:"Ubuntu 5.04 : mozilla-firefox, mozilla vulnerabilities (USN-124-1)");
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
"When a popup is blocked the user is given the ability to open that
popup through the popup-blocking status bar icon and, in Firefox,
through the information bar. Doron Rosenberg noticed that popups which
are permitted by the user were executed with elevated privileges,
which could be abused to automatically install and execute arbitrary
code with the privileges of the user. (CAN-2005-1153)

It was discovered that the browser did not start with a clean global
JavaScript state for each new website. This allowed a malicious web
page to define a global variable known to be used by a different site,
allowing malicious code to be executed in the context of that site
(for example, sending web mail or automatic purchasing).
(CAN-2005-1154)

Michael Krax discovered a flaw in the 'favicon' links handler. A
malicious web page could define a favicon link tag as JavaScript,
which could be exploited to execute arbitrary code with the privileges
of the user. (CAN-2005-1155)

Michael Krax found two flaws in the Search Plugin installation. This
allowed malicious plugins to execute arbitrary code in the context of
the current site. If the current page had elevated privileges (like
'about:plugins' or 'about:config'), the malicious plugin could even
install malicious software when a search was performed.
(CAN-2005-1156, CAN-2005-1157)

Kohei Yoshino discovered two missing security checks when Firefox
opens links in its sidebar. This allowed a malicious web page to
construct a link that, when clicked on, could execute arbitrary
JavaScript code with the privileges of the user. (CAN-2005-1158)

Georgi Guninski discovered that the types of certain XPInstall related
JavaScript objects were not sufficiently validated when they were
called. This could be exploited by a malicious website to crash
Firefox or even execute arbitrary code with the privileges of the
user. (CAN-2005-1159)

Firefox did not properly verify the values of XML DOM nodes of web
pages. By tricking the user to perform a common action like clicking
on a link or opening the context menu, a malicious page could exploit
this to execute arbitrary JavaScript code with the full privileges of
the user. (CAN-2005-1160).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-chatzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-mailnews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-psm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/11");
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

if (ubuntu_check(osver:"5.04", pkgname:"libnspr-dev", pkgver:"1.7.6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libnspr4", pkgver:"1.7.6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libnss-dev", pkgver:"1.7.6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libnss3", pkgver:"1.7.6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla", pkgver:"1.7.6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-browser", pkgver:"1.7.6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-calendar", pkgver:"1.7.6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-chatzilla", pkgver:"1.7.6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-dev", pkgver:"1.7.6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-dom-inspector", pkgver:"1.7.6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-firefox", pkgver:"1.0.2-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-firefox-dev", pkgver:"1.0.2-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-firefox-dom-inspector", pkgver:"1.0.2-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-firefox-gnome-support", pkgver:"1.0.2-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-js-debugger", pkgver:"1.7.6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-mailnews", pkgver:"1.7.6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-psm", pkgver:"1.7.6-1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnspr-dev / libnspr4 / libnss-dev / libnss3 / mozilla / etc");
}
