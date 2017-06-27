#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-271-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21270);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0296", "CVE-2006-0749", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1736", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
  script_osvdb_id(21533, 22890, 22892, 22894, 24658, 24659, 24660, 24661, 24662, 24663, 24664, 24665, 24666, 24667, 24668, 24669, 24670, 24671, 24677, 24678, 24679, 24680, 79168, 79169);
  script_xref(name:"USN", value:"271-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : mozilla-firefox, firefox vulnerabilities (USN-271-1)");
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
"Web pages with extremely long titles caused subsequent launches of
Firefox browser to hang for up to a few minutes, or caused Firefox to
crash on computers with insufficient memory. (CVE-2005-4134)

Igor Bukanov discovered that the JavaScript engine did not properly
declare some temporary variables. Under some rare circumstances, a
malicious website could exploit this to execute arbitrary code with
the privileges of the user. (CVE-2006-0292, CVE-2006-1742)

The function XULDocument.persist() did not sufficiently validate the
names of attributes. An attacker could exploit this to inject
arbitrary XML code into the file 'localstore.rdf', which is read and
evaluated at startup. This could include JavaScript commands that
would be run with the user's privileges. (CVE-2006-0296)

Due to a flaw in the HTML tag parser a specific sequence of HTML tags
caused memory corruption. A malicious website could exploit this to
crash the browser or even execute arbitrary code with the user's
privileges. (CVE-2006-0749)

Georgi Guninski discovered that embedded XBL scripts of websites could
escalate their (normally reduced) privileges to get full privileges of
the user if that page is viewed with 'Print Preview'. (CVE-2006-1727)

The crypto.generateCRMFRequest() function had a flaw which could be
exploited to run arbitrary code with the user's privileges.
(CVE-2006-1728)

Claus Jorgensen and Jesse Ruderman discovered that a text input box
could be pre-filled with a filename and then turned into a file-upload
control with the contents intact. A malicious website could exploit
this to read any local file the user has read privileges for.
(CVE-2006-1729)

An integer overflow was detected in the handling of the CSS property
'letter-spacing'. A malicious website could exploit this to run
arbitrary code with the user's privileges. (CVE-2006-1730)

The methods valueOf.call() and .valueOf.apply() returned an object
whose privileges were not properly confined to those of the caller,
which made them vulnerable to cross-site scripting attacks. A
malicious website could exploit this to modify the contents or steal
confidential data (such as passwords) from other opened web pages.
(CVE-2006-1731) The window.controllers array variable (CVE-2006-1732)
and event handlers (CVE-2006-1741) were vulnerable to a similar
attack. 

The privileged built-in XBL bindings were not fully protected from web
content and could be accessed by calling valueOf.call() and
valueOf.apply() on a method of that binding. A malicious website could
exploit this to run arbitrary JavaScript code with the user's
privileges. (CVE-2006-1733)

It was possible to use the Object.watch() method to access an internal
function object (the 'clone parent'). A malicious website could
exploit this to execute arbitrary JavaScript code with the user's
privileges. (CVE-2006-1734)

By calling the XBL.method.eval() method in a special way it was
possible to create JavaScript functions that would get compiled with
the wrong privileges. A malicious website could exploit this to
execute arbitrary JavaScript code with the user's privileges.
(CVE-2006-1735)

Michael Krax discovered that by layering a transparent image link to
an executable on top of a visible (and presumably desirable) image a
malicious site could fool the user to right-click and choose 'Save
image as...' from the context menu, which would download the
executable instead of the image. (CVE-2006-1736)

Several crashes have been fixed which could be triggered by websites
and involve memory corruption. These could potentially be exploited to
execute arbitrary code with the user's privileges. (CVE-2006-1737,
CVE-2006-1738, CVE-2006-1739, CVE-2006-1790)

If the user has turned on the 'Entering secure site' modal warning
dialog, it was possible to spoof the browser's secure-site indicators
(the lock icon and the gold URL field background) by first loading the
target secure site in a pop-up window, then changing its location to a
different site, which retained the displayed secure-browsing
indicators from the original site. (CVE-2006-1740).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/07");
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

if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox", pkgver:"1.0.8-0ubuntu4.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-dom-inspector", pkgver:"1.0.8-0ubuntu4.10")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-firefox", pkgver:"1.0.8-0ubuntu5.04")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-firefox-dev", pkgver:"1.0.8-0ubuntu5.04")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-firefox-dom-inspector", pkgver:"1.0.8-0ubuntu5.04")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-firefox-gnome-support", pkgver:"1.0.8-0ubuntu5.04")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"firefox", pkgver:"1.0.8-0ubuntu5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"firefox-dev", pkgver:"1.0.8-0ubuntu5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"firefox-dom-inspector", pkgver:"1.0.8-0ubuntu5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"firefox-gnome-support", pkgver:"1.0.8-0ubuntu5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-firefox", pkgver:"1.0.8-0ubuntu5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-firefox-dev", pkgver:"1.0.8-0ubuntu5.10")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-dev / firefox-dom-inspector / etc");
}
