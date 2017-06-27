#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-619-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33436);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2806", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810", "CVE-2008-2811");
  script_osvdb_id(46673, 46674, 46675, 46676, 46677, 46678, 46679, 46680, 46681, 46682, 46683, 46684, 46686, 46687, 46688);
  script_xref(name:"USN", value:"619-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 : firefox vulnerabilities (USN-619-1)");
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
"Various flaws were discovered in the browser engine. By tricking a
user into opening a malicious web page, an attacker could cause a
denial of service via application crash, or possibly execute arbitrary
code with the privileges of the user invoking the program.
(CVE-2008-2798, CVE-2008-2799)

Several problems were discovered in the JavaScript engine. If a user
were tricked into opening a malicious web page, an attacker could
perform cross-site scripting attacks. (CVE-2008-2800)

Collin Jackson discovered various flaws in the JavaScript engine which
allowed JavaScript to be injected into signed JAR files. If a user
were tricked into opening malicious web content, an attacker may be
able to execute arbitrary code with the privileges of a different
website or link content within the JAR file to an attacker-controlled
JavaScript file. (CVE-2008-2801)

It was discovered that Firefox would allow non-privileged XUL
documents to load chrome scripts from the fastload file. This could
allow an attacker to execute arbitrary JavaScript code with chrome
privileges. (CVE-2008-2802)

A flaw was discovered in Firefox that allowed overwriting trusted
objects via mozIJSSubScriptLoader.loadSubScript(). If a user were
tricked into opening a malicious web page, an attacker could execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2008-2803)

Claudio Santambrogio discovered a vulnerability in Firefox which could
lead to stealing of arbitrary files. If a user were tricked into
opening malicious content, an attacker could force the browser into
uploading local files to the remote server. (CVE-2008-2805)

Gregory Fleischer discovered a flaw in Java LiveConnect. An attacker
could exploit this to bypass the same-origin policy and create
arbitrary socket connections to other domains. (CVE-2008-2806)

Daniel Glazman found that an improperly encoded .properties file in an
add-on can result in uninitialized memory being used. If a user were
tricked into installing a malicious add-on, the browser may be able to
see data from other programs. (CVE-2008-2807)

Masahiro Yamada discovered that Firefox did not properly sanitize file
URLs in directory listings, resulting in files from directory listings
being opened in unintended ways or not being able to be opened by the
browser at all. (CVE-2008-2808)

John G. Myers discovered a weakness in the trust model used by Firefox
regarding alternate names on self-signed certificates. If a user were
tricked into accepting a certificate containing alternate name
entries, an attacker could impersonate another server. (CVE-2008-2809)

A flaw was discovered in the way Firefox opened URL files. If a user
were tricked into opening a bookmark to a malicious web page, the page
could potentially read from local files on the user's computer.
(CVE-2008-2810)

A vulnerability was discovered in the block reflow code of Firefox.
This vulnerability could be used by an attacker to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2008-2811).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 79, 200, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-libthai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"firefox", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dbg", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dev", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dom-inspector", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-gnome-support", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnspr-dev", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnspr4", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnss-dev", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnss3", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-firefox", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-firefox-dev", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox", pkgver:"2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-dbg", pkgver:"2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-dev", pkgver:"2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-dom-inspector", pkgver:"2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-gnome-support", pkgver:"2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-libthai", pkgver:"2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnspr-dev", pkgver:"1.firefox2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnspr4", pkgver:"1.firefox2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnss-dev", pkgver:"1.firefox2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnss3", pkgver:"1.firefox2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox", pkgver:"2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox-dev", pkgver:"2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox-dom-inspector", pkgver:"2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox-gnome-support", pkgver:"2.0.0.15+0nobinonly-0ubuntu0.7.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox", pkgver:"2.0.0.15+1nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-dbg", pkgver:"2.0.0.15+1nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-dev", pkgver:"2.0.0.15+1nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-dom-inspector", pkgver:"2.0.0.15+1nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-gnome-support", pkgver:"2.0.0.15+1nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-libthai", pkgver:"2.0.0.15+1nobinonly-0ubuntu0.7.10")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-dbg / firefox-dev / firefox-dom-inspector / etc");
}
