#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-701-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37974);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512");
  script_bugtraq_id(32882);
  script_xref(name:"USN", value:"701-1");

  script_name(english:"Ubuntu 7.10 / 8.04 LTS / 8.10 : thunderbird vulnerabilities (USN-701-1)");
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
"Several flaws were discovered in the browser engine. If a user had
JavaScript enabled, these problems could allow an attacker to crash
Thunderbird and possibly execute arbitrary code with user privileges.
(CVE-2008-5500)

Boris Zbarsky discovered that the same-origin check in Thunderbird
could be bypassed by utilizing XBL-bindings. If a user had JavaScript
enabled, an attacker could exploit this to read data from other
domains. (CVE-2008-5503)

Marius Schilder discovered that Thunderbird did not properly handle
redirects to an outside domain when an XMLHttpRequest was made to a
same-origin resource. When JavaScript is enabled, it's possible that
sensitive information could be revealed in the XMLHttpRequest
response. (CVE-2008-5506)

Chris Evans discovered that Thunderbird did not properly protect a
user's data when accessing a same-domain JavaScript URL that is
redirected to an unparsable JavaScript off-site resource. If a user
were tricked into opening a malicious website and had JavaScript
enabled, an attacker may be able to steal a limited amount of private
data. (CVE-2008-5507)

Chip Salzenberg, Justin Schuh, Tom Cross, and Peter William discovered
Thunderbird did not properly parse URLs when processing certain
control characters. (CVE-2008-5508)

Kojima Hajime discovered that Thunderbird did not properly handle an
escaped null character. An attacker may be able to exploit this flaw
to bypass script sanitization. (CVE-2008-5510)

Several flaws were discovered in the JavaScript engine. If a user were
tricked into opening a malicious website and had JavaScript enabled,
an attacker could exploit this to execute arbitrary JavaScript code
within the context of another website or with chrome privileges.
(CVE-2008-5511, CVE-2008-5512).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.10", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.19+nobinonly-0ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mozilla-thunderbird-dev", pkgver:"2.0.0.19+nobinonly-0ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"thunderbird", pkgver:"2.0.0.19+nobinonly-0ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"thunderbird-dev", pkgver:"2.0.0.19+nobinonly-0ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"thunderbird-gnome-support", pkgver:"2.0.0.19+nobinonly-0ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.19+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mozilla-thunderbird-dev", pkgver:"2.0.0.19+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"thunderbird", pkgver:"2.0.0.19+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"thunderbird-dev", pkgver:"2.0.0.19+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"thunderbird-gnome-support", pkgver:"2.0.0.19+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.19+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mozilla-thunderbird-dev", pkgver:"2.0.0.19+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"thunderbird", pkgver:"2.0.0.19+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"thunderbird-dev", pkgver:"2.0.0.19+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"thunderbird-gnome-support", pkgver:"2.0.0.19+nobinonly-0ubuntu0.8.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-thunderbird / mozilla-thunderbird-dev / thunderbird / etc");
}
