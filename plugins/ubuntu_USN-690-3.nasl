#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-690-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65111);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5503", "CVE-2008-5504", "CVE-2008-5505", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513");
  script_bugtraq_id(32882);
  script_osvdb_id(51284, 51285, 51286, 51287, 51288, 51289, 51290, 51291, 51292, 51293, 51294, 51295, 51296, 51297);
  script_xref(name:"USN", value:"690-3");

  script_name(english:"Ubuntu 6.06 LTS : firefox vulnerabilities (USN-690-3)");
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
"Several flaws were discovered in the browser engine. These problems
could allow an attacker to crash the browser and possibly execute
arbitrary code with user privileges. (CVE-2008-5500)

Boris Zbarsky discovered that the same-origin check in Firefox could
be bypassed by utilizing XBL-bindings. An attacker could exploit this
to read data from other domains. (CVE-2008-5503)

Marius Schilder discovered that Firefox did not properly handle
redirects to an outside domain when an XMLHttpRequest was made to a
same-origin resource. It's possible that sensitive information could
be revealed in the XMLHttpRequest response. (CVE-2008-5506)

Chris Evans discovered that Firefox did not properly protect a user's
data when accessing a same-domain JavaScript URL that is redirected to
an unparsable JavaScript off-site resource. If a user were tricked
into opening a malicious website, an attacker may be able to steal a
limited amount of private data. (CVE-2008-5507)

Several flaws were discovered in the JavaScript engine. If a user were
tricked into opening a malicious website, an attacker could exploit
this to execute arbitrary JavaScript code within the context of
another website or with chrome privileges. (CVE-2008-5511,
CVE-2008-5512).

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"firefox", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dbg", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dev", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dom-inspector", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-gnome-support", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnspr-dev", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnspr4", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnss-dev", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnss3", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-firefox", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-firefox-dev", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1")) flag++;

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
