#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3165-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96871);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2017/03/15 21:22:53 $");

  script_cve_id("CVE-2016-9893", "CVE-2016-9895", "CVE-2016-9897", "CVE-2016-9898", "CVE-2016-9899", "CVE-2016-9900", "CVE-2016-9904", "CVE-2016-9905", "CVE-2017-5373", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5378", "CVE-2017-5380", "CVE-2017-5383", "CVE-2017-5390", "CVE-2017-5396");
  script_osvdb_id(148666, 148667, 148668, 148693, 148695, 148696, 148697, 148698, 148699, 148700, 148701, 148704, 148705, 148706, 148707, 148708, 148711, 150831, 150832, 150834, 150836, 150837, 150858, 150859, 150860, 150861, 150862, 150863, 150864, 150865, 150866, 150875, 150878);
  script_xref(name:"USN", value:"3165-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : thunderbird vulnerabilities (USN-3165-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple memory safety issues were discovered in Thunderbird. If a
user were tricked in to opening a specially crafted message, an
attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code. (CVE-2016-9893,
CVE-2017-5373)

Andrew Krasichkov discovered that event handlers on <marquee> elements
were executed despite a Content Security Policy (CSP) that disallowed
inline JavaScript. If a user were tricked in to opening a specially
crafted website in a browsing context, an attacker could potentially
exploit this to conduct cross-site scripting (XSS) attacks.
(CVE-2016-9895)

A memory corruption issue was discovered in WebGL in some
circumstances. If a user were tricked in to opening a specially
crafted website in a browsing context, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code. (CVE-2016-9897)

A use-after-free was discovered when manipulating DOM subtrees in the
Editor. If a user were tricked in to opening a specially crafted
website in a browsing context, an attacker could potentially exploit
this to cause a denial of service via application crash, or execute
arbitrary code. (CVE-2016-9898)

A use-after-free was discovered when manipulating DOM events and audio
elements. If a user were tricked in to opening a specially crafted
website in a browsing context, an attacker could potentially exploit
this to cause a denial of service via application crash, or execute
arbitrary code. (CVE-2016-9899)

It was discovered that external resources that should be blocked when
loading SVG images can bypass security restrictions using data: URLs.
An attacker could potentially exploit this to obtain sensitive
information. (CVE-2016-9900)

Jann Horn discovered that JavaScript Map/Set were vulnerable to timing
attacks. If a user were tricked in to opening a specially crafted
website in a browsing context, an attacker could potentially exploit
this to obtain sensitive information across domains. (CVE-2016-9904)

A crash was discovered in EnumerateSubDocuments while adding or
removing sub-documents. If a user were tricked in to opening a
specially crafted website in a browsing context, an attacker could
potentially exploit this to execute arbitrary code. (CVE-2016-9905)

JIT code allocation can allow a bypass of ASLR protections in some
circumstances. If a user were tricked in to opening a specially
crafted website in a browsing context, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code. (CVE-2017-5375)

Nicolas Gregoire discovered a use-after-free when manipulating XSL in
XSLT documents in some circumstances. If a user were tricked in to
opening a specially crafted website in a browsing context, an attacker
could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code. (CVE-2017-5376)

Jann Horn discovered that an object's address could be discovered
through hashed codes of JavaScript objects shared between pages. If a
user were tricked in to opening a specially crafted website in a
browsing context, an attacker could potentially exploit this to obtain
sensitive information. (CVE-2017-5378)

A use-after-free was discovered during DOM manipulation of SVG content
in some circumstances. If a user were tricked in to opening a
specially crafted website in a browsing context, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2017-5380)

Armin Razmjou discovered that certain unicode glyphs do not trigger
punycode display. If a user were tricked in to opening a specially
crafted website in a browsing context, an attacker could potentially
exploit this to spoof the URL bar contents. (CVE-2017-5383)

Jerri Rice discovered insecure communication methods in the Dev Tools
JSON Viewer. An attacker could potentially exploit this to gain
additional privileges. (CVE-2017-5390)

Filipe Gomes discovered a use-after-free in the media decoder in some
circumstances. If a user were tricked in to opening a specially
crafted website in a browsing context, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code. (CVE-2017-5396).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"thunderbird", pkgver:"1:45.7.0+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"thunderbird", pkgver:"1:45.7.0+build1-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"thunderbird", pkgver:"1:45.7.0+build1-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"thunderbird", pkgver:"1:45.7.0+build1-0ubuntu0.16.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
