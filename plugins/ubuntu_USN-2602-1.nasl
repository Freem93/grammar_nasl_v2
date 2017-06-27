#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2602-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83434);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/06/15 16:38:32 $");

  script_cve_id("CVE-2015-2708", "CVE-2015-2709", "CVE-2015-2710", "CVE-2015-2711", "CVE-2015-2712", "CVE-2015-2713", "CVE-2015-2715", "CVE-2015-2716", "CVE-2015-2717", "CVE-2015-2718");
  script_osvdb_id(122020, 122021, 122022, 122023, 122033, 122036, 122039, 122040);
  script_xref(name:"USN", value:"2602-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 14.10 / 15.04 : firefox vulnerabilities (USN-2602-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jesse Ruderman, Mats Palmgren, Byron Campen, Steve Fink, Gary Kwong,
Andrew McCreight, Christian Holler, Jon Coppeard, and Milan Sreckovic
discovered multiple memory safety issues in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2015-2708, CVE-2015-2709)

Atte Kettunen discovered a buffer overflow during the rendering of SVG
content with certain CSS properties in some circumstances. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2015-2710)

Alex Verstak discovered that <meta name='referrer'> is ignored in some
circumstances. (CVE-2015-2711)

Dougall Johnson discovered an out of bounds read and write in asm.js.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to obtain sensitive
information, cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-2712)

Scott Bell discovered a use-afer-free during the processing of text
when vertical text is enabled. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2015-2713)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free
during shutdown. An attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2015-2715)

Ucha Gobejishvili discovered a buffer overflow when parsing compressed
XML content. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-2716)

A buffer overflow and out-of-bounds read were discovered when parsing
metadata in MP4 files in some circumstances. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-2717)

Mark Hammond discovered that when a trusted page is hosted within an
iframe in an untrusted page, the untrusted page can intercept
webchannel responses meant for the trusted page in some circumstances.
If a user were tricked in to opening a specially crafted website, an
attacker could exploit this to bypass origin restrictions.
(CVE-2015-2718).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|14\.10|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 14.10 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"38.0+build3-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"38.0+build3-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"firefox", pkgver:"38.0+build3-0ubuntu0.14.10.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"firefox", pkgver:"38.0+build3-0ubuntu0.15.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
