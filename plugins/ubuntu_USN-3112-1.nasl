#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3112-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94352);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2016-5250", "CVE-2016-5257", "CVE-2016-5270", "CVE-2016-5272", "CVE-2016-5274", "CVE-2016-5276", "CVE-2016-5277", "CVE-2016-5278", "CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5284");
  script_osvdb_id(142472, 144426, 144614, 144615, 144616, 144617, 144618, 144619, 144620, 144621, 144623, 144624, 144625, 144627, 144628, 144630, 144634, 144635, 144636);
  script_xref(name:"USN", value:"3112-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : thunderbird vulnerabilities (USN-3112-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Catalin Dumitru discovered that URLs of resources loaded after a
navigation start could be leaked to the following page via the
Resource Timing API. If a user were tricked in to opening a specially
crafted website in a browsing context, an attacker could potentially
exploit this to obtain sensitive information. (CVE-2016-5250)

Christoph Diehl, Andrew McCreight, Dan Minor, Byron Campen, Jon
Coppeard, Steve Fink, Tyson Smith, and Carsten Book discovered
multiple memory safety issues in Thunderbird. If a user were tricked
in to opening a specially crafted message, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-5257)

Atte Kettunen discovered a heap buffer overflow during text conversion
with some unicode characters. If a user were tricked in to opening a
specially crafted message, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code. (CVE-2016-5270)

Abhishek Arya discovered a bad cast when processing layout with input
elements in some circumstances. If a user were tricked in to opening a
specially crafted website in a browsing context, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-5272)

A use-after-free was discovered in web animations during restyling. If
a user were tricked in to opening a specially crafted website in a
browsing context, an attacker could potentially exploit this to cause
a denial of service via application crash, or execute arbitrary code.
(CVE-2016-5274)

A use-after-free was discovered in accessibility. If a user were
tricked in to opening a specially crafted website in a browsing
context, an attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code.
(CVE-2016-5276)

A use-after-free was discovered in web animations when destroying a
timeline. If a user were tricked in to opening a specially crafted
website in a browsing context, an attacker could potentially exploit
this to cause a denial of service via application crash, or execute
arbitrary code. (CVE-2016-5277)

A buffer overflow was discovered when encoding image frames to images
in some circumstances. If a user were tricked in to opening a
specially crafted message, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code. (CVE-2016-5278)

Mei Wang discovered a use-after-free when changing text direction. If
a user were tricked in to opening a specially crafted website in a
browsing context, an attacker could potentially exploit this to cause
a denial of service via application crash, or execute arbitrary code.
(CVE-2016-5280)

Brian Carpenter discovered a use-after-free when manipulating SVG
content in some circumstances. If a user were tricked in to opening a
specially crafted website in a browsing context, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-5281)

An issue was discovered with the preloaded Public Key Pinning (HPKP).
If a man-in-the-middle (MITM) attacker was able to obtain a fraudulent
certificate for a Mozilla site, they could exploit this by providing
malicious addon updates. (CVE-2016-5284).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"12.04", pkgname:"thunderbird", pkgver:"1:45.4.0+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"thunderbird", pkgver:"1:45.4.0+build1-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"thunderbird", pkgver:"1:45.4.0+build1-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"thunderbird", pkgver:"1:45.4.0+build1-0ubuntu0.16.10.1")) flag++;

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
