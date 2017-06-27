#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3044-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92785);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2016-0718", "CVE-2016-2830", "CVE-2016-2835", "CVE-2016-2836", "CVE-2016-2837", "CVE-2016-2838", "CVE-2016-2839", "CVE-2016-5250", "CVE-2016-5251", "CVE-2016-5252", "CVE-2016-5254", "CVE-2016-5255", "CVE-2016-5258", "CVE-2016-5259", "CVE-2016-5260", "CVE-2016-5261", "CVE-2016-5262", "CVE-2016-5263", "CVE-2016-5264", "CVE-2016-5265", "CVE-2016-5266", "CVE-2016-5268");
  script_osvdb_id(138680, 142419, 142420, 142421, 142422, 142423, 142424, 142425, 142426, 142427, 142428, 142430, 142431, 142432, 142433, 142434, 142435, 142468, 142469, 142471, 142472, 142473, 142474, 142475, 142476, 142477, 142478, 142479, 142480, 142481, 142482, 142483, 142484, 142485, 142486, 142487);
  script_xref(name:"USN", value:"3044-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS : firefox vulnerabilities (USN-3044-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Gustavo Grieco discovered an out-of-bounds read during XML parsing in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or obtain sensitive
information. (CVE-2016-0718)

Toni Huttunen discovered that once a favicon is requested from a site,
the remote server can keep the network connection open even after the
page is closed. A remote attacked could potentially exploit this to
track users, resulting in information disclosure. (CVE-2016-2830)

Christian Holler, Tyson Smith, Boris Zbarsky, Byron Campen, Julian
Seward, Carsten Book, Gary Kwong, Jesse Ruderman, Andrew McCreight,
and Phil Ringnalda discovered multiple memory safety issues in
Firefox. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial
of service via application crash, or execute arbitrary code.
(CVE-2016-2835, CVE-2016-2836)

A buffer overflow was discovered in the ClearKey Content Decryption
Module (CDM) during video playback. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via plugin process crash,
or, in combination with another vulnerability to escape the GMP
sandbox, execute arbitrary code. (CVE-2016-2837)

Atte Kettunen discovered a buffer overflow when rendering SVG content
in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code. (CVE-2016-2838)

Bert Massop discovered a crash in Cairo with version 0.10 of FFmpeg.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to execute arbitrary code.
(CVE-2016-2839)

Catalin Dumitru discovered that URLs of resources loaded after a
navigation start could be leaked to the following page via the
Resource Timing API. An attacker could potentially exploit this to
obtain sensitive information. (CVE-2016-5250)

Firas Salem discovered an issue with non-ASCII and emoji characters in
data: URLs. An attacker could potentially exploit this to spoof the
addressbar contents. (CVE-2016-5251)

Georg Koppen discovered a stack buffer underflow during 2D graphics
rendering in some circumstances. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via application crash, or execute
arbitrary code. (CVE-2016-5252)

Abhishek Arya discovered a use-after-free when the alt key is used
with top-level menus. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2016-5254)

Jukka Jylanki discovered a crash during garbage collection. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to execute arbitrary code.
(CVE-2016-5255)

Looben Yang discovered a use-after-free in WebRTC. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-5258)

Looben Yang discovered a use-after-free when working with nested sync
events in service workers. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code. (CVE-2016-5259)

Mike Kaply discovered that plain-text passwords can be stored in
session restore if an input field type is changed from 'password' to
'text' during a session, leading to information disclosure.
(CVE-2016-5260)

Samuel Gross discovered an integer overflow in WebSockets during data
buffering in some circumstances. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via application crash, or execute
arbitrary code. (CVE-2016-5261)

Nikita Arykov discovered that JavaScript event handlers on a <marquee>
element can execute in a sandboxed iframe without the allow-scripts
flag set. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to conduct
cross-site scripting (XSS) attacks. (CVE-2016-5262)

A type confusion bug was discovered in display transformation during
rendering. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code.
(CVE-2016-5263)

A use-after-free was discovered when applying effects to SVG elements
in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code. (CVE-2016-5264)

Abdulrahman Alqabandi discovered a same-origin policy violation
relating to local HTML files and saved shortcut files. An attacker
could potentially exploit this to obtain sensitive information.
(CVE-2016-5265)

Rafael Gieschke discovered an information disclosure issue related to
drag and drop. An attacker could potentially exploit this to obtain
sensitive information. (CVE-2016-5266)

A text injection issue was discovered with about: URLs. An attacker
could potentially exploit this to spoof internal error pages.
(CVE-2016-5268).

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
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/08");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"48.0+build2-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"48.0+build2-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"firefox", pkgver:"48.0+build2-0ubuntu0.16.04.1")) flag++;

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
