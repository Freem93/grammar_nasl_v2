#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2702-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85345);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/05/26 16:22:51 $");

  script_cve_id("CVE-2015-4473", "CVE-2015-4474", "CVE-2015-4475", "CVE-2015-4477", "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4480", "CVE-2015-4484", "CVE-2015-4485", "CVE-2015-4486", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4490", "CVE-2015-4491", "CVE-2015-4492", "CVE-2015-4493");
  script_osvdb_id(125395, 126004, 126005, 126006, 126007, 126008, 126009, 126010, 126011, 126012, 126013, 126014, 126015, 126016, 126017, 126018, 126021, 126022, 126023, 126024, 126025, 126026, 126027, 126028, 126029);
  script_xref(name:"USN", value:"2702-2");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 : ubufox update (USN-2702-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2702-1 fixed vulnerabilities in Firefox. This update provides the
corresponding updates for Ubufox.

Gary Kwong, Christian Holler, Byron Campen, Tyson Smith, Bobby Holley,
Chris Coulson, and Eric Rahm discovered multiple memory safety issues
in Firefox. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-4473,
CVE-2015-4474)

Aki Helin discovered an out-of-bounds read when playing
malformed MP3 content in some circumstances. If a user were
tricked in to opening a specially crafted website, an
attacker could potentially exploit this to obtain sensitive
information, cause a denial of service via application
crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2015-4475)

A use-after-free was discovered during MediaStream playback
in some circumstances. If a user were tricked in to opening
a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application
crash or execute arbitrary code with the priviliges of the
user invoking Firefox. (CVE-2015-4477)

Andre Bargull discovered that non-configurable properties
on JavaScript objects could be redefined when parsing JSON.
If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to
bypass same-origin restrictions. (CVE-2015-4478)

Multiple integer overflows were discovered in
libstagefright. If a user were tricked in to opening a
specially crafted website, an attacker could potentially
exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2015-4479, CVE-2015-4480,
CVE-2015-4493)

Jukka Jylanki discovered a crash that occurs because
JavaScript does not properly gate access to Atomics or
SharedArrayBuffers in some circumstances. If a user were
tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of
service. (CVE-2015-4484)

Abhishek Arya discovered 2 buffer overflows in libvpx when
decoding malformed WebM content in some circumstances. If a
user were tricked in to opening a specially crafted website,
an attacker could potentially exploit these to cause a
denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-4485, CVE-2015-4486)

Ronald Crane reported 3 security issues. If a user were
tricked in to opening a specially crafted website, an
attacker could potentially exploit these, in combination
with another security vulnerability, to cause a denial of
service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox.
(CVE-2015-4487, CVE-2015-4488, CVE-2015-4489)

Christoph Kerschbaumer discovered an issue with Mozilla's
implementation of Content Security Policy (CSP), which could
allow for a more permissive usage in some cirucumstances. An
attacker could potentially exploit this to conduct
cross-site scripting (XSS) attacks. (CVE-2015-4490)

Gustavo Grieco discovered a heap overflow in gdk-pixbuf. If
a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause
a denial of service via application crash or execute
arbitrary code with the priviliges of the user invoking
Firefox. (CVE-2015-4491)

Looben Yang discovered a use-after-free when using
XMLHttpRequest with shared workers in some circumstances. If
a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause
a denial of service via application crash or execute
arbitrary code with the priviliges of the user invoking
Firefox. (CVE-2015-4492).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xul-ext-ubufox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-ubufox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/12");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"xul-ext-ubufox", pkgver:"3.1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"xul-ext-ubufox", pkgver:"3.1-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"xul-ext-ubufox", pkgver:"3.1-0ubuntu0.15.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xul-ext-ubufox");
}
