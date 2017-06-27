#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2298-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76756);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/24 17:29:04 $");

  script_cve_id("CVE-2014-1730", "CVE-2014-1731", "CVE-2014-1735", "CVE-2014-1740", "CVE-2014-1741", "CVE-2014-1742", "CVE-2014-1743", "CVE-2014-1744", "CVE-2014-1746", "CVE-2014-1748", "CVE-2014-3152", "CVE-2014-3154", "CVE-2014-3155", "CVE-2014-3157", "CVE-2014-3160", "CVE-2014-3162", "CVE-2014-3803");
  script_bugtraq_id(67082, 67374, 67375, 67376, 67517, 67572, 67582, 67972, 67977, 67980, 68677);
  script_osvdb_id(106914, 107144, 115894, 115895, 115896, 115897, 115898, 115899, 115900, 115901, 115902, 115903, 115904, 115905, 115906, 115907, 115908, 115909);
  script_xref(name:"USN", value:"2298-1");

  script_name(english:"Ubuntu 14.04 LTS : oxide-qt vulnerabilities (USN-2298-1)");
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
"A type confusion bug was discovered in V8. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash, or
execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2014-1730)

A type confusion bug was discovered in Blink. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via renderer
crash, or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2014-1731)

Multiple security issues including memory safety bugs were discovered
in Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2014-1735,
CVE-2014-3162)

Multiple use-after-free issues were discovered in the WebSockets
implementation. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause
a denial of service via application crash or execute arbitrary code
with the privileges of the user invoking the program. (CVE-2014-1740)

Multiple integer overflows were discovered in CharacterData
implementation. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause
a denial of service via renderer crash or execute arbitrary code with
the privileges of the sandboxed render process. (CVE-2014-1741)

Multiple use-after-free issues were discovered in Blink. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit these to cause a denial of service via
renderer crash or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2014-1742, CVE-2014-1743)

An integer overflow bug was discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user
invoking the program. (CVE-2014-1744)

An out-of-bounds read was discovered in Chromium. If a user were
tricked in to opening a specially crafter website, an attacker could
potentially exploit this to cause a denial of service via application
crash. (CVE-2014-1746)

It was discovered that Blink allowed scrollbar painting to extend in
to the parent frame in some circumstances. An attacker could
potentially exploit this to conduct clickjacking attacks via UI
redress. (CVE-2014-1748)

An integer underflow was discovered in Blink. If a user were tricked
in to opening a specially crafter website, an attacker could
potentially exploit this to cause a denial of service via renderer
crash or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2014-3152)

A use-after-free was discovered in Chromium. If a use were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash or
execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2014-3154)

A security issue was discovered in the SPDY implementation. An
attacker could potentially exploit this to cause a denial of service
via application crash or execute arbitrary code with the privileges of
the user invoking the program. (CVE-2014-3155)

A heap overflow was discovered in Chromium. If a use were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash or
execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2014-3157)

It was discovered that Blink did not enforce security rules for
subresource loading in SVG images. If a user opened a site that
embedded a specially crafted image, an attacker could exploit this to
log page views. (CVE-2014-3160)

It was discovered that the SpeechInput feature in Blink could be
activated without consent or any visible indication. If a user were
tricked in to opening a specially crafted website, an attacker could
exploit this to eavesdrop on the user. (CVE-2014-3803).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected liboxideqtcore0, oxideqt-codecs and / or
oxideqt-codecs-extra packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.0.4-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs", pkgver:"1.0.4-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs-extra", pkgver:"1.0.4-0ubuntu0.14.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liboxideqtcore0 / oxideqt-codecs / oxideqt-codecs-extra");
}
