#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3041-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92784);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2016-1705", "CVE-2016-1706", "CVE-2016-1710", "CVE-2016-1711", "CVE-2016-5127", "CVE-2016-5128", "CVE-2016-5129", "CVE-2016-5130", "CVE-2016-5131", "CVE-2016-5132", "CVE-2016-5133", "CVE-2016-5134", "CVE-2016-5135", "CVE-2016-5137");
  script_osvdb_id(137439, 137773, 141924, 141928, 141929, 141930, 141931, 141932, 141933, 141934, 141935, 141936, 141937, 141938, 141940, 141947, 141948, 141949, 141950, 141951, 141952, 141989, 141990, 141991, 141992, 141994, 141995, 142038, 142039, 142040, 142085);
  script_xref(name:"USN", value:"3041-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : oxide-qt vulnerabilities (USN-3041-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service (application crash) or execute arbitrary code.
(CVE-2016-1705)

It was discovered that the PPAPI implementation does not validate the
origin of IPC messages to the plugin broker process. A remote attacker
could potentially exploit this to bypass sandbox protection
mechanisms. (CVE-2016-1706)

It was discovered that Blink does not prevent window creation by a
deferred frame. A remote attacker could potentially exploit this to
bypass same origin restrictions. (CVE-2016-1710)

It was discovered that Blink does not disable frame navigation during
a detach operation on a DocumentLoader object. A remote attacker could
potentially exploit this to bypass same origin restrictions.
(CVE-2016-1711)

A use-after-free was discovered in Blink. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer process crash,
or execute arbitrary code. (CVE-2016-5127)

It was discovered that objects.cc in V8 does not prevent API
interceptors from modifying a store target without setting a property.
A remote attacker could potentially exploit this to bypass same origin
restrictions. (CVE-2016-5128)

A memory corruption was discovered in V8. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer process crash,
or execute arbitrary code. (CVE-2016-5129)

A security issue was discovered in Chromium. A remote attacker could
potentially exploit this to spoof the currently displayed URL.
(CVE-2016-5130)

A use-after-free was discovered in libxml. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer process crash,
or execute arbitrary code. (CVE-2016-5131)

The Service Workers implementation in Chromium does not properly
implement the Secure Contexts specification during decisions about
whether to control a subframe. A remote attacker could potentially
exploit this to bypass same origin restrictions. (CVE-2016-5132)

It was discovered that Chromium mishandles origin information during
proxy authentication. A man-in-the-middle attacker could potentially
exploit this to spoof a proxy authentication login prompt.
(CVE-2016-5133)

It was discovered that the Proxy Auto-Config (PAC) feature in Chromium
does not ensure that URL information is restricted to a scheme, host
and port. A remote attacker could potentially exploit this to obtain
sensitive information. (CVE-2016-5134)

It was discovered that Blink does not consider referrer-policy
information inside an HTML document during a preload request. A remote
attacker could potentially exploit this to bypass Content Security
Policy (CSP) protections. (CVE-2016-5135)

It was discovered that the Content Security Policy (CSP)
implementation in Blink does not apply http :80 policies to https :443
URLs. A remote attacker could potentially exploit this to determine
whether a specific HSTS website has been visited by reading a CSP
report. (CVE-2016-5137).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liboxideqtcore0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
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
if (! ereg(pattern:"^(14\.04|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.16.5-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"liboxideqtcore0", pkgver:"1.16.5-0ubuntu0.16.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liboxideqtcore0");
}
