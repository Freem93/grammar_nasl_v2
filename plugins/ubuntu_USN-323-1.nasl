#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-323-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27901);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2005-0752", "CVE-2006-1729", "CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2777", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2781", "CVE-2006-2782", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787");
  script_osvdb_id(26298, 26299, 26300, 26301, 26302, 26303, 26304, 26305, 26306, 26307, 26308, 26309, 26310, 26311, 26312, 26313, 26314, 26315);
  script_xref(name:"USN", value:"323-1");

  script_name(english:"Ubuntu 5.04 / 5.10 : mozilla vulnerabilities (USN-323-1)");
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
"Jonas Sicking discovered that under some circumstances persisted XUL
attributes are associated with the wrong URL. A malicious website
could exploit this to execute arbitrary code with the privileges of
the user. (MFSA 2006-35, CVE-2006-2775)

Paul Nickerson discovered that content-defined setters on an object
prototype were getting called by privileged UI code. It was
demonstrated that this could be exploited to run arbitrary web script
with full user privileges (MFSA 2006-37, CVE-2006-2776). A similar
attack was discovered by moz_bug_r_a4 that leveraged SelectionObject
notifications that were called in privileged context. (MFSA 2006-43,
CVE-2006-2777)

Mikolaj Habryn discovered a buffer overflow in the crypto.signText()
function. By tricking a user to visit a site with an SSL certificate
with specially crafted optional Certificate Authority name arguments,
this could potentially be exploited to execute arbitrary code with the
user's privileges. (MFSA 2006-38, CVE-2006-2778)

The Mozilla developer team discovered several bugs that lead to
crashes with memory corruption. These might be exploitable by
malicious websites to execute arbitrary code with the privileges of
the user. (MFSA 2006-32, CVE-2006-2779, CVE-2006-2780)

Masatoshi Kimura discovered a memory corruption (double-free) when
processing a large VCard with invalid base64 characters in it. By
sending a maliciously crafted set of VCards to a user, this could
potentially be exploited to execute arbitrary code with the user's
privileges. (MFSA 2006-40, CVE-2006-2781)

Chuck McAuley reported that the fix for CVE-2006-1729 (file stealing
by changing input type) was not sufficient to prevent all variants of
exploitation. (MFSA 2006-41, CVE-2006-2782)

Masatoshi Kimura found a way to bypass web input sanitizers which
filter out JavaScript. By inserting 'Unicode Byte-order-Mark (BOM)'
characters into the HTML code (e. g. '<scr[BOM]ipt>'), these filters
might not recognize the tags anymore; however, Mozilla would still
execute them since BOM markers are filtered out before processing the
page. (MFSA 2006-42, CVE-2006-2783)

Paul Nickerson noticed that the fix for CVE-2005-0752 (JavaScript
privilege escalation on the plugins page) was not sufficient to
prevent all variants of exploitation. (MFSA 2006-36, CVE-2006-2784)

Paul Nickerson demonstrated that if an attacker could convince a user
to right-click on a broken image and choose 'View Image' from the
context menu then he could get JavaScript to run on a site of the
attacker's choosing. This could be used to steal login cookies or
other confidential information from the target site. (MFSA 2006-34,
CVE-2006-2785)

Kazuho Oku discovered various ways to perform HTTP response smuggling
when used with certain proxy servers. Due to different interpretation
of nonstandard HTTP headers in Mozilla and the proxy server, a
malicious website can exploit this to send back two responses to one
request. The second response could be used to steal login cookies or
other sensitive data from another opened website. (MFSA 2006-33,
CVE-2006-2786).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-chatzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-mailnews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-psm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"libnspr-dev", pkgver:"1.7.13-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libnspr4", pkgver:"1.7.13-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libnss-dev", pkgver:"1.7.13-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libnss3", pkgver:"1.7.13-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla", pkgver:"1.7.13-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-browser", pkgver:"2:1.7.13-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-calendar", pkgver:"1.7.13-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-chatzilla", pkgver:"1.7.13-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-dev", pkgver:"1.7.13-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-dom-inspector", pkgver:"1.7.13-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-js-debugger", pkgver:"1.7.13-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-mailnews", pkgver:"2:1.7.13-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-psm", pkgver:"2:1.7.13-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libnspr-dev", pkgver:"1.7.13-0ubuntu5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libnspr4", pkgver:"1.7.13-0ubuntu5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libnss-dev", pkgver:"1.7.13-0ubuntu5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libnss3", pkgver:"1.7.13-0ubuntu5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla", pkgver:"1.7.13-0ubuntu5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-browser", pkgver:"2:1.7.13-0ubuntu5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-calendar", pkgver:"1.7.13-0ubuntu5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-chatzilla", pkgver:"1.7.13-0ubuntu5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-dev", pkgver:"1.7.13-0ubuntu5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-dom-inspector", pkgver:"1.7.13-0ubuntu5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-js-debugger", pkgver:"1.7.13-0ubuntu5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-mailnews", pkgver:"2:1.7.13-0ubuntu5.10.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-psm", pkgver:"2:1.7.13-0ubuntu5.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnspr-dev / libnspr4 / libnss-dev / libnss3 / mozilla / etc");
}
