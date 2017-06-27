#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-297-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27872);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2781", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2786", "CVE-2006-2787");
  script_osvdb_id(26298, 26301, 26302, 26303, 26304, 26305, 26306, 26307, 26308, 26309, 26310, 26311, 26312, 26314);
  script_xref(name:"USN", value:"297-3");

  script_name(english:"Ubuntu 5.04 / 5.10 : mozilla-thunderbird vulnerabilities (USN-297-3)");
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
"USN-297-1 fixed several vulnerabilities in Thunderbird for the Ubuntu
6.06 LTS release. This update provides the corresponding fixes for
Ubuntu 5.04 and Ubuntu 5.10.

For reference, these are the details of the original USN :

Jonas Sicking discovered that under some circumstances persisted XUL
attributes are associated with the wrong URL. A malicious website
could exploit this to execute arbitrary code with the privileges of
the user. (MFSA 2006-35, CVE-2006-2775)

Paul Nickerson discovered that content-defined setters on an
object prototype were getting called by privileged UI code.
It was demonstrated that this could be exploited to run
arbitrary web script with full user privileges (MFSA
2006-37, CVE-2006-2776).

Mikolaj Habryn discovered a buffer overflow in the
crypto.signText() function. By sending an email with
malicious JavaScript to an user, and that user enabled
JavaScript in Thunderbird (which is not the default and not
recommended), this could potentially be exploited to execute
arbitrary code with the user's privileges. (MFSA 2006-38,
CVE-2006-2778)

The Mozilla developer team discovered several bugs that lead
to crashes with memory corruption. These might be
exploitable by malicious websites to execute arbitrary code
with the privileges of the user. (MFSA 2006-32,
CVE-2006-2779, CVE-2006-2780)

Masatoshi Kimura discovered a memory corruption
(double-free) when processing a large VCard with invalid
base64 characters in it. By sending a maliciously crafted
set of VCards to a user, this could potentially be exploited
to execute arbitrary code with the user's privileges. (MFSA
2006-40, CVE-2006-2781)

Masatoshi Kimura found a way to bypass web input sanitizers
which filter out JavaScript. By inserting 'Unicode
Byte-order-Mark (BOM)' characters into the HTML code (e. g.
'<scr[BOM]ipt>'), these filters might not recognize the tags
anymore; however, Thunderbird would still execute them since
BOM markers are filtered out before processing a mail
containing JavaScript. (MFSA 2006-42, CVE-2006-2783)

Kazuho Oku discovered various ways to perform HTTP response
smuggling when used with certain proxy servers. Due to
different interpretation of nonstandard HTTP headers in
Thunderbird and the proxy server, a malicious HTML email can
exploit this to send back two responses to one request. The
second response could be used to steal login cookies or
other sensitive data from another opened web site. (MFSA
2006-33, CVE-2006-2786)

It was discovered that JavaScript run via EvalInSandbox()
can escape the sandbox. Malicious scripts received in emails
containing JavaScript could use these privileges to execute
arbitrary code with the user's privileges. (MFSA 2006-31,
CVE-2006-2787).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-offline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-typeaheadfind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/26");
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

if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird", pkgver:"1.0.8-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-dev", pkgver:"1.0.8-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.0.8-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-offline", pkgver:"1.0.8-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.0.8-0ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird", pkgver:"1.0.8-0ubuntu05.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-dev", pkgver:"1.0.8-0ubuntu05.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.0.8-0ubuntu05.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-offline", pkgver:"1.0.8-0ubuntu05.10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.0.8-0ubuntu05.10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-thunderbird / mozilla-thunderbird-dev / etc");
}
