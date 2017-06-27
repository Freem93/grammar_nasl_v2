#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-200-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20616);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/26 16:22:49 $");

  script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2968");
  script_osvdb_id(19589, 19643, 19644, 19645, 19646, 19647, 19648, 19649);
  script_xref(name:"USN", value:"200-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : mozilla-thunderbird vulnerabilities (USN-200-1)");
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
"A buffer overflow was discovered in the XBM image handler. By tricking
an user into opening a specially crafted XBM image, an attacker could
exploit this to execute arbitrary code with the user's privileges.
(CAN-2005-2701)

Mats Palmgren discovered a buffer overflow in the Unicode string
parser. Unicode strings that contained 'zero-width non-joiner'
characters caused a browser crash, which could possibly even exploited
to execute arbitrary code with the user's privileges. (CAN-2005-2702)

Georgi Guninski reported an integer overflow in the JavaScript engine.
This could be exploited to run arbitrary code under some conditions.
(CAN-2005-2705)

Peter Zelezny discovered that URLs which are passed to Thunderbird on
the command line are not correctly protected against interpretation by
the shell. If Thunderbird is configured as the default handler for
'mailto:' URLs, this could be exploited to execute arbitrary code with
user privileges by tricking the user into clicking on a specially
crafted URL (for example, in an email or chat client). (CAN-2005-2968)

This update also fixes some less critical issues which are described
at http://www.mozilla.org/security/announce/mfsa2005-58.html.
(CAN-2005-2703, CAN-2005-2704, CAN-2005-2706, CAN-2005-2707)

The 'enigmail' plugin has been updated to work with the new
Thunderbird and Mozilla versions.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-offline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-typeaheadfind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"mozilla-enigmail", pkgver:"0.92-1ubuntu04.10.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird", pkgver:"1.0.7-0ubuntu04.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird-dev", pkgver:"1.0.7-0ubuntu04.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird-enigmail", pkgver:"0.92-1ubuntu04.10.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.0.7-0ubuntu04.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird-offline", pkgver:"1.0.7-0ubuntu04.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.0.7-0ubuntu04.10")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-enigmail", pkgver:"0.92-1ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird", pkgver:"1.0.7-0ubuntu05.04")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-dev", pkgver:"1.0.7-0ubuntu05.04")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-enigmail", pkgver:"0.92-1ubuntu05.04.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.0.7-0ubuntu05.04")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-offline", pkgver:"1.0.7-0ubuntu05.04")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.0.7-0ubuntu05.04")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-enigmail / mozilla-thunderbird / mozilla-thunderbird-dev / etc");
}
