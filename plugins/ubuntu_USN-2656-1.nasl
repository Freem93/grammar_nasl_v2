#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2656-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84664);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2015-2721", "CVE-2015-2722", "CVE-2015-2724", "CVE-2015-2725", "CVE-2015-2726", "CVE-2015-2727", "CVE-2015-2728", "CVE-2015-2729", "CVE-2015-2730", "CVE-2015-2731", "CVE-2015-2733", "CVE-2015-2734", "CVE-2015-2735", "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738", "CVE-2015-2739", "CVE-2015-2740", "CVE-2015-2741", "CVE-2015-2743", "CVE-2015-4000");
  script_bugtraq_id(74733, 75541);
  script_osvdb_id(118705, 122331, 124070, 124071, 124072, 124073, 124074, 124075, 124076, 124077, 124078, 124079, 124080, 124081, 124082, 124083, 124084, 124085, 124086, 124087, 124089, 124090, 124091, 124092, 124093, 124094, 124095, 124096, 124097, 124098, 124099, 124100, 124101, 124102, 124104, 124105);
  script_xref(name:"USN", value:"2656-1");

  script_name(english:"Ubuntu 14.04 LTS / 14.10 / 15.04 : firefox vulnerabilities (USN-2656-1) (Logjam)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Karthikeyan Bhargavan discovered that NSS incorrectly handled state
transitions for the TLS state machine. If a remote attacker were able
to perform a man-in-the-middle attack, this flaw could be exploited to
skip the ServerKeyExchange message and remove the forward-secrecy
property. (CVE-2015-2721)

Looben Yan discovered 2 use-after-free issues when using
XMLHttpRequest in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit these to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-2722, CVE-2015-2733)

Bob Clary, Christian Holler, Bobby Holley, Andrew McCreight, Terrence
Cole, Steve Fink, Mats Palmgren, Wes Kocher, Andreas Pehrson, Tooru
Fujisawa, Andrew Sutherland, and Gary Kwong discovered multiple memory
safety issues in Firefox. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit these
to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2015-2724, CVE-2015-2725, CVE-2015-2726)

Armin Razmdjou discovered that opening hyperlinks with specific mouse
and key combinations could allow a Chrome privileged URL to be opened
without context restrictions being preserved. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to bypass security restrictions.
(CVE-2015-2727)

Paul Bandha discovered a type confusion bug in the Indexed DB Manager.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via application crash or execute arbitrary code with the priviliges of
the user invoking Firefox. (CVE-2015-2728)

Holger Fuhrmannek discovered an out-of-bounds read in Web Audio. If a
user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to obtain sensitive
information. (CVE-2015-2729)

Watson Ladd discovered that NSS incorrectly handled Elliptical Curve
Cryptography (ECC) multiplication. A remote attacker could possibly
use this issue to spoof ECDSA signatures. (CVE-2015-2730)

A use-after-free was discovered when a Content Policy modifies the DOM
to remove a DOM object. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash or execute
arbitrary code with the priviliges of the user invoking Firefox.
(CVE-2015-2731)

Ronald Crane discovered multiple security vulnerabilities. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit these to cause a denial of service via
application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2015-2734, CVE-2015-2735,
CVE-2015-2736, CVE-2015-2737, CVE-2015-2738, CVE-2015-2739,
CVE-2015-2740)

David Keeler discovered that key pinning checks can be skipped when an
overridable certificate error occurs. This allows a user to manually
override an error for a fake certificate, but cannot be exploited on
its own. (CVE-2015-2741)

Jonas Jenwald discovered that some internal workers were incorrectly
executed with a high privilege. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
in combination with another security vulnerability, to execute
arbitrary code in a privileged scope. (CVE-2015-2743)

Matthew Green discovered a DHE key processing issue in NSS where a
MITM could force a server to downgrade TLS connections to 512-bit
export-grade cryptography. An attacker could potentially exploit this
to impersonate the server. (CVE-2015-4000).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/13");
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
if (! ereg(pattern:"^(14\.04|14\.10|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 14.10 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"39.0+build5-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"firefox", pkgver:"39.0+build5-0ubuntu0.14.10.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"firefox", pkgver:"39.0+build5-0ubuntu0.15.04.1")) flag++;

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
