#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2770-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86565);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/24 17:44:51 $");

  script_cve_id("CVE-2015-6755", "CVE-2015-6757", "CVE-2015-6759", "CVE-2015-6761", "CVE-2015-6762", "CVE-2015-6763", "CVE-2015-7834");
  script_osvdb_id(126459, 128813, 128814, 128815, 128816, 128817, 128818, 128819, 128820, 128821, 128828, 128829, 128831, 128833, 128834);
  script_xref(name:"USN", value:"2770-2");

  script_name(english:"Ubuntu 15.10 : oxide-qt vulnerabilities (USN-2770-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2770-1 fixed vulnerabilities in Oxide in Ubuntu 14.04 LTS and
Ubuntu 15.04. This update provides the corresponding updates for
Ubuntu 15.10.

It was discovered that ContainerNode::parserInsertBefore in Blink
would incorrectly proceed with a DOM tree insertion in some
circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to bypass
same origin restrictions. (CVE-2015-6755)

A use-after-free was discovered in the service worker
implementation in Chromium. If a user were tricked in to
opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-6757)

It was discovered that Blink did not ensure that the origin
of LocalStorage resources are considered unique. If a user
were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to obtain sensitive
information. (CVE-2015-6759)

A race condition and memory corruption was discovered in
FFmpeg. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this
to cause a denial of service via renderer crash, or execute
arbitrary code with the privileges of the sandboxed render
process. (CVE-2015-6761)

It was discovered that CSSFontFaceSrcValue::fetch in Blink
did not use CORS in some circumstances. If a user were
tricked in to opening a specially crafted website, an
attacker could potentially exploit this to bypass same
origin restrictions. (CVE-2015-6762)

Multiple security issues were discovered in Chromium. If a
user were tricked in to opening a specially crafted website,
an attacker could potentially exploit these to read
uninitialized memory, cause a denial of service via
application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-6763)

Multiple security issues were discovered in V8. If a user
were tricked in to opening a specially crafted website, an
attacker could potentially exploit these to read
uninitialized memory, cause a denial of service via renderer
crash or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2015-7834).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liboxideqtcore0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/23");
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
if (! ereg(pattern:"^(15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"15.10", pkgname:"liboxideqtcore0", pkgver:"1.10.3-0ubuntu0.15.10.1")) flag++;

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
