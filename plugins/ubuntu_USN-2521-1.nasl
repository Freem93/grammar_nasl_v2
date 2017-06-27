#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2521-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81753);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/24 17:37:08 $");

  script_cve_id("CVE-2015-1213", "CVE-2015-1214", "CVE-2015-1215", "CVE-2015-1216", "CVE-2015-1217", "CVE-2015-1218", "CVE-2015-1219", "CVE-2015-1220", "CVE-2015-1221", "CVE-2015-1222", "CVE-2015-1223", "CVE-2015-1224", "CVE-2015-1227", "CVE-2015-1228", "CVE-2015-1229", "CVE-2015-1230", "CVE-2015-1231", "CVE-2015-2238");
  script_bugtraq_id(72901, 72916);
  script_osvdb_id(118996, 118997, 118998, 119000, 119001, 119002, 119003, 119004, 119005, 119006, 119007, 119008, 119011, 119012, 119026, 119028, 119029, 119030, 119031, 119032, 119033, 119034, 119035, 119036, 119037, 119038, 119039, 119040, 119041, 119042, 119043, 119044, 119045, 119046, 119047, 119048, 119068, 119105);
  script_xref(name:"USN", value:"2521-1");

  script_name(english:"Ubuntu 14.04 LTS / 14.10 : oxide-qt vulnerabilities (USN-2521-1)");
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
"Several out-of-bounds write bugs were discovered in Skia. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit these to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking the program. (CVE-2015-1213, CVE-2015-1214,
CVE-2015-1215)

A use-after-free was discovered in the V8 bindings in Blink. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
renderer crash, or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2015-1216)

Multiple type confusion bugs were discovered in the V8 bindings in
Blink. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial
of service via renderer crash, or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2015-1217,
CVE-2015-1230)

Multiple use-after-free bugs were discovered in the DOM implementation
in Blink. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial
of service via renderer crash, or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2015-1218,
CVE-2015-1223)

An integer overflow was discovered in Skia. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application crash or
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2015-1219)

A use-after-free was discovered in the GIF image decoder in Blink. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via renderer crash, or execute arbitrary code with the privileges of
the sandboxed render process. (CVE-2015-1220)

A use-after-free was discovered in Blink. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash, or
execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2015-1221)

Multiple use-after-free bugs were discovered in the service worker
implementation in Chromium. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit these
to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2015-1222)

An out-of-bounds read was discovered in the VPX decoder implementation
in Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via renderer crash. (CVE-2015-1224)

It was discovered that Blink did not initialize memory for image
drawing in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to read uninitialized memory. (CVE-2015-1227)

It was discovered that Blink did not initialize memory for a data
structure in some circumstances. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer crash, or execute
arbitrary code with the privileges of the sandboxed render process.
(CVE-2015-1228)

It was discovered that a web proxy returning a 407 response could
inject cookies in to the originally requested domain. If a user
connected to a malicious web proxy, an attacker could potentially
exploit this to conduct session-fixation attacks. (CVE-2015-1229)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1231)

Multiple security issues were discovered in V8. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via renderer crash or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2015-2238).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/11");
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
if (! ereg(pattern:"^(14\.04|14\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 14.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.5.5-0ubuntu0.14.04.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-chromedriver", pkgver:"1.5.5-0ubuntu0.14.04.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs", pkgver:"1.5.5-0ubuntu0.14.04.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs-extra", pkgver:"1.5.5-0ubuntu0.14.04.3")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"liboxideqtcore0", pkgver:"1.5.5-0ubuntu0.14.10.2")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"oxideqt-chromedriver", pkgver:"1.5.5-0ubuntu0.14.10.2")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"oxideqt-codecs", pkgver:"1.5.5-0ubuntu0.14.10.2")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"oxideqt-codecs-extra", pkgver:"1.5.5-0ubuntu0.14.10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liboxideqtcore0 / oxideqt-chromedriver / oxideqt-codecs / etc");
}
