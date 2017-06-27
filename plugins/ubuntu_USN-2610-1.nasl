#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2610-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83778);
  script_version("$Revision: 2.13 $");
  script_cvs_date("$Date: 2016/05/24 17:44:49 $");

  script_cve_id("CVE-2015-1253", "CVE-2015-1254", "CVE-2015-1255", "CVE-2015-1256", "CVE-2015-1257", "CVE-2015-1258", "CVE-2015-1260", "CVE-2015-1262", "CVE-2015-1265", "CVE-2015-3910");
  script_bugtraq_id(74723, 74727);
  script_osvdb_id(120092, 122291, 122292, 122293, 122294, 122295, 122297, 122299, 122330, 122340, 122343, 122359, 122360, 122377, 122378, 122380, 122398, 122400, 122406);
  script_xref(name:"USN", value:"2610-1");

  script_name(english:"Ubuntu 14.04 LTS / 14.10 / 15.04 : oxide-qt vulnerabilities (USN-2610-1)");
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
"Several security issues were discovered in the DOM implementation in
Blink. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to bypass Same
Origin Policy restrictions. (CVE-2015-1253, CVE-2015-1254)

A use-after-free was discovered in the WebAudio implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via renderer crash, or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2015-1255)

A use-after-free was discovered in the SVG implementation in Blink. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via renderer crash, or execute arbitrary code with the privileges of
the sandboxed render process. (CVE-2015-1256)

A security issue was discovered in the SVG implementation in Blink. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via renderer crash. (CVE-2015-1257)

An issue was discovered with the build of libvpx. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via renderer
crash, or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2015-1258)

Multiple use-after-free issues were discovered in the WebRTC
implementation in Chromium. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit these
to cause a denial of service via renderer crash, or execute arbitrary
code with the privileges of the sandboxed render process.
(CVE-2015-1260)

An uninitialized value bug was discovered in the font shaping code in
Blink. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via renderer crash. (CVE-2015-1262)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1265)

Multiple security issues were discovered in V8. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via renderer crash or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2015-3910).

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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/22");
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

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.7.8-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs", pkgver:"1.7.8-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs-extra", pkgver:"1.7.8-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"liboxideqtcore0", pkgver:"1.7.8-0ubuntu0.14.10.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"oxideqt-codecs", pkgver:"1.7.8-0ubuntu0.14.10.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"oxideqt-codecs-extra", pkgver:"1.7.8-0ubuntu0.14.10.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"liboxideqtcore0", pkgver:"1.7.8-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"oxideqt-codecs", pkgver:"1.7.8-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"oxideqt-codecs-extra", pkgver:"1.7.8-0ubuntu0.15.04.1")) flag++;

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
