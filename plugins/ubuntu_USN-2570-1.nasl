#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2570-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83109);
  script_version("$Revision: 2.14 $");
  script_cvs_date("$Date: 2016/05/24 17:37:08 $");

  script_cve_id("CVE-2015-1235", "CVE-2015-1236", "CVE-2015-1237", "CVE-2015-1238", "CVE-2015-1240", "CVE-2015-1241", "CVE-2015-1242", "CVE-2015-1244", "CVE-2015-1246", "CVE-2015-1249", "CVE-2015-1321", "CVE-2015-3333");
  script_bugtraq_id(74165, 74167, 74221, 74411);
  script_osvdb_id(117805, 120749, 120750, 120751, 120752, 120753, 120754, 120759, 120760, 120805, 120806, 120827, 120829, 120831, 120832, 120852, 120853, 120854, 120864, 120866, 120867, 120868, 120869, 120882, 120883, 120884, 120909, 120910, 120911, 120913, 120914, 120917);
  script_xref(name:"USN", value:"2570-1");

  script_name(english:"Ubuntu 14.04 LTS / 14.10 / 15.04 : oxide-qt vulnerabilities (USN-2570-1)");
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
"An issue was discovered in the HTML parser in Blink. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to bypass same-origin restrictions.
(CVE-2015-1235)

An issue was discovered in the Web Audio API implementation in Blink.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to bypass same-origin
restrictions. (CVE-2015-1236)

A use-after-free was discovered in Chromium. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash, or
execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2015-1237)

An out-of-bounds write was discovered in Skia. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user
invoking the program. (CVE-2015-1238)

An out-of-bounds read was discovered in the WebGL implementation. If a
user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via renderer crash. (CVE-2015-1240)

An issue was discovered with the interaction of page navigation and
touch event handling. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to conduct
'tap jacking' attacks. (CVE-2015-1241)

A type confusion bug was discovered in V8. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash, or
execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2015-1242)

It was discovered that websocket connections were not upgraded
whenever a HSTS policy is active. A remote attacker could potentially
exploit this to conduct a man in the middle (MITM) attack.
(CVE-2015-1244)

An out-of-bounds read was discovered in Blink. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via renderer
crash. (CVE-2015-1246)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1249)

A use-after-free was discovered in the file picker implementation. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via application crash or execute arbitrary code with the privileges of
the user invoking the program. (CVE-2015-1321)

Multiple security issues were discovered in V8. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via renderer crash or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2015-3333).

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
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/28");
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

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.6.5-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs", pkgver:"1.6.5-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs-extra", pkgver:"1.6.5-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"liboxideqtcore0", pkgver:"1.6.5-0ubuntu0.14.10.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"oxideqt-codecs", pkgver:"1.6.5-0ubuntu0.14.10.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"oxideqt-codecs-extra", pkgver:"1.6.5-0ubuntu0.14.10.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"liboxideqtcore0", pkgver:"1.6.5-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"oxideqt-codecs", pkgver:"1.6.5-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"oxideqt-codecs-extra", pkgver:"1.6.5-0ubuntu0.15.04.1")) flag++;

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
