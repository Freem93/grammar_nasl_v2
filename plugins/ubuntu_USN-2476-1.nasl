#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2476-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81016);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/24 17:37:08 $");

  script_cve_id("CVE-2014-7923", "CVE-2014-7924", "CVE-2014-7925", "CVE-2014-7926", "CVE-2014-7927", "CVE-2014-7928", "CVE-2014-7929", "CVE-2014-7930", "CVE-2014-7931", "CVE-2014-7932", "CVE-2014-7933", "CVE-2014-7934", "CVE-2014-7937", "CVE-2014-7938", "CVE-2014-7940", "CVE-2014-7942", "CVE-2014-7943", "CVE-2014-7946", "CVE-2014-7948", "CVE-2015-1205", "CVE-2015-1346");
  script_bugtraq_id(72288);
  script_osvdb_id(112817, 115057, 117380, 117381, 117382, 117383, 117384, 117385, 117386, 117387, 117388, 117389, 117390, 117391, 117395, 117397, 117399, 117400, 117403, 117405, 117611, 117613, 117617, 117639, 117641, 117643, 117646, 117650, 117657, 117661, 117679, 117682, 117683, 117684, 117685, 117688, 117689, 117721, 117722, 117723, 117724, 117813, 117814, 117815, 117817, 117820, 117821, 117822, 117823, 117824, 117826);
  script_xref(name:"USN", value:"2476-1");

  script_name(english:"Ubuntu 14.04 LTS / 14.10 : oxide-qt vulnerabilities (USN-2476-1)");
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
"Several memory corruption bugs were discovered in ICU. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via renderer
crash or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2014-7923, CVE-2014-7926)

A use-after-free was discovered in the IndexedDB implementation. If a
user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via application crash or execute arbitrary code with the privileges of
the user invoking the program. (CVE-2014-7924)

A use-after free was discovered in the WebAudio implementation in
Blink. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via renderer crash or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2014-7925)

Several memory corruption bugs were discovered in V8. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via renderer
crash or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2014-7927, CVE-2014-7928, CVE-2014-7931)

Several use-after free bugs were discovered in the DOM implementation
in Blink. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial
of service via renderer crash or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2014-7929,
CVE-2014-7930, CVE-2014-7932, CVE-2014-7934)

A use-after free was discovered in FFmpeg. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash or
execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2014-7933)

Multiple off-by-one errors were discovered in FFmpeg. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via renderer
crash or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2014-7937)

A memory corruption bug was discovered in the fonts implementation. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via renderer crash or execute arbitrary code with the privileges of
the sandboxed render process. (CVE-2014-7938)

It was discovered that ICU did not initialize memory for a data
structure correctly. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via renderer crash or execute arbitrary code with
the privileges of the sandboxed render process. (CVE-2014-7940)

It was discovered that the fonts implementation did not initialize
memory for a data structure correctly. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash or
execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2014-7942)

An out-of-bounds read was discovered in Skia. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via renderer
crash. (CVE-2014-7943)

An out-of-bounds read was discovered in Blink. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via renderer
crash. (CVE-2014-7946)

It was discovered that the AppCache proceeded with caching for SSL
sessions even if there is a certificate error. A remote attacker could
potentially exploit this by conducting a MITM attack to modify HTML
application content. (CVE-2014-7948)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1205)

Multiple security issues were discovered in V8. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via renderer crash or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2015-1346).

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
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/27");
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

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.4.2-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs", pkgver:"1.4.2-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs-extra", pkgver:"1.4.2-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"liboxideqtcore0", pkgver:"1.4.2-0ubuntu0.14.10.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"oxideqt-codecs", pkgver:"1.4.2-0ubuntu0.14.10.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"oxideqt-codecs-extra", pkgver:"1.4.2-0ubuntu0.14.10.1")) flag++;

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
