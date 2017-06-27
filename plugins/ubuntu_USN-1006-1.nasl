#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1006-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50046);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

  script_cve_id("CVE-2009-2797", "CVE-2009-2841", "CVE-2010-0046", "CVE-2010-0047", "CVE-2010-0048", "CVE-2010-0049", "CVE-2010-0050", "CVE-2010-0051", "CVE-2010-0052", "CVE-2010-0053", "CVE-2010-0054", "CVE-2010-0314", "CVE-2010-0647", "CVE-2010-0650", "CVE-2010-0651", "CVE-2010-0656", "CVE-2010-1386", "CVE-2010-1387", "CVE-2010-1389", "CVE-2010-1390", "CVE-2010-1391", "CVE-2010-1392", "CVE-2010-1393", "CVE-2010-1394", "CVE-2010-1395", "CVE-2010-1396", "CVE-2010-1397", "CVE-2010-1398", "CVE-2010-1400", "CVE-2010-1401", "CVE-2010-1402", "CVE-2010-1403", "CVE-2010-1404", "CVE-2010-1405", "CVE-2010-1406", "CVE-2010-1407", "CVE-2010-1408", "CVE-2010-1409", "CVE-2010-1410", "CVE-2010-1412", "CVE-2010-1414", "CVE-2010-1415", "CVE-2010-1416", "CVE-2010-1417", "CVE-2010-1418", "CVE-2010-1419", "CVE-2010-1421", "CVE-2010-1422", "CVE-2010-1664", "CVE-2010-1665", "CVE-2010-1758", "CVE-2010-1759", "CVE-2010-1760", "CVE-2010-1761", "CVE-2010-1762", "CVE-2010-1764", "CVE-2010-1766", "CVE-2010-1767", "CVE-2010-1770", "CVE-2010-1771", "CVE-2010-1772", "CVE-2010-1773", "CVE-2010-1774", "CVE-2010-1780", "CVE-2010-1781", "CVE-2010-1782", "CVE-2010-1783", "CVE-2010-1784", "CVE-2010-1785", "CVE-2010-1786", "CVE-2010-1787", "CVE-2010-1788", "CVE-2010-1790", "CVE-2010-1792", "CVE-2010-1793", "CVE-2010-1807", "CVE-2010-1812", "CVE-2010-1814", "CVE-2010-1815", "CVE-2010-2264", "CVE-2010-2647", "CVE-2010-2648", "CVE-2010-3113", "CVE-2010-3114", "CVE-2010-3115", "CVE-2010-3116", "CVE-2010-3248", "CVE-2010-3257", "CVE-2010-3259");
  script_bugtraq_id(36339, 36996, 37925, 37948, 38177, 38372, 38373, 38684, 38685, 38686, 38687, 38688, 38689, 38690, 38691, 38692, 39804, 39808, 40644, 40646, 40647, 40649, 40650, 40653, 40654, 40655, 40656, 40657, 40658, 40659, 40660, 40661, 40662, 40663, 40665, 40666, 40667, 40668, 40669, 40670, 40671, 40672, 40675, 40697, 40698, 40705, 40707, 40710, 40714, 40726, 40727, 40732, 40750, 40753, 40754, 40756, 41051, 41053, 41572, 41573, 41575, 42034, 42035, 42036, 42037, 42038, 42041, 42042, 42043, 42044, 42046, 42049, 42494, 42500, 43047, 43077, 43079, 43081, 43083, 44199, 44200, 44201, 44203, 44204, 44206);
  script_osvdb_id(57891, 59941, 61792, 61793, 62306, 62307, 62308, 62317, 62939, 62940, 62941, 62942, 62943, 62947, 62948, 62949, 64002, 64257, 65299, 65301, 65302, 65303, 65304, 65305, 65306, 65307, 65308, 65309, 65310, 65311, 65312, 65313, 65314, 65315, 65316, 65317, 65318, 65319, 65320, 65321, 65322, 65326, 65327, 65328, 65329, 65330, 65333, 65334, 65335, 65336, 65337, 65338, 65340, 65341, 65399, 65400, 65448, 65657, 65700, 66480, 66845, 66846, 66847, 66848, 66849, 66850, 66851, 66852, 66854, 66856, 66857, 67295, 67296, 67459, 67460, 67461, 67462, 67865, 67867, 67926, 67930, 67932, 67933, 67962, 89663);
  script_xref(name:"USN", value:"1006-1");

  script_name(english:"Ubuntu 9.10 / 10.04 LTS / 10.10 : webkit vulnerabilities (USN-1006-1)");
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
"A large number of security issues were discovered in the WebKit
browser and JavaScript engines. If a user were tricked into viewing a
malicious website, a remote attacker could exploit a variety of issues
related to web browser security, including cross-site scripting
attacks, denial of service attacks, and arbitrary code execution.

Please consult the bug listed at the top of this advisory to get the
exact list of CVE numbers fixed for each release.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.0-webkit-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit-1.0-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit-1.0-2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit-1.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:webkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.10", pkgname:"libwebkit-1.0-2", pkgver:"1.2.5-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libwebkit-1.0-2-dbg", pkgver:"1.2.5-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libwebkit-1.0-common", pkgver:"1.2.5-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libwebkit-dev", pkgver:"1.2.5-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"gir1.0-webkit-1.0", pkgver:"1.2.5-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libwebkit-1.0-2", pkgver:"1.2.5-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libwebkit-1.0-2-dbg", pkgver:"1.2.5-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libwebkit-1.0-common", pkgver:"1.2.5-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libwebkit-dev", pkgver:"1.2.5-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"webkit", pkgver:"1.2.5-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"gir1.0-webkit-1.0", pkgver:"1.2.5-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libwebkit-1.0-2", pkgver:"1.2.5-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libwebkit-1.0-2-dbg", pkgver:"1.2.5-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libwebkit-1.0-common", pkgver:"1.2.5-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libwebkit-dev", pkgver:"1.2.5-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"webkit", pkgver:"1.2.5-0ubuntu0.10.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gir1.0-webkit-1.0 / libwebkit-1.0-2 / libwebkit-1.0-2-dbg / etc");
}
