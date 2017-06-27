#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1619-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62709);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/25 16:19:25 $");

  script_cve_id("CVE-2012-1531", "CVE-2012-1532", "CVE-2012-1533", "CVE-2012-3143", "CVE-2012-3159", "CVE-2012-3216", "CVE-2012-4416", "CVE-2012-5067", "CVE-2012-5068", "CVE-2012-5069", "CVE-2012-5070", "CVE-2012-5071", "CVE-2012-5072", "CVE-2012-5073", "CVE-2012-5074", "CVE-2012-5075", "CVE-2012-5076", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5083", "CVE-2012-5084", "CVE-2012-5085", "CVE-2012-5086", "CVE-2012-5087", "CVE-2012-5088", "CVE-2012-5089");
  script_bugtraq_id(55501, 56025, 56033, 56039, 56046, 56051, 56055, 56056, 56058, 56059, 56061, 56065, 56067, 56070, 56072, 56075, 56076, 56079, 56080, 56081, 56082, 56083);
  script_osvdb_id(86344, 86345, 86346, 86347, 86348, 86349, 86350, 86351, 86352, 86354, 86355, 86357, 86358, 86359, 86360, 86361, 86362, 86363, 86364, 86365, 86366, 86367, 86368, 86369, 86371, 86372, 86374);
  script_xref(name:"USN", value:"1619-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS / 12.10 : openjdk-6, openjdk-7 vulnerabilities (USN-1619-1)");
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
"Several information disclosure vulnerabilities were discovered in the
OpenJDK JRE. (CVE-2012-3216, CVE-2012-5069, CVE-2012-5072,
CVE-2012-5075, CVE-2012-5077, CVE-2012-5085)

Vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. (CVE-2012-4416,
CVE-2012-5071)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit
these to cause a denial of service. (CVE-2012-1531, CVE-2012-1532,
CVE-2012-1533, CVE-2012-3143, CVE-2012-3159, CVE-2012-5068,
CVE-2012-5083, CVE-2012-5084, CVE-2012-5086, CVE-2012-5089)

Information disclosure vulnerabilities were discovered in the OpenJDK
JRE. These issues only affected Ubuntu 12.10. (CVE-2012-5067,
CVE-2012-5070)

Vulnerabilities were discovered in the OpenJDK JRE related to data
integrity. (CVE-2012-5073, CVE-2012-5079)

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure and data integrity. This issue only affected
Ubuntu 12.10. (CVE-2012-5074)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit
these to cause a denial of service. These issues only affected Ubuntu
12.10. (CVE-2012-5076, CVE-2012-5087, CVE-2012-5088)

A denial of service vulnerability was found in OpenJDK.
(CVE-2012-5081)

Please see the following for more information:
http://www.oracle.com/technetwork/topics/security/javacpuoct2012-15159
24.html.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Method Handle Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-cacao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-7-jre-cacao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-7-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-zero");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|11\.04|11\.10|12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.04 / 11.10 / 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b24-1.11.5-0ubuntu1~10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre", pkgver:"6b24-1.11.5-0ubuntu1~10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b24-1.11.5-0ubuntu1~10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b24-1.11.5-0ubuntu1~10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b24-1.11.5-0ubuntu1~10.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b24-1.11.5-0ubuntu1~11.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"icedtea-6-jre-jamvm", pkgver:"6b24-1.11.5-0ubuntu1~11.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre", pkgver:"6b24-1.11.5-0ubuntu1~11.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b24-1.11.5-0ubuntu1~11.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b24-1.11.5-0ubuntu1~11.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b24-1.11.5-0ubuntu1~11.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"icedtea-6-jre-cacao", pkgver:"6b24-1.11.5-0ubuntu1~11.10.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"icedtea-6-jre-jamvm", pkgver:"6b24-1.11.5-0ubuntu1~11.10.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre", pkgver:"6b24-1.11.5-0ubuntu1~11.10.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b24-1.11.5-0ubuntu1~11.10.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b24-1.11.5-0ubuntu1~11.10.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre-zero", pkgver:"6b24-1.11.5-0ubuntu1~11.10.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b24-1.11.5-0ubuntu1~12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"icedtea-6-jre-jamvm", pkgver:"6b24-1.11.5-0ubuntu1~12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre", pkgver:"6b24-1.11.5-0ubuntu1~12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b24-1.11.5-0ubuntu1~12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b24-1.11.5-0ubuntu1~12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b24-1.11.5-0ubuntu1~12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"icedtea-7-jre-cacao", pkgver:"7u9-2.3.3-0ubuntu1~12.10.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"icedtea-7-jre-jamvm", pkgver:"7u9-2.3.3-0ubuntu1~12.10.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"openjdk-7-jre", pkgver:"7u9-2.3.3-0ubuntu1~12.10.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"openjdk-7-jre-headless", pkgver:"7u9-2.3.3-0ubuntu1~12.10.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"openjdk-7-jre-lib", pkgver:"7u9-2.3.3-0ubuntu1~12.10.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"openjdk-7-jre-zero", pkgver:"7u9-2.3.3-0ubuntu1~12.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-6-jre-cacao / icedtea-6-jre-jamvm / icedtea-7-jre-cacao / etc");
}
