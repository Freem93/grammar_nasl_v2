#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1724-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64639);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/25 16:27:04 $");

  script_cve_id("CVE-2012-1541", "CVE-2012-3213", "CVE-2012-3342", "CVE-2013-0351", "CVE-2013-0409", "CVE-2013-0419", "CVE-2013-0423", "CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427", "CVE-2013-0428", "CVE-2013-0429", "CVE-2013-0430", "CVE-2013-0432", "CVE-2013-0433", "CVE-2013-0434", "CVE-2013-0435", "CVE-2013-0438", "CVE-2013-0440", "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-0444", "CVE-2013-0445", "CVE-2013-0446", "CVE-2013-0448", "CVE-2013-0449", "CVE-2013-0450", "CVE-2013-1473", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480", "CVE-2013-1481");
  script_bugtraq_id(57686, 57687, 57689, 57691, 57692, 57694, 57696, 57697, 57699, 57700, 57701, 57702, 57703, 57704, 57708, 57710, 57712, 57713, 57714, 57716, 57717, 57718, 57719, 57720, 57722, 57723, 57727, 57728, 57729, 57730, 57731);
  script_osvdb_id(89758, 89759, 89760, 89761, 89762, 89763, 89764, 89765, 89766, 89767, 89769, 89771, 89772, 89773, 89774, 89785, 89786, 89787, 89788, 89790, 89791, 89792, 89793, 89794, 89795, 89796, 89797, 89798, 89799, 89800, 89801, 89802, 89803, 89804, 89806);
  script_xref(name:"USN", value:"1724-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.10 / 12.04 LTS / 12.10 : openjdk-6, openjdk-7 vulnerabilities (USN-1724-1)");
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
"Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit
these to cause a denial of service. (CVE-2012-1541, CVE-2012-3342,
CVE-2013-0351, CVE-2013-0419, CVE-2013-0423, CVE-2013-0446,
CVE-2012-3213, CVE-2013-0425, CVE-2013-0426, CVE-2013-0428,
CVE-2013-0429, CVE-2013-0430, CVE-2013-0441, CVE-2013-0442,
CVE-2013-0445, CVE-2013-0450, CVE-2013-1475, CVE-2013-1476,
CVE-2013-1478, CVE-2013-1480)

Vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure. (CVE-2013-0409, CVE-2013-0434, CVE-2013-0438)

Several data integrity vulnerabilities were discovered in the OpenJDK
JRE. (CVE-2013-0424, CVE-2013-0427, CVE-2013-0433, CVE-2013-1473)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. (CVE-2013-0432,
CVE-2013-0435, CVE-2013-0443)

A vulnerability was discovered in the OpenJDK JRE related to
availability. An attacker could exploit this to cause a denial of
service. (CVE-2013-0440)

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit
this to cause a denial of service. This issue only affected Ubuntu
12.10. (CVE-2013-0444)

A data integrity vulnerability was discovered in the OpenJDK JRE. This
issue only affected Ubuntu 12.10. (CVE-2013-0448)

An information disclosure vulnerability was discovered in the OpenJDK
JRE. This issue only affected Ubuntu 12.10. (CVE-2013-0449)

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit
this to cause a denial of service. This issue did not affect Ubuntu
12.10. (CVE-2013-1481).

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
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-cacao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-jamvm");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|11\.10|12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.10 / 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b27-1.12.1-2ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre", pkgver:"6b27-1.12.1-2ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b27-1.12.1-2ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b27-1.12.1-2ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b27-1.12.1-2ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"icedtea-6-jre-cacao", pkgver:"6b27-1.12.1-2ubuntu0.11.10.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"icedtea-6-jre-jamvm", pkgver:"6b27-1.12.1-2ubuntu0.11.10.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre", pkgver:"6b27-1.12.1-2ubuntu0.11.10.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b27-1.12.1-2ubuntu0.11.10.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b27-1.12.1-2ubuntu0.11.10.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre-zero", pkgver:"6b27-1.12.1-2ubuntu0.11.10.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b27-1.12.1-2ubuntu0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"icedtea-6-jre-jamvm", pkgver:"6b27-1.12.1-2ubuntu0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre", pkgver:"6b27-1.12.1-2ubuntu0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b27-1.12.1-2ubuntu0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b27-1.12.1-2ubuntu0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b27-1.12.1-2ubuntu0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"icedtea-7-jre-jamvm", pkgver:"7u13-2.3.6-0ubuntu0.12.10.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"openjdk-7-jre", pkgver:"7u13-2.3.6-0ubuntu0.12.10.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"openjdk-7-jre-headless", pkgver:"7u13-2.3.6-0ubuntu0.12.10.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"openjdk-7-jre-lib", pkgver:"7u13-2.3.6-0ubuntu0.12.10.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"openjdk-7-jre-zero", pkgver:"7u13-2.3.6-0ubuntu0.12.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-6-jre-cacao / icedtea-6-jre-jamvm / icedtea-7-jre-jamvm / etc");
}
