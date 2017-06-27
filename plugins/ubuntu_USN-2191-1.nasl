#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2191-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73822);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/24 17:29:03 $");

  script_cve_id("CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-0462", "CVE-2014-1876", "CVE-2014-2397", "CVE-2014-2398", "CVE-2014-2403", "CVE-2014-2405", "CVE-2014-2412", "CVE-2014-2414", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427");
  script_bugtraq_id(65568, 66856, 66866, 66873, 66877, 66879, 66881, 66883, 66887, 66891, 66893, 66894, 66902, 66903, 66909, 66910, 66914, 66916, 66918, 66920, 67508, 67512);
  script_xref(name:"USN", value:"2191-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS : openjdk-6 vulnerabilities (USN-2191-1)");
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
information disclosure, data integrity and availability. An attacker
could exploit these to cause a denial of service or expose sensitive
data over the network. (CVE-2014-0429, CVE-2014-0446, CVE-2014-0451,
CVE-2014-0452, CVE-2014-0456, CVE-2014-0457, CVE-2014-0458,
CVE-2014-0461, CVE-2014-0462, CVE-2014-2397, CVE-2014-2405,
CVE-2014-2412, CVE-2014-2414, CVE-2014-2421, CVE-2014-2423,
CVE-2014-2427)

Two vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit
these to expose sensitive data over the network. (CVE-2014-0453,
CVE-2014-0460)

A vulnerability was discovered in the OpenJDK JRE related to
availability. An attacker could exploit this to cause a denial of
service. (CVE-2014-0459)

Jakub Wilk discovered that the OpenJDK JRE incorrectly handled
temporary files. A local attacker could possibly use this issue to
overwrite arbitrary files. In the default installation of Ubuntu, this
should be prevented by the Yama link restrictions. (CVE-2014-1876)

A vulnerability was discovered in the OpenJDK JRE related to data
integrity. (CVE-2014-2398)

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit this to expose
sensitive data over the network. (CVE-2014-2403).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-cacao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-zero");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b31-1.13.3-1ubuntu1~0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre", pkgver:"6b31-1.13.3-1ubuntu1~0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b31-1.13.3-1ubuntu1~0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b31-1.13.3-1ubuntu1~0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b31-1.13.3-1ubuntu1~0.10.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b31-1.13.3-1ubuntu1~0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"icedtea-6-jre-jamvm", pkgver:"6b31-1.13.3-1ubuntu1~0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre", pkgver:"6b31-1.13.3-1ubuntu1~0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b31-1.13.3-1ubuntu1~0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b31-1.13.3-1ubuntu1~0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b31-1.13.3-1ubuntu1~0.12.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-6-jre-cacao / icedtea-6-jre-jamvm / openjdk-6-jre / etc");
}
