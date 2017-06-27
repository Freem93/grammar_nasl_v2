#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2706-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85265);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");
  script_osvdb_id(117855, 122331, 124489, 124617, 124618, 124619, 124621, 124622, 124625, 124628, 124629, 124631, 124636, 124639);
  script_xref(name:"USN", value:"2706-1");

  script_name(english:"Ubuntu 12.04 LTS : openjdk-6 vulnerabilities (USN-2706-1) (Bar Mitzvah) (Logjam)");
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
information disclosure, data integrity, and availability. An attacker
could exploit these to cause a denial of service or expose sensitive
data over the network. (CVE-2015-2590, CVE-2015-2628, CVE-2015-4731,
CVE-2015-4732, CVE-2015-4733, CVE-2015-4760, CVE-2015-4748)

Several vulnerabilities were discovered in the cryptographic
components of the OpenJDK JRE. An attacker could exploit these to
expose sensitive data over the network. (CVE-2015-2601, CVE-2015-2808,
CVE-2015-4000, CVE-2015-2625, CVE-2015-2613)

As a security improvement, this update modifies OpenJDK behavior to
disable RC4 TLS/SSL cipher suites by default.

As a security improvement, this update modifies OpenJDK behavior to
reject DH key sizes below 768 bits by default, preventing a possible
downgrade attack.

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit these to expose
sensitive data over the network. (CVE-2015-2621, CVE-2015-2632)

A vulnerability was discovered with how the JNDI component of the
OpenJDK JRE handles DNS resolutions. A remote attacker could exploit
this to cause a denial of service. (CVE-2015-4749).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-cacao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/06");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/07");
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
if (! ereg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b36-1.13.8-0ubuntu1~12.04")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"icedtea-6-jre-jamvm", pkgver:"6b36-1.13.8-0ubuntu1~12.04")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jdk", pkgver:"6b36-1.13.8-0ubuntu1~12.04")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre", pkgver:"6b36-1.13.8-0ubuntu1~12.04")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b36-1.13.8-0ubuntu1~12.04")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b36-1.13.8-0ubuntu1~12.04")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b36-1.13.8-0ubuntu1~12.04")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-source", pkgver:"6b36-1.13.8-0ubuntu1~12.04")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-6-jre-cacao / icedtea-6-jre-jamvm / openjdk-6-jdk / etc");
}
