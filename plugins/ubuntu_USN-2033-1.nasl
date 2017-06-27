#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2033-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71037);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/25 16:34:54 $");

  script_cve_id("CVE-2013-3829", "CVE-2013-4002", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5809", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851");
  script_bugtraq_id(61310, 63082, 63089, 63095, 63098, 63101, 63102, 63103, 63106, 63110, 63115, 63118, 63120, 63121, 63128, 63133, 63134, 63135, 63137, 63142, 63143, 63146, 63148, 63149, 63150, 63153, 63154);
  script_osvdb_id(95418, 98524, 98525, 98526, 98531, 98532, 98535, 98544, 98546, 98548, 98549, 98550, 98551, 98552, 98558, 98559, 98560, 98562, 98564, 98565, 98566, 98567, 98568, 98569, 98571, 98572, 98573);
  script_xref(name:"USN", value:"2033-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS : openjdk-6 vulnerabilities (USN-2033-1)");
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
these to expose sensitive data over the network. (CVE-2013-3829,
CVE-2013-5783, CVE-2013-5804)

Several vulnerabilities were discovered in the OpenJDK JRE related to
availability. An attacker could exploit these to cause a denial of
service. (CVE-2013-4002, CVE-2013-5803, CVE-2013-5823, CVE-2013-5825)

Several vulnerabilities were discovered in the OpenJDK JRE related to
data integrity. (CVE-2013-5772, CVE-2013-5774, CVE-2013-5784,
CVE-2013-5797, CVE-2013-5820)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit these to expose
sensitive data over the network. (CVE-2013-5778, CVE-2013-5780,
CVE-2013-5790, CVE-2013-5840, CVE-2013-5849, CVE-2013-5851)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure, data integrity and availability. An attacker
could exploit these to cause a denial of service or expose sensitive
data over the network. (CVE-2013-5782, CVE-2013-5802, CVE-2013-5809,
CVE-2013-5829, CVE-2013-5814, CVE-2013-5817, CVE-2013-5830,
CVE-2013-5842, CVE-2013-5850).

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/22");
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
if (! ereg(pattern:"^(10\.04|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b27-1.12.6-1ubuntu0.10.04.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre", pkgver:"6b27-1.12.6-1ubuntu0.10.04.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b27-1.12.6-1ubuntu0.10.04.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b27-1.12.6-1ubuntu0.10.04.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b27-1.12.6-1ubuntu0.10.04.4")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b27-1.12.6-1ubuntu0.12.04.4")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"icedtea-6-jre-jamvm", pkgver:"6b27-1.12.6-1ubuntu0.12.04.4")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre", pkgver:"6b27-1.12.6-1ubuntu0.12.04.4")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b27-1.12.6-1ubuntu0.12.04.4")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b27-1.12.6-1ubuntu0.12.04.4")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b27-1.12.6-1ubuntu0.12.04.4")) flag++;

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
