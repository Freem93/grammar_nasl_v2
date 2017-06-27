#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2124-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73398);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/24 17:29:02 $");

  script_cve_id("CVE-2013-5878", "CVE-2013-5884", "CVE-2013-5896", "CVE-2013-5907", "CVE-2013-5910", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0376", "CVE-2014-0411", "CVE-2014-0416", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0428");
  script_xref(name:"USN", value:"2124-2");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS : openjdk-6 regression (USN-2124-2)");
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
"USN-2124-1 fixed vulnerabilities in OpenJDK 6. Due to an upstream
regression, memory was not properly zeroed under certain circumstances
which could lead to instability. This update fixes the problem.

We apologize for the inconvenience.

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit
this to expose sensitive data over the network. (CVE-2014-0411)

Several vulnerabilities were discovered in the OpenJDK JRE
related to information disclosure, data integrity and
availability. An attacker could exploit these to cause a
denial of service or expose sensitive data over the network.
(CVE-2013-5878, CVE-2013-5907, CVE-2014-0373, CVE-2014-0422,
CVE-2014-0428)

Two vulnerabilities were discovered in the OpenJDK JRE
related to information disclosure. An attacker could exploit
these to expose sensitive data over the network.
(CVE-2013-5884, CVE-2014-0368)

Two vulnerabilities were discovered in the OpenJDK JRE
related to availability. An attacker could exploit these to
cause a denial of service. (CVE-2013-5896, CVE-2013-5910)

Two vulnerabilities were discovered in the OpenJDK JRE
related to data integrity. (CVE-2014-0376, CVE-2014-0416)

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure and availability. An attacker could
exploit this to expose sensitive data over the network or
cause a denial of service. (CVE-2014-0423)

In addition to the above, USN-2033-1 fixed several
vulnerabilities and bugs in OpenJDK 6. This update
introduced a regression which caused an exception condition
in javax.xml when instantiating encryption algorithms. This
update fixes the problem. We apologize for the
inconvenience.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-cacao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-zero");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");
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

if (ubuntu_check(osver:"10.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b30-1.13.1-1ubuntu2~0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre", pkgver:"6b30-1.13.1-1ubuntu2~0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b30-1.13.1-1ubuntu2~0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b30-1.13.1-1ubuntu2~0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b30-1.13.1-1ubuntu2~0.10.04.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b30-1.13.1-1ubuntu2~0.12.04.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"icedtea-6-jre-jamvm", pkgver:"6b30-1.13.1-1ubuntu2~0.12.04.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre", pkgver:"6b30-1.13.1-1ubuntu2~0.12.04.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b30-1.13.1-1ubuntu2~0.12.04.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b30-1.13.1-1ubuntu2~0.12.04.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b30-1.13.1-1ubuntu2~0.12.04.3")) flag++;

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
