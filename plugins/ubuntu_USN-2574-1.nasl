#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2574-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82992);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/24 17:37:08 $");

  script_cve_id("CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488");
  script_osvdb_id(15435, 120703, 120709, 120710, 120712, 120713);
  script_xref(name:"USN", value:"2574-1");

  script_name(english:"Ubuntu 14.04 LTS / 14.10 : openjdk-7 vulnerabilities (USN-2574-1)");
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
data over the network. (CVE-2015-0460, CVE-2015-0469)

Alexander Cherepanov discovered that OpenJDK JRE was vulnerable to
directory traversal issues with respect to handling jar files. An
attacker could use this to expose sensitive data. (CVE-2015-0480)

Florian Weimer discovered that the RSA implementation in the JCE
component in OpenJDK JRE did not follow recommended practices for
implementing RSA signatures. An attacker could use this to expose
sensitive data. (CVE-2015-0478)

A vulnerability was discovered in the OpenJDK JRE related to data
integrity. An attacker could exploit this expose sensitive data over
the network. (CVE-2015-0477)

A vulnerability was discovered in the OpenJDK JRE related to
availability. An attacker could exploit these to cause a denial of
service. (CVE-2015-0488).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-7-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/11");
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

if (ubuntu_check(osver:"14.04", pkgname:"icedtea-7-jre-jamvm", pkgver:"7u79-2.5.5-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-demo", pkgver:"7u79-2.5.5-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-doc", pkgver:"7u79-2.5.5-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jdk", pkgver:"7u79-2.5.5-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jre", pkgver:"7u79-2.5.5-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jre-headless", pkgver:"7u79-2.5.5-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jre-lib", pkgver:"7u79-2.5.5-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jre-zero", pkgver:"7u79-2.5.5-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-source", pkgver:"7u79-2.5.5-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"icedtea-7-jre-jamvm", pkgver:"7u79-2.5.5-0ubuntu0.14.10.2")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"openjdk-7-demo", pkgver:"7u79-2.5.5-0ubuntu0.14.10.2")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"openjdk-7-doc", pkgver:"7u79-2.5.5-0ubuntu0.14.10.2")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"openjdk-7-jdk", pkgver:"7u79-2.5.5-0ubuntu0.14.10.2")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"openjdk-7-jre", pkgver:"7u79-2.5.5-0ubuntu0.14.10.2")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"openjdk-7-jre-headless", pkgver:"7u79-2.5.5-0ubuntu0.14.10.2")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"openjdk-7-jre-lib", pkgver:"7u79-2.5.5-0ubuntu0.14.10.2")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"openjdk-7-jre-zero", pkgver:"7u79-2.5.5-0ubuntu0.14.10.2")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"openjdk-7-source", pkgver:"7u79-2.5.5-0ubuntu0.14.10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-7-jre-jamvm / openjdk-7-demo / openjdk-7-doc / etc");
}
