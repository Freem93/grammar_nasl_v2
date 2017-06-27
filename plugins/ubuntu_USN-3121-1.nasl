#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3121-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94510);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5573", "CVE-2016-5582", "CVE-2016-5597");
  script_osvdb_id(145946, 145947, 145948, 145949, 145950);
  script_xref(name:"USN", value:"3121-1");

  script_name(english:"Ubuntu 16.04 LTS / 16.10 : openjdk-8 vulnerabilities (USN-3121-1)");
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
"It was discovered that the Hotspot component of OpenJDK did not
properly check arguments of the System.arraycopy() function in certain
cases. An attacker could use this to bypass Java sandbox restrictions.
(CVE-2016-5582)

It was discovered that OpenJDK did not restrict the set of algorithms
used for Jar integrity verification. An attacker could use this to
modify without detection the content of a JAR file, affecting system
integrity. (CVE-2016-5542)

It was discovered that the JMX component of OpenJDK did not
sufficiently perform classloader consistency checks. An attacker could
use this to bypass Java sandbox restrictions. (CVE-2016-5554)

It was discovered that the Hotspot component of OpenJDK did not
properly check received Java Debug Wire Protocol (JDWP) packets. An
attacker could use this to send debugging commands to a Java
application with debugging enabled. (CVE-2016-5573)

It was discovered that OpenJDK did not properly handle HTTP proxy
authentication. An attacker could use this to expose HTTPS server
authentication credentials. (CVE-2016-5597).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-zero");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jdk", pkgver:"8u111-b14-2ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jdk-headless", pkgver:"8u111-b14-2ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre", pkgver:"8u111-b14-2ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-headless", pkgver:"8u111-b14-2ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-jamvm", pkgver:"8u111-b14-2ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-zero", pkgver:"8u111-b14-2ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jdk", pkgver:"8u111-b14-2ubuntu0.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jdk-headless", pkgver:"8u111-b14-2ubuntu0.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jre", pkgver:"8u111-b14-2ubuntu0.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jre-headless", pkgver:"8u111-b14-2ubuntu0.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jre-jamvm", pkgver:"8u111-b14-2ubuntu0.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jre-zero", pkgver:"8u111-b14-2ubuntu0.16.10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjdk-8-jdk / openjdk-8-jdk-headless / openjdk-8-jre / etc");
}
