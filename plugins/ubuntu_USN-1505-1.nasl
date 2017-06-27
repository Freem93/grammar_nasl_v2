#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1505-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59964);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/25 16:19:24 $");

  script_cve_id("CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725");
  script_bugtraq_id(53946, 53947, 53949, 53950, 53951, 53952, 53954, 53958, 53960);
  script_osvdb_id(82874, 82877, 82878, 82879, 82880, 82882, 82883, 82884, 82886);
  script_xref(name:"USN", value:"1505-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : icedtea-web, openjdk-6 vulnerabilities (USN-1505-1)");
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
"It was discovered that multiple flaws existed in the CORBA (Common
Object Request Broker Architecture) implementation in OpenJDK. An
attacker could create a Java application or applet that used these
flaws to bypass Java sandbox restrictions or modify immutable object
data. (CVE-2012-1711, CVE-2012-1719)

It was discovered that multiple flaws existed in the OpenJDK font
manager's layout lookup implementation. A attacker could specially
craft a font file that could cause a denial of service through
crashing the JVM (Java Virtual Machine) or possibly execute arbitrary
code. (CVE-2012-1713)

It was discovered that the SynthLookAndFeel class from Swing in
OpenJDK did not properly prevent access to certain UI elements from
outside the current application context. An attacker could create a
Java application or applet that used this flaw to cause a denial of
service through crashing the JVM or bypass Java sandbox restrictions.
(CVE-2012-1716)

It was discovered that OpenJDK runtime library classes could create
temporary files with insecure permissions. A local attacker could use
this to gain access to sensitive information. (CVE-2012-1717)

It was discovered that OpenJDK did not handle CRLs (Certificate
Revocation Lists) properly. A remote attacker could use this to gain
access to sensitive information. (CVE-2012-1718)

It was discovered that the OpenJDK HotSpot Virtual Machine did not
properly verify the bytecode of the class to be executed. A remote
attacker could create a Java application or applet that used this to
cause a denial of service through crashing the JVM or bypass Java
sandbox restrictions. (CVE-2012-1723, CVE-2012-1725)

It was discovered that the OpenJDK XML (Extensible Markup Language)
parser did not properly handle some XML documents. An attacker could
create an XML document that caused a denial of service in a Java
application or applet parsing the document. (CVE-2012-1724)

As part of this update, the IcedTea web browser applet plugin was
updated for Ubuntu 10.04 LTS, Ubuntu 11.04, and Ubuntu 11.10.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icedtea-6-plugin and / or openjdk-6-jre packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/13");
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
if (! ereg(pattern:"^(10\.04|11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"icedtea-6-plugin", pkgver:"1.2-2ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre", pkgver:"6b24-1.11.3-1ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"icedtea-6-plugin", pkgver:"1.2-2ubuntu0.11.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre", pkgver:"6b24-1.11.3-1ubuntu0.11.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"icedtea-6-plugin", pkgver:"1.2-2ubuntu0.11.10.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre", pkgver:"6b24-1.11.3-1ubuntu0.11.10.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"openjdk-6-jre", pkgver:"6b24-1.11.3-1ubuntu0.12.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-6-plugin / openjdk-6-jre");
}
