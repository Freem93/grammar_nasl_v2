#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3179-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96796);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/02/06 15:09:25 $");

  script_cve_id("CVE-2016-2183", "CVE-2016-5546", "CVE-2016-5547", "CVE-2016-5548", "CVE-2016-5549", "CVE-2016-5552", "CVE-2017-3231", "CVE-2017-3241", "CVE-2017-3252", "CVE-2017-3253", "CVE-2017-3261", "CVE-2017-3272", "CVE-2017-3289");
  script_osvdb_id(143387, 143388, 150415, 150416, 150417, 150419, 150420, 150421, 150422, 150423, 150425, 150426, 150427, 150428);
  script_xref(name:"USN", value:"3179-1");

  script_name(english:"Ubuntu 16.04 LTS / 16.10 : openjdk-8 vulnerabilities (USN-3179-1)");
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
"Karthik Bhargavan and Gaetan Leurent discovered that the DES and
Triple DES ciphers were vulnerable to birthday attacks. A remote
attacker could possibly use this flaw to obtain clear text data from
long encrypted sessions. This update moves those algorithms to the
legacy algorithm set and causes them to be used only if no non-legacy
algorithms can be negotiated. (CVE-2016-2183)

It was discovered that OpenJDK accepted ECSDA signatures using
non-canonical DER encoding. An attacker could use this to modify or
expose sensitive data. (CVE-2016-5546)

It was discovered that OpenJDK did not properly verify object
identifier (OID) length when reading Distinguished Encoding Rules
(DER) records, as used in x.509 certificates and elsewhere. An
attacker could use this to cause a denial of service (memory
consumption). (CVE-2016-5547)

It was discovered that covert timing channel vulnerabilities existed
in the DSA and ECDSA implementations in OpenJDK. A remote attacker
could use this to expose sensitive information. (CVE-2016-5548,
CVE-2016-5549)

It was discovered that the URLStreamHandler class in OpenJDK did not
properly parse user information from a URL. A remote attacker could
use this to expose sensitive information. (CVE-2016-5552)

It was discovered that the URLClassLoader class in OpenJDK did not
properly check access control context when downloading class files. A
remote attacker could use this to expose sensitive information.
(CVE-2017-3231)

It was discovered that the Remote Method Invocation (RMI)
implementation in OpenJDK performed deserialization of untrusted
inputs. A remote attacker could use this to execute arbitrary code.
(CVE-2017-3241)

It was discovered that the Java Authentication and Authorization
Service (JAAS) component of OpenJDK did not properly perform user
search LDAP queries. An attacker could use a specially constructed
LDAP entry to expose or modify sensitive information. (CVE-2017-3252)

It was discovered that the PNGImageReader class in OpenJDK did not
properly handle iTXt and zTXt chunks. An attacker could use this to
cause a denial of service (memory consumption). (CVE-2017-3253)

It was discovered that integer overflows existed in the
SocketInputStream and SocketOutputStream classes of OpenJDK. An
attacker could use this to expose sensitive information.
(CVE-2017-3261)

It was discovered that the atomic field updaters in the
java.util.concurrent.atomic package in OpenJDK did not properly
restrict access to protected field members. An attacker could use this
to specially craft a Java application or applet that could bypass Java
sandbox restrictions. (CVE-2017-3272)

It was discovered that a vulnerability existed in the class
construction implementation in OpenJDK. An attacker could use this to
specially craft a Java application or applet that could bypass Java
sandbox restrictions. (CVE-2017-3289).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-zero");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jdk", pkgver:"8u121-b13-0ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jdk-headless", pkgver:"8u121-b13-0ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre", pkgver:"8u121-b13-0ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-headless", pkgver:"8u121-b13-0ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-jamvm", pkgver:"8u121-b13-0ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-zero", pkgver:"8u121-b13-0ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jdk", pkgver:"8u121-b13-0ubuntu1.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jdk-headless", pkgver:"8u121-b13-0ubuntu1.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jre", pkgver:"8u121-b13-0ubuntu1.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jre-headless", pkgver:"8u121-b13-0ubuntu1.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jre-jamvm", pkgver:"8u121-b13-0ubuntu1.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jre-zero", pkgver:"8u121-b13-0ubuntu1.16.10.2")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
