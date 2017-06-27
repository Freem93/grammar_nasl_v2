#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3275-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100154);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/16 13:59:27 $");

  script_cve_id("CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544");
  script_osvdb_id(152319, 155831, 155832, 155833, 155835, 155836);
  script_xref(name:"USN", value:"3275-1");

  script_name(english:"Ubuntu 16.04 LTS / 16.10 / 17.04 : openjdk-8 vulnerabilities (USN-3275-1)");
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
"It was discovered that OpenJDK improperly re-used cached NTLM
connections in some situations. A remote attacker could possibly use
this to cause a Java application to perform actions with the
credentials of a different user. (CVE-2017-3509)

It was discovered that an untrusted library search path flaw existed
in the Java Cryptography Extension (JCE) component of OpenJDK. A local
attacker could possibly use this to gain the privileges of a Java
application. (CVE-2017-3511)

It was discovered that the Java API for XML Processing (JAXP)
component in OpenJDK did not properly enforce size limits when parsing
XML documents. An attacker could use this to cause a denial of service
(processor and memory consumption). (CVE-2017-3526)

It was discovered that the FTP client implementation in OpenJDK did
not properly sanitize user inputs. If a user was tricked into opening
a specially crafted FTP URL, a remote attacker could use this to
manipulate the FTP connection. (CVE-2017-3533)

It was discovered that OpenJDK allowed MD5 to be used as an algorithm
for JAR integrity verification. An attacker could possibly use this to
modify the contents of a JAR file without detection. (CVE-2017-3539)

It was discovered that the SMTP client implementation in OpenJDK did
not properly sanitize sender and recipient addresses. A remote
attacker could use this to specially craft email addresses and gain
control of a Java application's SMTP connections. (CVE-2017-3544).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-zero");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");
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
if (! ereg(pattern:"^(16\.04|16\.10|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 16.10 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre", pkgver:"8u131-b11-0ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-headless", pkgver:"8u131-b11-0ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-jamvm", pkgver:"8u131-b11-0ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-zero", pkgver:"8u131-b11-0ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jre", pkgver:"8u131-b11-0ubuntu1.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jre-headless", pkgver:"8u131-b11-0ubuntu1.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jre-jamvm", pkgver:"8u131-b11-0ubuntu1.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openjdk-8-jre-zero", pkgver:"8u131-b11-0ubuntu1.16.10.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"openjdk-8-jre", pkgver:"8u131-b11-0ubuntu1.17.04.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"openjdk-8-jre-headless", pkgver:"8u131-b11-0ubuntu1.17.04.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"openjdk-8-jre-zero", pkgver:"8u131-b11-0ubuntu1.17.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjdk-8-jre / openjdk-8-jre-headless / openjdk-8-jre-jamvm / etc");
}
