#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1010-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50410);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3551", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3557", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3564", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3573", "CVE-2010-3574");
  script_bugtraq_id(36935, 43963, 43979, 43985, 43988, 43992, 43994, 44009, 44011, 44012, 44013, 44014, 44016, 44017, 44027, 44028, 44032, 44035);
  script_osvdb_id(69032, 69033, 69034, 69038, 69039, 69040, 69041, 69042, 69044, 69045, 69049, 69052, 69053, 69055, 69057, 69058, 69059, 70072);
  script_xref(name:"USN", value:"1010-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : openjdk-6, openjdk-6b18 vulnerabilities (USN-1010-1)");
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
"Marsh Ray and Steve Dispensa discovered a flaw in the TLS and SSLv3
protocols. If an attacker could perform a man in the middle attack at
the start of a TLS connection, the attacker could inject arbitrary
content at the beginning of the user's session. USN-923-1 disabled
SSL/TLS renegotiation by default; this update implements the TLS
Renegotiation Indication Extension as defined in RFC 5746, and thus
supports secure renegotiation between updated clients and servers.
(CVE-2009-3555)

It was discovered that the HttpURLConnection class did not validate
request headers set by java applets, which could allow an attacker to
trigger actions otherwise not allowed to HTTP clients. (CVE-2010-3541)

It was discovered that JNDI could leak information that would allow an
attacker to to access information about otherwise-protected internal
network names. (CVE-2010-3548)

It was discovered that HttpURLConnection improperly handled the
'chunked' transfer encoding method, which could allow attackers to
conduct HTTP response splitting attacks. (CVE-2010-3549)

It was discovered that the NetworkInterface class improperly checked
the network 'connect' permissions for local network addresses. This
could allow an attacker to read local network addresses.
(CVE-2010-3551)

It was discovered that UIDefault.ProxyLazyValue had unsafe reflection
usage, allowing an attacker to create objects. (CVE-2010-3553)

It was discovered that multiple flaws in the CORBA reflection
implementation could allow an attacker to execute arbitrary code by
misusing permissions granted to certain system objects.
(CVE-2010-3554)

It was discovered that unspecified flaws in the Swing library could
allow untrusted applications to modify the behavior and state of
certain JDK classes. (CVE-2010-3557)

It was discovered that the privileged accept method of the
ServerSocket class in the CORBA implementation allowed it to receive
connections from any host, instead of just the host of the current
connection. An attacker could use this flaw to bypass restrictions
defined by network permissions. (CVE-2010-3561)

It was discovered that there exists a double free in java's
indexColorModel that could allow an attacker to cause an applet or
application to crash, or possibly execute arbitrary code with the
privilege of the user running the java applet or application.
(CVE-2010-3562)

It was discovered that the Kerberos implementation improperly checked
AP-REQ requests, which could allow an attacker to cause a denial of
service against the receiving JVM. (CVE-2010-3564)

It was discovered that improper checks of unspecified image metadata
in JPEGImageWriter.writeImage of the imageio API could allow an
attacker to execute arbitrary code with the privileges of the user
running a java applet or application. (CVE-2010-3565)

It was discovered that an unspecified vulnerability in the ICC profile
handling code could allow an attacker to execute arbitrary code with
the privileges of the user running a java applet or application.
(CVE-2010-3566)

It was discovered that a miscalculation in the OpenType font rendering
implementation would allow out-of-bounds memory access. This could
allow an attacker to execute arbitrary code with the privileges of the
user running a java application. (CVE-2010-3567)

It was discovered that an unspecified race condition in the way
objects were deserialized could allow an attacker to cause an applet
or application to misuse the privileges of the user running the java
applet or application. (CVE-2010-3568)

It was discovered that the defaultReadObject of the Serialization API
could be tricked into setting a volatile field multiple times. This
could allow an attacker to execute arbitrary code with the privileges
of the user running a java applet or application. (CVE-2010-3569)

It was discovered that the HttpURLConnection class did not validate
request headers set by java applets, which could allow an attacker to
trigger actions otherwise not allowed to HTTP clients. (CVE-2010-3573)

It was discovered that the HttpURLConnection class improperly checked
whether the calling code was granted the 'allowHttpTrace' permission,
allowing an attacker to create HTTP TRACE requests. (CVE-2010-3574).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-cacao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea6-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"icedtea6-plugin", pkgver:"6b18-1.8.2-4ubuntu1~8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-dbg", pkgver:"6b18-1.8.2-4ubuntu1~8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-demo", pkgver:"6b18-1.8.2-4ubuntu1~8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-doc", pkgver:"6b18-1.8.2-4ubuntu1~8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-jdk", pkgver:"6b18-1.8.2-4ubuntu1~8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-jre", pkgver:"6b18-1.8.2-4ubuntu1~8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b18-1.8.2-4ubuntu1~8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b18-1.8.2-4ubuntu1~8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-source", pkgver:"6b18-1.8.2-4ubuntu1~8.04.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"icedtea-6-jre-cacao", pkgver:"6b18-1.8.2-4ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"icedtea6-plugin", pkgver:"6b18-1.8.2-4ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-dbg", pkgver:"6b18-1.8.2-4ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-demo", pkgver:"6b18-1.8.2-4ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-doc", pkgver:"6b18-1.8.2-4ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jdk", pkgver:"6b18-1.8.2-4ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre", pkgver:"6b18-1.8.2-4ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b18-1.8.2-4ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b18-1.8.2-4ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-zero", pkgver:"6b18-1.8.2-4ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-source", pkgver:"6b18-1.8.2-4ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b18-1.8.2-4ubuntu2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"icedtea6-plugin", pkgver:"6b18-1.8.2-4ubuntu2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-dbg", pkgver:"6b18-1.8.2-4ubuntu2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-demo", pkgver:"6b18-1.8.2-4ubuntu2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-doc", pkgver:"6b18-1.8.2-4ubuntu2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jdk", pkgver:"6b18-1.8.2-4ubuntu2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre", pkgver:"6b18-1.8.2-4ubuntu2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b18-1.8.2-4ubuntu2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b18-1.8.2-4ubuntu2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b18-1.8.2-4ubuntu2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-source", pkgver:"6b18-1.8.2-4ubuntu2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"icedtea-6-jre-cacao", pkgver:"6b20-1.9.1-1ubuntu3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"icedtea6-plugin", pkgver:"6b18-1.8.2-4ubuntu1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-dbg", pkgver:"6b20-1.9.1-1ubuntu3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-demo", pkgver:"6b20-1.9.1-1ubuntu3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-doc", pkgver:"6b20-1.9.1-1ubuntu3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jdk", pkgver:"6b18-1.8.2-4ubuntu1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre", pkgver:"6b18-1.8.2-4ubuntu1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b18-1.8.2-4ubuntu1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b20-1.9.1-1ubuntu3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre-zero", pkgver:"6b20-1.9.1-1ubuntu3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-source", pkgver:"6b20-1.9.1-1ubuntu3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-6-jre-cacao / icedtea6-plugin / openjdk-6-dbg / etc");
}
