#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1263-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57685);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/25 16:11:44 $");

  script_cve_id("CVE-2011-3377", "CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3558", "CVE-2011-3560");
  script_bugtraq_id(49778, 50211, 50215, 50216, 50218, 50224, 50231, 50234, 50236, 50242, 50243, 50246, 50248, 50610);
  script_xref(name:"USN", value:"1263-2");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 / 11.04 / 11.10 : openjdk-6, openjdk-6b18 regression (USN-1263-2) (BEAST)");
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
"USN-1263-1 fixed vulnerabilities in OpenJDK 6. The upstream patch for
the chosen plaintext attack on the block-wise AES encryption algorithm
(CVE-2011-3389) introduced a regression that caused TLS/SSL
connections to fail when using certain algorithms. This update fixes
the problem.

We apologize for the inconvenience.

Deepak Bhole discovered a flaw in the Same Origin Policy (SOP)
implementation in the IcedTea web browser plugin. This could allow a
remote attacker to open connections to certain hosts that should not
be permitted. (CVE-2011-3377)

Juliano Rizzo and Thai Duong discovered that the block-wise
AES encryption algorithm block-wise as used in TLS/SSL was
vulnerable to a chosen-plaintext attack. This could allow a
remote attacker to view confidential data. (CVE-2011-3389)

It was discovered that a type confusion flaw existed in the
in the Internet Inter-Orb Protocol (IIOP) deserialization
code. A remote attacker could use this to cause an untrusted
application or applet to execute arbitrary code by
deserializing malicious input. (CVE-2011-3521)

It was discovered that the Java scripting engine did not
perform SecurityManager checks. This could allow a remote
attacker to cause an untrusted application or applet to
execute arbitrary code with the full privileges of the JVM.
(CVE-2011-3544)

It was discovered that the InputStream class used a global
buffer to store input bytes skipped. An attacker could
possibly use this to gain access to sensitive information.
(CVE-2011-3547)

It was discovered that a vulnerability existed in the
AWTKeyStroke class. A remote attacker could cause an
untrusted application or applet to execute arbitrary code.
(CVE-2011-3548)

It was discovered that an integer overflow vulnerability
existed in the TransformHelper class in the Java2D
implementation. A remote attacker could use this cause a
denial of service via an application or applet crash or
possibly execute arbitrary code. (CVE-2011-3551)

It was discovered that the default number of available UDP
sockets for applications running under SecurityManager
restrictions was set too high. A remote attacker could use
this with a malicious application or applet exhaust the
number of available UDP sockets to cause a denial of service
for other applets or applications running within the same
JVM. (CVE-2011-3552)

It was discovered that Java API for XML Web Services
(JAX-WS) could incorrectly expose a stack trace. A remote
attacker could potentially use this to gain access to
sensitive information. (CVE-2011-3553)

It was discovered that the unpacker for pack200 JAR files
did not sufficiently check for errors. An attacker could
cause a denial of service or possibly execute arbitrary code
through a specially crafted pack200 JAR file.
(CVE-2011-3554)

It was discovered that the RMI registration implementation
did not properly restrict privileges of remotely executed
code. A remote attacker could use this to execute code with
elevated privileges. (CVE-2011-3556, CVE-2011-3557)

It was discovered that the HotSpot VM could be made to
crash, allowing an attacker to cause a denial of service or
possibly leak sensitive information. (CVE-2011-3558)

It was discovered that the HttpsURLConnection class did not
properly perform SecurityManager checks in certain
situations. This could allow a remote attacker to bypass
restrictions on HTTPS connections. (CVE-2011-3560).

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
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Rhino Script Engine Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-cacao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-6-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-zero");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/24");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/25");
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
if (! ereg(pattern:"^(10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b20-1.9.10-0ubuntu1~10.04.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre", pkgver:"6b20-1.9.10-0ubuntu1~10.04.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b20-1.9.10-0ubuntu1~10.04.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b20-1.9.10-0ubuntu1~10.04.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b20-1.9.10-0ubuntu1~10.04.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"icedtea-6-jre-cacao", pkgver:"6b20-1.9.10-0ubuntu1~10.10.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre", pkgver:"6b20-1.9.10-0ubuntu1~10.10.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b20-1.9.10-0ubuntu1~10.10.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b20-1.9.10-0ubuntu1~10.10.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre-zero", pkgver:"6b20-1.9.10-0ubuntu1~10.10.3")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b22-1.10.4-0ubuntu1~11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"icedtea-6-jre-jamvm", pkgver:"6b22-1.10.4-0ubuntu1~11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre", pkgver:"6b22-1.10.4-0ubuntu1~11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b22-1.10.4-0ubuntu1~11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b22-1.10.4-0ubuntu1~11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b22-1.10.4-0ubuntu1~11.04.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"icedtea-6-jre-cacao", pkgver:"6b23~pre11-0ubuntu1.11.10.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"icedtea-6-jre-jamvm", pkgver:"6b23~pre11-0ubuntu1.11.10.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre", pkgver:"6b23~pre11-0ubuntu1.11.10.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b23~pre11-0ubuntu1.11.10.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b23~pre11-0ubuntu1.11.10.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre-zero", pkgver:"6b23~pre11-0ubuntu1.11.10.1")) flag++;

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
