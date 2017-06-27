#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-923-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45474);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/27 14:45:43 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085", "CVE-2010-0088", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0840", "CVE-2010-0845", "CVE-2010-0847", "CVE-2010-0848");
  script_bugtraq_id(36935, 39065, 39069, 39071, 39072, 39075, 39078, 39081, 39085, 39086, 39088, 39089, 39090, 39093, 39094, 39096);
  script_osvdb_id(63481, 63482, 63483, 63485, 63486, 63487, 63488, 63489, 63498, 63499, 63500, 63503, 63504, 63505);
  script_xref(name:"USN", value:"923-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 / 9.10 : openjdk-6 vulnerabilities (USN-923-1)");
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
content at the beginning of the user's session. (CVE-2009-3555)

It was discovered that Loader-constraint table, Policy/PolicyFile,
Inflater/Deflater, drag/drop access, and deserialization did not
correctly handle certain sensitive objects. If a user were tricked
into running a specially crafted applet, private information could be
leaked to a remote attacker, leading to a loss of privacy.
(CVE-2010-0082, CVE-2010-0084, CVE-2010-0085, CVE-2010-0088,
CVE-2010-0091, CVE-2010-0094)

It was discovered that AtomicReferenceArray, System.arraycopy,
InetAddress, and HashAttributeSet did not correctly handle certain
situations. If a remote attacker could trigger specific error
conditions, a Java application could crash, leading to a denial of
service. (CVE-2010-0092, CVE-2010-0093, CVE-2010-0095, CVE-2010-0845)

It was discovered that Pack200, CMM readMabCurveData, ImagingLib, and
the AWT library did not correctly check buffer lengths. If a user or
automated system were tricked into handling specially crafted JAR
files or images, a remote attacker could crash the Java application or
possibly gain user privileges (CVE-2010-0837, CVE-2010-0838,
CVE-2010-0847, CVE-2010-0848).

It was discovered that applets did not correctly handle certain trust
chains. If a user were tricked into running a specially crafted
applet, a remote attacker could possibly run untrusted code with user
privileges. (CVE-2010-0840).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Statement.invoke() Trusted Method Chain Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-source-files");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/09");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-dbg", pkgver:"6b11-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-demo", pkgver:"6b11-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-doc", pkgver:"6b11-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-jdk", pkgver:"6b11-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-jre", pkgver:"6b11-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b11-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b11-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openjdk-6-source", pkgver:"6b11-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"icedtea6-plugin", pkgver:"6b12-0ubuntu6.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-dbg", pkgver:"6b12-0ubuntu6.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-demo", pkgver:"6b12-0ubuntu6.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-doc", pkgver:"6b12-0ubuntu6.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jdk", pkgver:"6b12-0ubuntu6.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre", pkgver:"6b12-0ubuntu6.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b12-0ubuntu6.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b12-0ubuntu6.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-source", pkgver:"6b12-0ubuntu6.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-source-files", pkgver:"6b12-0ubuntu6.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b14-1.4.1-0ubuntu13")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"icedtea6-plugin", pkgver:"6b14-1.4.1-0ubuntu13")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-dbg", pkgver:"6b14-1.4.1-0ubuntu13")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-demo", pkgver:"6b14-1.4.1-0ubuntu13")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-doc", pkgver:"6b14-1.4.1-0ubuntu13")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jdk", pkgver:"6b14-1.4.1-0ubuntu13")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre", pkgver:"6b14-1.4.1-0ubuntu13")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b14-1.4.1-0ubuntu13")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b14-1.4.1-0ubuntu13")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b14-1.4.1-0ubuntu13")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-source", pkgver:"6b14-1.4.1-0ubuntu13")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-source-files", pkgver:"6b14-1.4.1-0ubuntu13")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"icedtea-6-jre-cacao", pkgver:"6b16-1.6.1-3ubuntu3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"icedtea6-plugin", pkgver:"6b16-1.6.1-3ubuntu3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-dbg", pkgver:"6b16-1.6.1-3ubuntu3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-demo", pkgver:"6b16-1.6.1-3ubuntu3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-doc", pkgver:"6b16-1.6.1-3ubuntu3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jdk", pkgver:"6b16-1.6.1-3ubuntu3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre", pkgver:"6b16-1.6.1-3ubuntu3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b16-1.6.1-3ubuntu3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b16-1.6.1-3ubuntu3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-zero", pkgver:"6b16-1.6.1-3ubuntu3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-source", pkgver:"6b16-1.6.1-3ubuntu3")) flag++;

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
