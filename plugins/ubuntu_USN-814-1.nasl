#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-814-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40547);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-0217", "CVE-2009-1896", "CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676", "CVE-2009-2689", "CVE-2009-2690");
  script_bugtraq_id(35671, 35922, 35939, 35942, 35943, 35944, 35946, 35958);
  script_xref(name:"USN", value:"814-1");

  script_name(english:"Ubuntu 8.10 / 9.04 : openjdk-6 vulnerabilities (USN-814-1)");
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
"It was discovered that the XML HMAC signature system did not correctly
check certain lengths. If an attacker sent a truncated HMAC, it could
bypass authentication, leading to potential privilege escalation.
(CVE-2009-0217)

It was discovered that JAR bundles would appear signed if only one
element was signed. If a user were tricked into running a malicious
Java applet, a remote attacker could exploit this to gain access to
private information and potentially run untrusted code.
(CVE-2009-1896)

It was discovered that certain variables could leak information. If a
user were tricked into running a malicious Java applet, a remote
attacker could exploit this to gain access to private information and
potentially run untrusted code. (CVE-2009-2475, CVE-2009-2690)

A flaw was discovered the OpenType checking. If a user were tricked
into running a malicious Java applet, a remote attacker could bypass
access restrictions. (CVE-2009-2476)

It was discovered that the XML processor did not correctly check
recursion. If a user or automated system were tricked into processing
a specially crafted XML, the system could crash, leading to a denial
of service. (CVE-2009-2625)

It was discovered that the Java audio subsystem did not correctly
validate certain parameters. If a user were tricked into running an
untrusted applet, a remote attacker could read system properties.
(CVE-2009-2670)

Multiple flaws were discovered in the proxy subsystem. If a user were
tricked into running an untrusted applet, a remote attacker could
discover local user names, obtain access to sensitive information, or
bypass socket restrictions, leading to a loss of privacy.
(CVE-2009-2671, CVE-2009-2672, CVE-2009-2673)

Flaws were discovered in the handling of JPEG images, Unpack200
archives, and JDK13Services. If a user were tricked into running an
untrusted applet, a remote attacker could load a specially crafted
file that would bypass local file access protections and run arbitrary
code with user privileges. (CVE-2009-2674, CVE-2009-2675,
CVE-2009-2676, CVE-2009-2689).

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
  script_cwe_id(200, 264);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.10", pkgname:"icedtea6-plugin", pkgver:"6b12-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-dbg", pkgver:"6b12-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-demo", pkgver:"6b12-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-doc", pkgver:"6b12-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jdk", pkgver:"6b12-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre", pkgver:"6b12-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b12-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b12-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-source", pkgver:"6b12-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-source-files", pkgver:"6b12-0ubuntu6.5")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b14-1.4.1-0ubuntu11")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"icedtea6-plugin", pkgver:"6b14-1.4.1-0ubuntu11")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-dbg", pkgver:"6b14-1.4.1-0ubuntu11")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-demo", pkgver:"6b14-1.4.1-0ubuntu11")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-doc", pkgver:"6b14-1.4.1-0ubuntu11")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jdk", pkgver:"6b14-1.4.1-0ubuntu11")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre", pkgver:"6b14-1.4.1-0ubuntu11")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b14-1.4.1-0ubuntu11")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b14-1.4.1-0ubuntu11")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b14-1.4.1-0ubuntu11")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-source", pkgver:"6b14-1.4.1-0ubuntu11")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-source-files", pkgver:"6b14-1.4.1-0ubuntu11")) flag++;

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
