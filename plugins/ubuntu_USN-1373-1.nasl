#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1373-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58130);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/25 16:11:45 $");

  script_cve_id("CVE-2011-3563", "CVE-2011-5035", "CVE-2012-0497", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506", "CVE-2012-0507");
  script_osvdb_id(78114, 78413, 79228, 79229, 79230, 79232, 79233, 79235, 79236);
  script_xref(name:"USN", value:"1373-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 / 11.04 / 11.10 : openjdk-6 vulnerabilities (USN-1373-1)");
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
"It was discovered that the Java HttpServer class did not limit the
number of headers read from a HTTP request. A remote attacker could
cause a denial of service by sending special requests that trigger
hash collisions predictably. (CVE-2011-5035)

ATTENTION: this update changes previous Java HttpServer class behavior
by limiting the number of request headers to 200. This may be
increased by adjusting the sun.net.httpserver.maxReqHeaders property.

It was discovered that the Java Sound component did not properly check
buffer boundaries. A remote attacker could use this to cause a denial
of service or view confidential data. (CVE-2011-3563)

It was discovered that the Java2D implementation does not properly
check graphics rendering objects before passing them to the native
renderer. A remote attacker could use this to cause a denial of
service or to bypass Java sandbox restrictions. (CVE-2012-0497)

It was discovered that an off-by-one error exists in the Java ZIP file
processing code. An attacker could us this to cause a denial of
service through a maliciously crafted ZIP file. (CVE-2012-0501)

It was discovered that the Java AWT KeyboardFocusManager did not
properly enforce keyboard focus security policy. A remote attacker
could use this with an untrusted application or applet to grab
keyboard focus and possibly expose confidential data. (CVE-2012-0502)

It was discovered that the Java TimeZone class did not properly
enforce security policy around setting the default time zone. A remote
attacker could use this with an untrusted application or applet to set
a new default time zone and bypass Java sandbox restrictions.
(CVE-2012-0503)

It was discovered the Java ObjectStreamClass did not throw an
accurately identifiable exception when a deserialization failure
occurred. A remote attacker could use this with an untrusted
application or applet to bypass Java sandbox restrictions.
(CVE-2012-0505)

It was discovered that the Java CORBA implementation did not properly
protect repository identifiers on certain CORBA objects. A remote
attacker could use this to corrupt object data. (CVE-2012-0506)

It was discovered that the Java AtomicReferenceArray class
implementation did not properly check if an array was of the expected
Object[] type. A remote attacker could use this with a malicious
application or applet to bypass Java sandbox restrictions.
(CVE-2012-0507).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java AtomicReferenceArray Type Violation Vulnerability');
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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/27");
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

if (ubuntu_check(osver:"10.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b20-1.9.13-0ubuntu1~10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre", pkgver:"6b20-1.9.13-0ubuntu1~10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b20-1.9.13-0ubuntu1~10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b20-1.9.13-0ubuntu1~10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b20-1.9.13-0ubuntu1~10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"icedtea-6-jre-cacao", pkgver:"6b20-1.9.13-0ubuntu1~10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre", pkgver:"6b20-1.9.13-0ubuntu1~10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b20-1.9.13-0ubuntu1~10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b20-1.9.13-0ubuntu1~10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre-zero", pkgver:"6b20-1.9.13-0ubuntu1~10.10.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b22-1.10.6-0ubuntu1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"icedtea-6-jre-jamvm", pkgver:"6b22-1.10.6-0ubuntu1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre", pkgver:"6b22-1.10.6-0ubuntu1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b22-1.10.6-0ubuntu1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b22-1.10.6-0ubuntu1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b22-1.10.6-0ubuntu1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"icedtea-6-jre-cacao", pkgver:"6b23~pre11-0ubuntu1.11.10.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"icedtea-6-jre-jamvm", pkgver:"6b23~pre11-0ubuntu1.11.10.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre", pkgver:"6b23~pre11-0ubuntu1.11.10.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b23~pre11-0ubuntu1.11.10.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b23~pre11-0ubuntu1.11.10.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"openjdk-6-jre-zero", pkgver:"6b23~pre11-0ubuntu1.11.10.2")) flag++;

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
