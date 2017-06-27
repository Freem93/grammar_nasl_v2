#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1154-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55172);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/26 16:14:08 $");

  script_cve_id("CVE-2011-0815", "CVE-2011-0822", "CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0870", "CVE-2011-0871", "CVE-2011-0872");
  script_bugtraq_id(48137, 48139, 48140, 48142, 48144, 48146, 48147);
  script_xref(name:"USN", value:"1154-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 / 11.04 : openjdk-6, openjdk-6b18 vulnerabilities (USN-1154-1)");
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
"It was discovered that a heap overflow in the AWT FileDialog.show()
method could allow an attacker to cause a denial of service through an
application crash or possibly execute arbitrary code. (CVE-2011-0815)

It was dicovered that integer overflows in the JPEGImageReader
readImage() function and the SunLayoutEngine nativeLayout() function
could allow an attacker to cause a denial of service through an
application crash or possibly execute arbitrary code. (CVE-2011-0822,
CVE-2011-0862)

It was discovered that memory corruption could occur when interpreting
bytecode in the HotSpot VM. This could allow an attacker to cause a
denial of service through an application crash or possibly execute
arbitrary code. (CVE-2011-0864)

It was discovered that the deserialization code allowed the creation
of mutable SignedObjects. This could allow an attacker to possibly
execute code with elevated privileges. (CVE-2011-0865)

It was discovered that the toString method in the NetworkInterface
class would reveal multiple addresses if they were bound to the
interface. This could give an attacker more information about the
networking environment. (CVE-2011-0867)

It was discovered that the Java 2D code to transform an image with a
scale close to 0 could trigger an integer overflow. This could allow
an attacker to cause a denial of service through an application crash
or possibly execute arbitrary code. (CVE-2011-0868)

It was discovered that the SOAP with Attachments API for Java (SAAJ)
implementation allowed the modification of proxy settings via
unprivileged SOAP messages. (CVE-2011-0869, CVE-2011-0870)

It was the discovered that the Swing ImageIcon class created
MediaTracker objects that potentially leaked privileged
ApplicationContexts. This could possibly allow an attacker access to
restricted resources or services. (CVE-2011-0871)

It was discovered that non-blocking sockets marked as not urgent could
still get selected for read operations. This could allow an attacker
to cause a denial of service. (CVE-2011-0872).

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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea6-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|10\.10|11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10 / 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"icedtea6-plugin", pkgver:"6b20-1.9.8-0ubuntu1~10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre", pkgver:"6b20-1.9.8-0ubuntu1~10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b20-1.9.8-0ubuntu1~10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b20-1.9.8-0ubuntu1~10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"icedtea6-plugin", pkgver:"6b20-1.9.8-0ubuntu1~10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre", pkgver:"6b20-1.9.8-0ubuntu1~10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b20-1.9.8-0ubuntu1~10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b20-1.9.8-0ubuntu1~10.10.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre", pkgver:"6b22-1.10.2-0ubuntu1~11.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b22-1.10.2-0ubuntu1~11.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b22-1.10.2-0ubuntu1~11.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea6-plugin / openjdk-6-jre / openjdk-6-jre-headless / etc");
}
