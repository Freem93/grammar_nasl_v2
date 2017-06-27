#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1079-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65100);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4465", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2010-4476", "CVE-2011-0706");
  script_bugtraq_id(46091, 46387, 46397, 46398, 46399, 46400, 46404, 46406, 46439);
  script_xref(name:"USN", value:"1079-3");

  script_name(english:"Ubuntu 10.10 : openjdk-6b18 vulnerabilities (USN-1079-3)");
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
"USN-1079-2 fixed vulnerabilities in OpenJDK 6 for armel (ARM)
architectures in Ubuntu 9.10 and Ubuntu 10.04 LTS. This update fixes
vulnerabilities in OpenJDK 6 for armel (ARM) architectures for Ubuntu
10.10.

It was discovered that untrusted Java applets could create domain name
resolution cache entries, allowing an attacker to manipulate name
resolution within the JVM. (CVE-2010-4448)

It was discovered that the Java launcher did not did not
properly setup the LD_LIBRARY_PATH environment variable. A
local attacker could exploit this to execute arbitrary code
as the user invoking the program. (CVE-2010-4450)

It was discovered that within the Swing library, forged
timer events could allow bypass of SecurityManager checks.
This could allow an attacker to access restricted resources.
(CVE-2010-4465)

It was discovered that certain bytecode combinations
confused memory management within the HotSpot JVM. This
could allow an attacker to cause a denial of service through
an application crash or possibly inject code.
(CVE-2010-4469)

It was discovered that the way JAXP components were handled
allowed them to be manipulated by untrusted applets. An
attacker could use this to bypass XML processing
restrictions and elevate privileges. (CVE-2010-4470)

It was discovered that the Java2D subcomponent, when
processing broken CFF fonts could leak system properties.
(CVE-2010-4471)

It was discovered that a flaw in the XML Digital Signature
component could allow an attacker to cause untrusted code to
replace the XML Digital Signature Transform or C14N
algorithm implementations. (CVE-2010-4472)

Konstantin Preisser and others discovered that specific
double literals were improperly handled, allowing a remote
attacker to cause a denial of service. (CVE-2010-4476)

It was discovered that the JNLPClassLoader class when
handling multiple signatures allowed remote attackers to
gain privileges due to the assignment of an inappropriate
security descriptor. (CVE-2011-0706).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected icedtea6-plugin, openjdk-6-jre and / or
openjdk-6-jre-headless packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea6-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-headless");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.10", pkgname:"icedtea6-plugin", pkgver:"6b18-1.8.7-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre", pkgver:"6b18-1.8.7-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b18-1.8.7-0ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea6-plugin / openjdk-6-jre / openjdk-6-jre-headless");
}
