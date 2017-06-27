#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-859-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42817);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-2409", "CVE-2009-3728", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884", "CVE-2009-3885", "CVE-2010-0079");
  script_bugtraq_id(36881);
  script_osvdb_id(56752, 59705, 59706, 59707, 59708, 59709, 59710, 59714, 59915, 59916, 59917, 59918, 59919, 59920, 59921, 59922);
  script_xref(name:"USN", value:"859-1");

  script_name(english:"Ubuntu 8.10 / 9.04 / 9.10 : openjdk-6 vulnerabilities (USN-859-1)");
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
"Dan Kaminsky discovered that SSL certificates signed with MD2 could be
spoofed given enough time. As a result, an attacker could potentially
create a malicious trusted certificate to impersonate another site.
This update handles this issue by completely disabling MD2 for
certificate validation in OpenJDK. (CVE-2009-2409)

It was discovered that ICC profiles could be identified with '..'
pathnames. If a user were tricked into running a specially crafted
applet, a remote attacker could gain information about a local system.
(CVE-2009-3728)

Peter Vreugdenhil discovered multiple flaws in the processing of
graphics in the AWT library. If a user were tricked into running a
specially crafted applet, a remote attacker could crash the
application or run arbitrary code with user privileges.
(CVE-2009-3869, CVE-2009-3871)

Multiple flaws were discovered in JPEG and BMP image handling. If a
user were tricked into loading a specially crafted image, a remote
attacker could crash the application or run arbitrary code with user
privileges. (CVE-2009-3873, CVE-2009-3874, CVE-2009-3885)

Coda Hale discovered that HMAC-based signatures were not correctly
validated. Remote attackers could bypass certain forms of
authentication, granting unexpected access. (CVE-2009-3875)

Multiple flaws were discovered in ASN.1 parsing. A remote attacker
could send a specially crafted HTTP stream that would exhaust system
memory and lead to a denial of service. (CVE-2009-3876, CVE-2009-3877)

It was discovered that the graphics configuration subsystem did not
correctly handle arrays. If a user were tricked into running a
specially crafted applet, a remote attacker could exploit this to
crash the application or execute arbitrary code with user privileges.
(CVE-2009-3879)

It was discovered that loggers and Swing did not correctly handle
certain sensitive objects. If a user were tricked into running a
specially crafted applet, private information could be leaked to a
remote attacker, leading to a loss of privacy. (CVE-2009-3880,
CVE-2009-3882, CVE-2009-3883)

It was discovered that the ClassLoader did not correctly handle
certain options. If a user were tricked into running a specially
crafted applet, a remote attacker could execute arbitrary code with
user privileges. (CVE-2009-3881)

It was discovered that time zone file loading could be used to
determine the existence of files on the local system. If a user were
tricked into running a specially crafted applet, private information
could be leaked to a remote attacker, leading to a loss of privacy.
(CVE-2009-3884).

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
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(22, 119, 189, 200, 264, 310, 399);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/16");
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
if (! ereg(pattern:"^(8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.10", pkgname:"icedtea6-plugin", pkgver:"6b12-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-dbg", pkgver:"6b12-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-demo", pkgver:"6b12-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-doc", pkgver:"6b12-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jdk", pkgver:"6b12-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre", pkgver:"6b12-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b12-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b12-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-source", pkgver:"6b12-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-source-files", pkgver:"6b12-0ubuntu6.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b14-1.4.1-0ubuntu12")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"icedtea6-plugin", pkgver:"6b14-1.4.1-0ubuntu12")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-dbg", pkgver:"6b14-1.4.1-0ubuntu12")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-demo", pkgver:"6b14-1.4.1-0ubuntu12")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-doc", pkgver:"6b14-1.4.1-0ubuntu12")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jdk", pkgver:"6b14-1.4.1-0ubuntu12")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre", pkgver:"6b14-1.4.1-0ubuntu12")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b14-1.4.1-0ubuntu12")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b14-1.4.1-0ubuntu12")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b14-1.4.1-0ubuntu12")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-source", pkgver:"6b14-1.4.1-0ubuntu12")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-source-files", pkgver:"6b14-1.4.1-0ubuntu12")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"icedtea-6-jre-cacao", pkgver:"6b16-1.6.1-3ubuntu1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"icedtea6-plugin", pkgver:"6b16-1.6.1-3ubuntu1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-dbg", pkgver:"6b16-1.6.1-3ubuntu1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-demo", pkgver:"6b16-1.6.1-3ubuntu1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-doc", pkgver:"6b16-1.6.1-3ubuntu1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jdk", pkgver:"6b16-1.6.1-3ubuntu1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre", pkgver:"6b16-1.6.1-3ubuntu1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b16-1.6.1-3ubuntu1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b16-1.6.1-3ubuntu1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-zero", pkgver:"6b16-1.6.1-3ubuntu1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-source", pkgver:"6b16-1.6.1-3ubuntu1")) flag++;

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
