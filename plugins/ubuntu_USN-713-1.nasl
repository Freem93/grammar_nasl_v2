#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-713-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37381);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360");
  script_bugtraq_id(32608);
  script_xref(name:"USN", value:"713-1");

  script_name(english:"Ubuntu 8.10 : OpenJDK vulnerabilities (USN-713-1)");
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
"It was discovered that Java did not correctly handle untrusted
applets. If a user were tricked into running a malicious applet, a
remote attacker could gain user privileges, or list directory
contents. (CVE-2008-5347, CVE-2008-5350)

It was discovered that Kerberos authentication and RSA public key
processing were not correctly handled in Java. A remote attacker could
exploit these flaws to cause a denial of service. (CVE-2008-5348,
CVE-2008-5349)

It was discovered that Java accepted UTF-8 encodings that might be
handled incorrectly by certain applications. A remote attacker could
bypass string filters, possible leading to other exploits.
(CVE-2008-5351)

Overflows were discovered in Java JAR processing. If a user or
automated system were tricked into processing a malicious JAR file, a
remote attacker could crash the application, leading to a denial of
service. (CVE-2008-5352, CVE-2008-5354)

It was discovered that Java calendar objects were not unserialized
safely. If a user or automated system were tricked into processing a
specially crafted calendar object, a remote attacker could execute
arbitrary code with user privileges. (CVE-2008-5353)

It was discovered that the Java image handling code could lead to
memory corruption. If a user or automated system were tricked into
processing a specially crafted image, a remote attacker could crash
the application, leading to a denial of service. (CVE-2008-5358,
CVE-2008-5359)

It was discovered that temporary files created by Java had predictable
names. If a user or automated system were tricked into processing a
specially crafted JAR file, a remote attacker could overwrite
sensitive information. (CVE-2008-5360).

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
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Calendar Deserialization Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea6-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-6-source-files");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! ereg(pattern:"^(8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.10", pkgname:"icedtea6-plugin", pkgver:"6b12-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-dbg", pkgver:"6b12-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-demo", pkgver:"6b12-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-doc", pkgver:"6b12-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jdk", pkgver:"6b12-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre", pkgver:"6b12-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b12-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b12-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-source", pkgver:"6b12-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-source-files", pkgver:"6b12-0ubuntu6.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea6-plugin / openjdk-6-dbg / openjdk-6-demo / openjdk-6-doc / etc");
}
