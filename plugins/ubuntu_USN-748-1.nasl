#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-748-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36366);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2006-2426", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1102");
  script_bugtraq_id(34240);
  script_osvdb_id(53164, 53165, 53166, 53170, 53171, 53173);
  script_xref(name:"USN", value:"748-1");

  script_name(english:"Ubuntu 8.10 : openjdk-6 vulnerabilities (USN-748-1)");
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
"It was discovered that font creation could leak temporary files. If a
user were tricked into loading a malicious program or applet, a remote
attacker could consume disk space, leading to a denial of service.
(CVE-2006-2426, CVE-2009-1100)

It was discovered that the lightweight HttpServer did not correctly
close files on dataless connections. A remote attacker could send
specially crafted requests, leading to a denial of service.
(CVE-2009-1101)

The Java Runtime Environment did not correctly validate certain
generated code. If a user were tricked into running a malicious applet
a remote attacker could execute arbitrary code. (CVE-2009-1102)

It was discovered that LDAP connections did not close correctly. A
remote attacker could send specially crafted requests, leading to a
denial of service. (CVE-2009-1093)

Java LDAP routines did not unserialize certain data correctly. A
remote attacker could send specially crafted requests that could lead
to arbitrary code execution. (CVE-2009-1094)

Java did not correctly check certain JAR headers. If a user or
automated system were tricked into processing a malicious JAR file, a
remote attacker could crash the application, leading to a denial of
service. (CVE-2009-1095, CVE-2009-1096)

It was discovered that PNG and GIF decoding in Java could lead to
memory corruption. If a user or automated system were tricked into
processing a specially crafted image, a remote attacker could crash
the application, leading to a denial of service. (CVE-2009-1097,
CVE-2009-1098).

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
  script_cwe_id(16, 94, 119, 189);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/26");
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

if (ubuntu_check(osver:"8.10", pkgname:"icedtea6-plugin", pkgver:"6b12-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-dbg", pkgver:"6b12-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-demo", pkgver:"6b12-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-doc", pkgver:"6b12-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jdk", pkgver:"6b12-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre", pkgver:"6b12-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b12-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b12-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-source", pkgver:"6b12-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openjdk-6-source-files", pkgver:"6b12-0ubuntu6.4")) flag++;

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
