#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-971-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48349);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2010-2548", "CVE-2010-2783");
  script_osvdb_id(75193, 75194);
  script_xref(name:"USN", value:"971-1");

  script_name(english:"Ubuntu 9.04 / 9.10 / 10.04 LTS : openjdk-6 vulnerabilities (USN-971-1)");
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
"It was discovered that the IcedTea plugin did not correctly check
certain accesses. If a user or automated system were tricked into
running a specially crafted Java applet, a remote attacker could read
arbitrary files with user privileges, leading to a loss of privacy.
(CVE-2010-2548, CVE-2010-2783).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/17");
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
if (! ereg(pattern:"^(9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b18-1.8.1-0ubuntu1~9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"icedtea6-plugin", pkgver:"6b18-1.8.1-0ubuntu1~9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-dbg", pkgver:"6b18-1.8.1-0ubuntu1~9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-demo", pkgver:"6b18-1.8.1-0ubuntu1~9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-doc", pkgver:"6b18-1.8.1-0ubuntu1~9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jdk", pkgver:"6b18-1.8.1-0ubuntu1~9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre", pkgver:"6b18-1.8.1-0ubuntu1~9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b18-1.8.1-0ubuntu1~9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b18-1.8.1-0ubuntu1~9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b18-1.8.1-0ubuntu1~9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openjdk-6-source", pkgver:"6b18-1.8.1-0ubuntu1~9.04.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"icedtea-6-jre-cacao", pkgver:"6b18-1.8.1-0ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"icedtea6-plugin", pkgver:"6b18-1.8.1-0ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-dbg", pkgver:"6b18-1.8.1-0ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-demo", pkgver:"6b18-1.8.1-0ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-doc", pkgver:"6b18-1.8.1-0ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jdk", pkgver:"6b18-1.8.1-0ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre", pkgver:"6b18-1.8.1-0ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-headless", pkgver:"6b18-1.8.1-0ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-lib", pkgver:"6b18-1.8.1-0ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-jre-zero", pkgver:"6b18-1.8.1-0ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openjdk-6-source", pkgver:"6b18-1.8.1-0ubuntu1~9.10.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"icedtea-6-jre-cacao", pkgver:"6b18-1.8.1-0ubuntu1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"icedtea6-plugin", pkgver:"6b18-1.8.1-0ubuntu1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-dbg", pkgver:"6b18-1.8.1-0ubuntu1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-demo", pkgver:"6b18-1.8.1-0ubuntu1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-doc", pkgver:"6b18-1.8.1-0ubuntu1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jdk", pkgver:"6b18-1.8.1-0ubuntu1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre", pkgver:"6b18-1.8.1-0ubuntu1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-headless", pkgver:"6b18-1.8.1-0ubuntu1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-lib", pkgver:"6b18-1.8.1-0ubuntu1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-jre-zero", pkgver:"6b18-1.8.1-0ubuntu1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openjdk-6-source", pkgver:"6b18-1.8.1-0ubuntu1")) flag++;

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
