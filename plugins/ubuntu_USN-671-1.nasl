#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-671-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37299);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-2079", "CVE-2008-3963", "CVE-2008-4097", "CVE-2008-4098");
  script_xref(name:"USN", value:"671-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS : mysql-dfsg-5.0 vulnerabilities (USN-671-1)");
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
"It was discovered that MySQL could be made to overwrite existing table
files in the data directory. An authenticated user could use the DATA
DIRECTORY and INDEX DIRECTORY options to possibly bypass privilege
checks. This update alters table creation behaviour by disallowing the
use of the MySQL data directory in DATA DIRECTORY and INDEX DIRECTORY
options. (CVE-2008-2079, CVE-2008-4097 and CVE-2008-4098)

It was discovered that MySQL did not handle empty bit-string literals
properly. An attacker could exploit this problem and cause the MySQL
server to crash, leading to a denial of service. (CVE-2008-3963).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_cwe_id(59, 134, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient15off");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libmysqlclient15-dev", pkgver:"5.0.22-0ubuntu6.06.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmysqlclient15off", pkgver:"5.0.22-0ubuntu6.06.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-client", pkgver:"5.0.22-0ubuntu6.06.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-client-5.0", pkgver:"5.0.22-0ubuntu6.06.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-common", pkgver:"5.0.22-0ubuntu6.06.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-server", pkgver:"5.0.22-0ubuntu6.06.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-server-5.0", pkgver:"5.0.22-0ubuntu6.06.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libmysqlclient15-dev", pkgver:"5.0.45-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libmysqlclient15off", pkgver:"5.0.45-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-client", pkgver:"5.0.45-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-client-5.0", pkgver:"5.0.45-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-common", pkgver:"5.0.45-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-server", pkgver:"5.0.45-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-server-5.0", pkgver:"5.0.45-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmysqlclient15-dev", pkgver:"5.0.51a-3ubuntu5.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmysqlclient15off", pkgver:"5.0.51a-3ubuntu5.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-client", pkgver:"5.0.51a-3ubuntu5.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-client-5.0", pkgver:"5.0.51a-3ubuntu5.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-common", pkgver:"5.0.51a-3ubuntu5.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-server", pkgver:"5.0.51a-3ubuntu5.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-server-5.0", pkgver:"5.0.51a-3ubuntu5.4")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient15-dev / libmysqlclient15off / mysql-client / etc");
}
