#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-950-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46855);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2010-1621", "CVE-2010-1626", "CVE-2010-1848", "CVE-2010-1849", "CVE-2010-1850");
  script_bugtraq_id(39543, 40100, 40106, 40109, 40257);
  script_xref(name:"USN", value:"950-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.04 / 9.10 / 10.04 LTS : mysql-dfsg-5.0, mysql-dfsg-5.1 vulnerabilities (USN-950-1)");
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
"It was discovered that MySQL did not check privileges before
uninstalling plugins. An authenticated user could uninstall arbitrary
plugins, bypassing intended restrictions. This issue only affected
Ubuntu 9.10 and 10.04 LTS. (CVE-2010-1621)

It was discovered that MySQL could be made to delete another user's
data and index files. An authenticated user could use symlinks
combined with the DROP TABLE command to possibly bypass privilege
checks. (CVE-2010-1626)

It was discovered that MySQL incorrectly validated the table name
argument of the COM_FIELD_LIST command. An authenticated user could
use a specially- crafted table name to bypass privilege checks and
possibly access other tables. (CVE-2010-1848)

Eric Day discovered that MySQL incorrectly handled certain network
packets. A remote attacker could exploit this flaw and cause the
server to consume all available resources, resulting in a denial of
service. (CVE-2010-1849)

It was discovered that MySQL performed incorrect bounds checking on
the table name argument of the COM_FIELD_LIST command. An
authenticated user could use a specially crafted table name to cause a
denial of service or possibly execute arbitrary code. The default
compiler options for affected releases should reduce the vulnerability
to a denial of service. (CVE-2010-1850).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient15off");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqld-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqld-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-core-5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-core-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-core-5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/10");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libmysqlclient15-dev", pkgver:"5.0.22-0ubuntu6.06.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmysqlclient15off", pkgver:"5.0.22-0ubuntu6.06.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-client", pkgver:"5.0.22-0ubuntu6.06.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-client-5.0", pkgver:"5.0.22-0ubuntu6.06.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-common", pkgver:"5.0.22-0ubuntu6.06.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-server", pkgver:"5.0.22-0ubuntu6.06.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-server-5.0", pkgver:"5.0.22-0ubuntu6.06.14")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmysqlclient15-dev", pkgver:"5.0.51a-3ubuntu5.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmysqlclient15off", pkgver:"5.0.51a-3ubuntu5.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-client", pkgver:"5.0.51a-3ubuntu5.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-client-5.0", pkgver:"5.0.51a-3ubuntu5.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-common", pkgver:"5.0.51a-3ubuntu5.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-server", pkgver:"5.0.51a-3ubuntu5.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-server-5.0", pkgver:"5.0.51a-3ubuntu5.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmysqlclient15-dev", pkgver:"5.1.30really5.0.75-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmysqlclient15off", pkgver:"5.1.30really5.0.75-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mysql-client", pkgver:"5.1.30really5.0.75-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mysql-client-5.0", pkgver:"5.1.30really5.0.75-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mysql-common", pkgver:"5.1.30really5.0.75-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mysql-server", pkgver:"5.1.30really5.0.75-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mysql-server-5.0", pkgver:"5.1.30really5.0.75-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mysql-server-core-5.0", pkgver:"5.1.30really5.0.75-0ubuntu10.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqlclient-dev", pkgver:"5.1.37-1ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqlclient16", pkgver:"5.1.37-1ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqlclient16-dev", pkgver:"5.1.37-1ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqld-dev", pkgver:"5.1.37-1ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqld-pic", pkgver:"5.1.37-1ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-client", pkgver:"5.1.37-1ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-client-5.1", pkgver:"5.1.37-1ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-common", pkgver:"5.1.37-1ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-server", pkgver:"5.1.37-1ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-server-5.1", pkgver:"5.1.37-1ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-server-core-5.1", pkgver:"5.1.37-1ubuntu5.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmysqlclient-dev", pkgver:"5.1.41-3ubuntu12.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmysqlclient16", pkgver:"5.1.41-3ubuntu12.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmysqlclient16-dev", pkgver:"5.1.41-3ubuntu12.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmysqld-dev", pkgver:"5.1.41-3ubuntu12.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmysqld-pic", pkgver:"5.1.41-3ubuntu12.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-client", pkgver:"5.1.41-3ubuntu12.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-client-5.1", pkgver:"5.1.41-3ubuntu12.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-client-core-5.1", pkgver:"5.1.41-3ubuntu12.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-common", pkgver:"5.1.41-3ubuntu12.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-server", pkgver:"5.1.41-3ubuntu12.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-server-5.1", pkgver:"5.1.41-3ubuntu12.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-server-core-5.1", pkgver:"5.1.41-3ubuntu12.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-testsuite", pkgver:"5.1.41-3ubuntu12.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient-dev / libmysqlclient15-dev / libmysqlclient15off / etc");
}
