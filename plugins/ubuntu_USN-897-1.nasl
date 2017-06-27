#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-897-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44585);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2008-4098", "CVE-2008-4456", "CVE-2008-7247", "CVE-2009-2446", "CVE-2009-4019", "CVE-2009-4030", "CVE-2009-4484");
  script_bugtraq_id(29106, 31486, 35609, 37075, 37297, 37640, 37943, 38043);
  script_xref(name:"USN", value:"897-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 / 9.10 : mysql-dfsg-5.0, mysql-dfsg-5.1 vulnerabilities (USN-897-1)");
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
options. This issue only affected Ubuntu 8.10. (CVE-2008-4098) 

It was discovered that MySQL contained a cross-site scripting
vulnerability in the command-line client when the --html option is
enabled. An attacker could place arbitrary web script or html in a
database cell, which would then get placed in the html document output
by the command-line tool. This issue only affected Ubuntu 6.06 LTS,
8.04 LTS, 8.10 and 9.04. (CVE-2008-4456)

It was discovered that MySQL could be made to overwrite existing table
files in the data directory. An authenticated user could use symlinks
combined with the DATA DIRECTORY and INDEX DIRECTORY options to
possibly bypass privilege checks. This issue only affected Ubuntu
9.10. (CVE-2008-7247)

It was discovered that MySQL contained multiple format string flaws
when logging database creation and deletion. An authenticated user
could use specially crafted database names to make MySQL crash,
causing a denial of service. This issue only affected Ubuntu 6.06 LTS,
8.04 LTS, 8.10 and 9.04. (CVE-2009-2446)

It was discovered that MySQL incorrectly handled errors when
performing certain SELECT statements, and did not preserve correct
flags when performing statements that use the GeomFromWKB function. An
authenticated user could exploit this to make MySQL crash, causing a
denial of service. (CVE-2009-4019)

It was discovered that MySQL incorrectly checked symlinks when using
the DATA DIRECTORY and INDEX DIRECTORY options. A local user could use
symlinks to create tables that pointed to tables known to be created
at a later time, bypassing access restrictions. (CVE-2009-4030)

It was discovered that MySQL contained a buffer overflow when parsing
ssl certificates. A remote attacker could send crafted requests and
cause a denial of service or possibly execute arbitrary code. This
issue did not affect Ubuntu 6.06 LTS and the default compiler options
for affected releases should reduce the vulnerability to a denial of
service. In the default installation, attackers would also be isolated
by the AppArmor MySQL profile. (CVE-2009-4484).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MySQL yaSSL CertDecoder::GetName Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(59, 79, 119, 134);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-core-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-core-5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/11");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libmysqlclient15-dev", pkgver:"5.0.22-0ubuntu6.06.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmysqlclient15off", pkgver:"5.0.22-0ubuntu6.06.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-client", pkgver:"5.0.22-0ubuntu6.06.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-client-5.0", pkgver:"5.0.22-0ubuntu6.06.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-common", pkgver:"5.0.22-0ubuntu6.06.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-server", pkgver:"5.0.22-0ubuntu6.06.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-server-5.0", pkgver:"5.0.22-0ubuntu6.06.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmysqlclient15-dev", pkgver:"5.0.51a-3ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmysqlclient15off", pkgver:"5.0.51a-3ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-client", pkgver:"5.0.51a-3ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-client-5.0", pkgver:"5.0.51a-3ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-common", pkgver:"5.0.51a-3ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-server", pkgver:"5.0.51a-3ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-server-5.0", pkgver:"5.0.51a-3ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmysqlclient15-dev", pkgver:"5.0.67-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmysqlclient15off", pkgver:"5.0.67-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mysql-client", pkgver:"5.0.67-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mysql-client-5.0", pkgver:"5.0.67-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mysql-common", pkgver:"5.0.67-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mysql-server", pkgver:"5.0.67-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mysql-server-5.0", pkgver:"5.0.67-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmysqlclient15-dev", pkgver:"5.1.30really5.0.75-0ubuntu10.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmysqlclient15off", pkgver:"5.1.30really5.0.75-0ubuntu10.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mysql-client", pkgver:"5.1.30really5.0.75-0ubuntu10.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mysql-client-5.0", pkgver:"5.1.30really5.0.75-0ubuntu10.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mysql-common", pkgver:"5.1.30really5.0.75-0ubuntu10.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mysql-server", pkgver:"5.1.30really5.0.75-0ubuntu10.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mysql-server-5.0", pkgver:"5.1.30really5.0.75-0ubuntu10.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mysql-server-core-5.0", pkgver:"5.1.30really5.0.75-0ubuntu10.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqlclient-dev", pkgver:"5.1.37-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqlclient16", pkgver:"5.1.37-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqlclient16-dev", pkgver:"5.1.37-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqld-dev", pkgver:"5.1.37-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqld-pic", pkgver:"5.1.37-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-client", pkgver:"5.1.37-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-client-5.1", pkgver:"5.1.37-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-common", pkgver:"5.1.37-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-server", pkgver:"5.1.37-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-server-5.1", pkgver:"5.1.37-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-server-core-5.1", pkgver:"5.1.37-1ubuntu5.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient-dev / libmysqlclient15-dev / libmysqlclient15off / etc");
}
