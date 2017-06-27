#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1017-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50573);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2010-2008", "CVE-2010-3677", "CVE-2010-3678", "CVE-2010-3679", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3683", "CVE-2010-3833", "CVE-2010-3834", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840");
  script_bugtraq_id(41198, 42596, 42598, 42599, 42625, 42633, 42638, 42646, 43676);
  script_osvdb_id(65851, 67378, 67379, 67380, 67381, 67383, 67384, 69000, 69001, 69387, 69390, 69391, 69392, 69393, 69394, 69395);
  script_xref(name:"USN", value:"1017-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : mysql-5.1, mysql-dfsg-5.0, mysql-dfsg-5.1 vulnerabilities (USN-1017-1)");
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
"It was discovered that MySQL incorrectly handled certain requests with
the UPGRADE DATA DIRECTORY NAME command. An authenticated user could
exploit this to make MySQL crash, causing a denial of service. This
issue only affected Ubuntu 9.10 and 10.04 LTS. (CVE-2010-2008)

It was discovered that MySQL incorrectly handled joins involving a
table with a unique SET column. An authenticated user could exploit
this to make MySQL crash, causing a denial of service. This issue only
affected Ubuntu 6.06 LTS, 8.04 LTS, 9.10 and 10.04 LTS.
(CVE-2010-3677)

It was discovered that MySQL incorrectly handled NULL arguments to
IN() or CASE operations. An authenticated user could exploit this to
make MySQL crash, causing a denial of service. This issue only
affected Ubuntu 9.10 and 10.04 LTS. (CVE-2010-3678)

It was discovered that MySQL incorrectly handled malformed arguments
to the BINLOG statement. An authenticated user could exploit this to
make MySQL crash, causing a denial of service. This issue only
affected Ubuntu 9.10 and 10.04 LTS. (CVE-2010-3679)

It was discovered that MySQL incorrectly handled the use of TEMPORARY
InnoDB tables with nullable columns. An authenticated user could
exploit this to make MySQL crash, causing a denial of service. This
issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 9.10 and 10.04 LTS.
(CVE-2010-3680)

It was discovered that MySQL incorrectly handled alternate reads from
two indexes on a table using the HANDLER interface. An authenticated
user could exploit this to make MySQL crash, causing a denial of
service. This issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 9.10 and
10.04 LTS. (CVE-2010-3681)

It was discovered that MySQL incorrectly handled use of EXPLAIN with
certain queries. An authenticated user could exploit this to make
MySQL crash, causing a denial of service. This issue only affected
Ubuntu 6.06 LTS, 8.04 LTS, 9.10 and 10.04 LTS. (CVE-2010-3682)

It was discovered that MySQL incorrectly handled error reporting when
using LOAD DATA INFILE and would incorrectly raise an assert in
certain circumstances. An authenticated user could exploit this to
make MySQL crash, causing a denial of service. This issue only
affected Ubuntu 9.10 and 10.04 LTS. (CVE-2010-3683)

It was discovered that MySQL incorrectly handled propagation during
evaluation of arguments to extreme-value functions. An authenticated
user could exploit this to make MySQL crash, causing a denial of
service. This issue only affected Ubuntu 8.04 LTS, 9.10, 10.04 LTS and
10.10. (CVE-2010-3833)

It was discovered that MySQL incorrectly handled materializing a
derived table that required a temporary table for grouping. An
authenticated user could exploit this to make MySQL crash, causing a
denial of service. (CVE-2010-3834)

It was discovered that MySQL incorrectly handled certain user-variable
assignment expressions that are evaluated in a logical expression
context. An authenticated user could exploit this to make MySQL crash,
causing a denial of service. This issue only affected Ubuntu 8.04 LTS,
9.10, 10.04 LTS and 10.10. (CVE-2010-3835)

It was discovered that MySQL incorrectly handled pre-evaluation of
LIKE predicates during view preparation. An authenticated user could
exploit this to make MySQL crash, causing a denial of service.
(CVE-2010-3836)

It was discovered that MySQL incorrectly handled using GROUP_CONCAT()
and WITH ROLLUP together. An authenticated user could exploit this to
make MySQL crash, causing a denial of service. (CVE-2010-3837)

It was discovered that MySQL incorrectly handled certain queries using
a mixed list of numeric and LONGBLOB arguments to the GREATEST() or
LEAST() functions. An authenticated user could exploit this to make
MySQL crash, causing a denial of service. (CVE-2010-3838)

It was discovered that MySQL incorrectly handled queries with nested
joins when used from stored procedures and prepared statements. An
authenticated user could exploit this to make MySQL hang, causing a
denial of service. This issue only affected Ubuntu 9.10, 10.04 LTS and
10.10. (CVE-2010-3839)

It was discovered that MySQL incorrectly handled improper WKB data
passed to the PolyFromWKB() function. An authenticated user could
exploit this to make MySQL crash, causing a denial of service.
(CVE-2010-3840).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-core-5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/12");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libmysqlclient15-dev", pkgver:"5.0.22-0ubuntu6.06.15")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmysqlclient15off", pkgver:"5.0.22-0ubuntu6.06.15")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-client", pkgver:"5.0.22-0ubuntu6.06.15")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-client-5.0", pkgver:"5.0.22-0ubuntu6.06.15")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-common", pkgver:"5.0.22-0ubuntu6.06.15")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-server", pkgver:"5.0.22-0ubuntu6.06.15")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-server-5.0", pkgver:"5.0.22-0ubuntu6.06.15")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmysqlclient15-dev", pkgver:"5.0.51a-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmysqlclient15off", pkgver:"5.0.51a-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-client", pkgver:"5.0.51a-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-client-5.0", pkgver:"5.0.51a-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-common", pkgver:"5.0.51a-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-server", pkgver:"5.0.51a-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mysql-server-5.0", pkgver:"5.0.51a-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqlclient-dev", pkgver:"5.1.37-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqlclient16", pkgver:"5.1.37-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqlclient16-dev", pkgver:"5.1.37-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqld-dev", pkgver:"5.1.37-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmysqld-pic", pkgver:"5.1.37-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-client", pkgver:"5.1.37-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-client-5.1", pkgver:"5.1.37-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-common", pkgver:"5.1.37-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-server", pkgver:"5.1.37-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-server-5.1", pkgver:"5.1.37-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mysql-server-core-5.1", pkgver:"5.1.37-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmysqlclient-dev", pkgver:"5.1.41-3ubuntu12.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmysqlclient16", pkgver:"5.1.41-3ubuntu12.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmysqlclient16-dev", pkgver:"5.1.41-3ubuntu12.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmysqld-dev", pkgver:"5.1.41-3ubuntu12.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmysqld-pic", pkgver:"5.1.41-3ubuntu12.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-client", pkgver:"5.1.41-3ubuntu12.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-client-5.1", pkgver:"5.1.41-3ubuntu12.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-client-core-5.1", pkgver:"5.1.41-3ubuntu12.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-common", pkgver:"5.1.41-3ubuntu12.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-server", pkgver:"5.1.41-3ubuntu12.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-server-5.1", pkgver:"5.1.41-3ubuntu12.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-server-core-5.1", pkgver:"5.1.41-3ubuntu12.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-testsuite", pkgver:"5.1.41-3ubuntu12.7")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libmysqlclient-dev", pkgver:"5.1.49-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libmysqlclient16", pkgver:"5.1.49-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libmysqlclient16-dev", pkgver:"5.1.49-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libmysqld-dev", pkgver:"5.1.49-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libmysqld-pic", pkgver:"5.1.49-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"mysql-client", pkgver:"5.1.49-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"mysql-client-5.1", pkgver:"5.1.49-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"mysql-client-core-5.1", pkgver:"5.1.49-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"mysql-common", pkgver:"5.1.49-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"mysql-server", pkgver:"5.1.49-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"mysql-server-5.1", pkgver:"5.1.49-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"mysql-server-core-5.1", pkgver:"5.1.49-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"mysql-testsuite", pkgver:"5.1.49-1ubuntu8.1")) flag++;

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
