#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-32-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20648);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/25 16:34:55 $");

  script_cve_id("CVE-2004-0836", "CVE-2004-0837", "CVE-2004-0956", "CVE-2004-0957");
  script_xref(name:"USN", value:"32-1");

  script_name(english:"Ubuntu 4.10 : mysql-dfsg vulnerabilities (USN-32-1)");
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
"Several vulnerabilities have been discovered in the MySQL database
server.

Lukasz Wojtow discovered a potential buffer overflow in the function
mysql_real_connect(). A malicious name server could send specially
crafted DNS packages which might result in execution of arbitrary code
with the database server's privileges. However, it is believed that
this bug cannot be exploited with the C Standard library (glibc) that
Ubuntu uses. (CAN-2004-0836).

Dean Ellis noticed a flaw that allows an authorized MySQL user to
cause a denial of service (crash or hang) via concurrent execution of
certain statements (ALTER TABLE ... UNION=, FLUSH TABLES) on tables of
type MERGE (CAN-2004-0837)

Some query strings containing a double quote (like MATCH ... AGAINST
(' some ' query' IN BOOLEAN MODE) ) that did not have a matching
closing double quote caused a denial of service (server crash). Again,
this is only exploitable by authorized mysql users. (CAN-2004-0956)

If a user was granted privileges to a database with a name containing
an underscore ('_'), the user also gained the ability to grant
privileges to other databases with similar names. (CAN-2004-0957).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2004-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libmysqlclient-dev", pkgver:"4.0.20-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libmysqlclient12", pkgver:"4.0.20-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mysql-client", pkgver:"4.0.20-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mysql-common", pkgver:"4.0.20-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mysql-server", pkgver:"4.0.20-2ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient-dev / libmysqlclient12 / mysql-client / mysql-common / etc");
}
