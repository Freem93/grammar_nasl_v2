#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1807-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66231);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/25 16:27:05 $");

  script_cve_id("CVE-2012-0553", "CVE-2013-1492", "CVE-2013-1502", "CVE-2013-1506", "CVE-2013-1511", "CVE-2013-1512", "CVE-2013-1521", "CVE-2013-1523", "CVE-2013-1526", "CVE-2013-1532", "CVE-2013-1544", "CVE-2013-1552", "CVE-2013-1555", "CVE-2013-1623", "CVE-2013-2375", "CVE-2013-2376", "CVE-2013-2378", "CVE-2013-2389", "CVE-2013-2391", "CVE-2013-2392");
  script_bugtraq_id(57780, 58594, 58595, 59180, 59188, 59196, 59201, 59207, 59209, 59210, 59211, 59217, 59218, 59224, 59225, 59227, 59229, 59237, 59239, 59242);
  script_xref(name:"USN", value:"1807-2");

  script_name(english:"Ubuntu 13.04 : mysql-5.5 vulnerabilities (USN-1807-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-1807-1 fixed vulnerabilities in MySQL. This update provides MySQL
5.5.31 for Ubuntu 13.04.

Multiple security issues were discovered in MySQL and this update
includes new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.1.69 in Ubuntu 10.04 LTS and
Ubuntu 11.10. Ubuntu 12.04 LTS and Ubuntu 12.10 have been
updated to MySQL 5.5.31.

In addition to security fixes, the updated packages contain
bug fixes, new features, and possibly incompatible changes.

Please see the following for more information:
http://dev.mysql.com/doc/relnotes/mysql/5.1/en/news-5-1-69.h
tml
http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-31.h
tml
http://www.oracle.com/technetwork/topics/security/cpuapr2013
-1899555.html.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-server-5.5 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(13\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 13.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"13.04", pkgname:"mysql-server-5.5", pkgver:"5.5.31-0ubuntu0.13.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql-server-5.5");
}
