#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1703-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63668);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2012-0572", "CVE-2012-0574", "CVE-2012-0578", "CVE-2012-1702", "CVE-2012-1705", "CVE-2012-5060", "CVE-2012-5096", "CVE-2012-5611", "CVE-2012-5612", "CVE-2013-0367", "CVE-2013-0368", "CVE-2013-0371", "CVE-2013-0375", "CVE-2013-0383", "CVE-2013-0384", "CVE-2013-0385", "CVE-2013-0386", "CVE-2013-0389");
  script_bugtraq_id(56768, 56769, 57334, 57385, 57388, 57391, 57397, 57400, 57405, 57408, 57410, 57411, 57412, 57414, 57415, 57416, 57417, 57418);
  script_osvdb_id(88064, 88066, 89250, 89251, 89252, 89253, 89254, 89255, 89256, 89257, 89258, 89259, 89260, 89261, 89262, 89263, 89264, 89265);
  script_xref(name:"USN", value:"1703-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.10 / 12.04 LTS / 12.10 : mysql-5.1, mysql-5.5, mysql-dfsg-5.1 vulnerabilities (USN-1703-1)");
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
"Multiple security issues were discovered in MySQL and this update
includes new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.1.67 in Ubuntu 10.04 LTS and Ubuntu 11.10.
Ubuntu 12.04 LTS and Ubuntu 12.10 have been updated to MySQL 5.5.29.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
http://dev.mysql.com/doc/relnotes/mysql/5.1/en/news-5-1-67.html
http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-29.html
http://www.oracle.com/technetwork/topics/security/cpujan2013-1515902.h
tml.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected mysql-server-5.1 and / or mysql-server-5.5
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/23");
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
if (! ereg(pattern:"^(10\.04|11\.10|12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.10 / 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"mysql-server-5.1", pkgver:"5.1.67-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"mysql-server-5.1", pkgver:"5.1.67-0ubuntu0.11.10.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"mysql-server-5.5", pkgver:"5.5.29-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"mysql-server-5.5", pkgver:"5.5.29-0ubuntu0.12.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql-server-5.1 / mysql-server-5.5");
}
