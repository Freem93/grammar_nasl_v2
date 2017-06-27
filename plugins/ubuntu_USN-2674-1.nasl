#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2674-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84915);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/05/24 17:44:50 $");

  script_cve_id("CVE-2015-2582", "CVE-2015-2611", "CVE-2015-2617", "CVE-2015-2620", "CVE-2015-2639", "CVE-2015-2641", "CVE-2015-2643", "CVE-2015-2648", "CVE-2015-2661", "CVE-2015-4737", "CVE-2015-4752", "CVE-2015-4757", "CVE-2015-4761", "CVE-2015-4767", "CVE-2015-4769", "CVE-2015-4771", "CVE-2015-4772");
  script_bugtraq_id(75751, 75753, 75759, 75760, 75762, 75770, 75774, 75781, 75802, 75813, 75815, 75822, 75830, 75835, 75837, 75844, 75849);
  script_osvdb_id(124735, 124736, 124737, 124738, 124739, 124741, 124742, 124743, 124744, 124745, 124746, 124747, 124748, 124749, 124750, 124751, 124752);
  script_xref(name:"USN", value:"2674-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 14.10 / 15.04 : mysql-5.5, mysql-5.6 vulnerabilities (USN-2674-1)");
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

MySQL has been updated to 5.5.44 in Ubuntu 12.04 LTS, Ubuntu 14.04 LTS
and Ubuntu 14.10. Ubuntu 15.04 has been updated to MySQL 5.6.25.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-44.html
http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-25.html
http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.h
tml.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected mysql-server-5.5 and / or mysql-server-5.6
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|14\.10|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 14.10 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"mysql-server-5.5", pkgver:"5.5.44-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"mysql-server-5.5", pkgver:"5.5.44-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"mysql-server-5.5", pkgver:"5.5.44-0ubuntu0.14.10.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"mysql-server-5.6", pkgver:"5.6.25-0ubuntu0.15.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql-server-5.5 / mysql-server-5.6");
}
