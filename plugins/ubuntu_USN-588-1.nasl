#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-588-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31638);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2006-7232", "CVE-2007-2692", "CVE-2007-6303", "CVE-2008-0226", "CVE-2008-0227");
  script_bugtraq_id(24011, 26832);
  script_osvdb_id(41195, 41197);
  script_xref(name:"USN", value:"588-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : mysql-dfsg-5.0 vulnerabilities (USN-588-1)");
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
"Masaaki Hirose discovered that MySQL could be made to dereference a
NULL pointer. An authenticated user could cause a denial of service
(application crash) via an EXPLAIN SELECT FROM on the
INFORMATION_SCHEMA table. This issue only affects Ubuntu 6.06 and
6.10. (CVE-2006-7232)

Alexander Nozdrin discovered that MySQL did not restore database
access privileges when returning from SQL SECURITY INVOKER stored
routines. An authenticated user could exploit this to gain privileges.
This issue does not affect Ubuntu 7.10. (CVE-2007-2692)

Martin Friebe discovered that MySQL did not properly update the
DEFINER value of an altered view. An authenticated user could use
CREATE SQL SECURITY DEFINER VIEW and ALTER VIEW statements to gain
privileges. (CVE-2007-6303)

Luigi Auriemma discovered that yaSSL as included in MySQL did not
properly validate its input. A remote attacker could send crafted
requests and cause a denial of service or possibly execute arbitrary
code. This issue did not affect Ubuntu 6.06 in the default
installation. (CVE-2008-0226, CVE-2008-0227).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MySQL yaSSL SSL Hello Message Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(89, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient15off");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libmysqlclient15-dev", pkgver:"5.0.22-0ubuntu6.06.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmysqlclient15off", pkgver:"5.0.22-0ubuntu6.06.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-client", pkgver:"5.0.22-0ubuntu6.06.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-client-5.0", pkgver:"5.0.22-0ubuntu6.06.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-common", pkgver:"5.0.22-0ubuntu6.06.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-server", pkgver:"5.0.22-0ubuntu6.06.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-server-5.0", pkgver:"5.0.22-0ubuntu6.06.8")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmysqlclient15-dev", pkgver:"5.0.24a-9ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmysqlclient15off", pkgver:"5.0.24a-9ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mysql-client", pkgver:"5.0.24a-9ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mysql-client-5.0", pkgver:"5.0.24a-9ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mysql-common", pkgver:"5.0.24a-9ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mysql-server", pkgver:"5.0.24a-9ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mysql-server-5.0", pkgver:"5.0.24a-9ubuntu2.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libmysqlclient15-dev", pkgver:"5.0.38-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libmysqlclient15off", pkgver:"5.0.38-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mysql-client", pkgver:"5.0.38-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mysql-client-5.0", pkgver:"5.0.38-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mysql-common", pkgver:"5.0.38-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mysql-server", pkgver:"5.0.38-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mysql-server-4.1", pkgver:"5.0.38-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mysql-server-5.0", pkgver:"5.0.38-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libmysqlclient15-dev", pkgver:"5.0.45-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libmysqlclient15off", pkgver:"5.0.45-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-client", pkgver:"5.0.45-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-client-5.0", pkgver:"5.0.45-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-common", pkgver:"5.0.45-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-server", pkgver:"5.0.45-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-server-5.0", pkgver:"5.0.45-1ubuntu3.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient15-dev / libmysqlclient15off / mysql-client / etc");
}
