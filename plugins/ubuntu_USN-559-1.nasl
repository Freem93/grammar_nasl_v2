#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-559-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29793);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2007-3781", "CVE-2007-5925", "CVE-2007-5969", "CVE-2007-6304");
  script_bugtraq_id(25017, 26353, 26765, 26832);
  script_xref(name:"USN", value:"559-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : mysql-dfsg-5.0 vulnerabilities (USN-559-1)");
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
"Joe Gallo and Artem Russakovskii discovered that the InnoDB engine in
MySQL did not properly perform input validation. An authenticated user
could use a crafted CONTAINS statement to cause a denial of service.
(CVE-2007-5925)

It was discovered that under certain conditions MySQL could be made to
overwrite system table information. An authenticated user could use a
crafted RENAME statement to escalate privileges. (CVE-2007-5969)

Philip Stoev discovered that the the federated engine of MySQL did not
properly handle responses with a small number of columns. An
authenticated user could use a crafted response to a SHOW TABLE STATUS
query and cause a denial of service. (CVE-2007-6304)

It was discovered that MySQL did not properly enforce access controls.
An authenticated user could use a crafted CREATE TABLE LIKE statement
to escalate privileges. (CVE-2007-3781).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 264);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"6.06", pkgname:"libmysqlclient15-dev", pkgver:"5.0.22-0ubuntu6.06.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmysqlclient15off", pkgver:"5.0.22-0ubuntu6.06.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-client", pkgver:"5.0.22-0ubuntu6.06.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-client-5.0", pkgver:"5.0.22-0ubuntu6.06.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-common", pkgver:"5.0.22-0ubuntu6.06.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-server", pkgver:"5.0.22-0ubuntu6.06.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mysql-server-5.0", pkgver:"5.0.22-0ubuntu6.06.6")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmysqlclient15-dev", pkgver:"5.0.24a-9ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmysqlclient15off", pkgver:"5.0.24a-9ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mysql-client", pkgver:"5.0.24a-9ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mysql-client-5.0", pkgver:"5.0.24a-9ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mysql-common", pkgver:"5.0.24a-9ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mysql-server", pkgver:"5.0.24a-9ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mysql-server-5.0", pkgver:"5.0.24a-9ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libmysqlclient15-dev", pkgver:"5.0.38-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libmysqlclient15off", pkgver:"5.0.38-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mysql-client", pkgver:"5.0.38-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mysql-client-5.0", pkgver:"5.0.38-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mysql-common", pkgver:"5.0.38-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mysql-server", pkgver:"5.0.38-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mysql-server-4.1", pkgver:"5.0.38-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mysql-server-5.0", pkgver:"5.0.38-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libmysqlclient15-dev", pkgver:"5.0.45-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libmysqlclient15off", pkgver:"5.0.45-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-client", pkgver:"5.0.45-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-client-5.0", pkgver:"5.0.45-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-common", pkgver:"5.0.45-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-server", pkgver:"5.0.45-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mysql-server-5.0", pkgver:"5.0.45-1ubuntu3.1")) flag++;

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
