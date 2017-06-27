#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-283-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21377);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 16:22:51 $");

  script_cve_id("CVE-2006-1516", "CVE-2006-1517");
  script_bugtraq_id(17780);
  script_osvdb_id(25226, 25228);
  script_xref(name:"USN", value:"283-1");

  script_name(english:"Ubuntu 5.04 / 5.10 : mysql-dfsg-4.1, mysql-dfsg vulnerabilities (USN-283-1)");
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
"Stefano Di Paola discovered an information leak in the login packet
parser. By sending a specially crafted malformed login packet, a
remote attacker could exploit this to read a random piece of memory,
which could potentially reveal sensitive data. (CVE-2006-1516)

Stefano Di Paola also found a similar information leak in the parser
for the COM_TABLE_DUMP request. (CVE-2006-1517).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient12-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-common-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"libmysqlclient12", pkgver:"4.0.23-3ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmysqlclient12-dev", pkgver:"4.0.23-3ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mysql-client", pkgver:"4.0.23-3ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mysql-common", pkgver:"4.0.23-3ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mysql-server", pkgver:"4.0.23-3ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmysqlclient12", pkgver:"4.0.24-10ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmysqlclient12-dev", pkgver:"4.0.24-10ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmysqlclient14", pkgver:"4.1.12-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmysqlclient14-dev", pkgver:"4.1.12-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mysql-client", pkgver:"4.0.24-10ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mysql-client-4.1", pkgver:"4.1.12-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mysql-common", pkgver:"4.0.24-10ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mysql-common-4.1", pkgver:"4.1.12-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mysql-server", pkgver:"4.0.24-10ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mysql-server-4.1", pkgver:"4.1.12-1ubuntu3.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient12 / libmysqlclient12-dev / libmysqlclient14 / etc");
}
