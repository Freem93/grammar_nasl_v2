#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-274-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21568);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/26 16:22:51 $");

  script_cve_id("CVE-2006-0903");
  script_xref(name:"USN", value:"274-2");

  script_name(english:"Ubuntu 5.04 / 5.10 : mysql-dfsg vulnerability (USN-274-2)");
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
"USN-274-1 fixed a logging bypass in the MySQL server. Unfortunately it
was determined that the original update was not sufficient to
completely fix the vulnerability, thus another update is necessary. We
apologize for the inconvenience.

For reference, these are the details of the original USN :

A logging bypass was discovered in the MySQL query parser. A local
attacker could exploit this by inserting NUL characters into query
strings (even into comments), which would cause the query to be logged
incompletely.

This only affects you if you enabled the 'log' parameter in
the MySQL configuration.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient12-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/16");
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

if (ubuntu_check(osver:"5.04", pkgname:"libmysqlclient12", pkgver:"4.0.23-3ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmysqlclient12-dev", pkgver:"4.0.23-3ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mysql-client", pkgver:"4.0.23-3ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mysql-common", pkgver:"4.0.23-3ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mysql-server", pkgver:"4.0.23-3ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmysqlclient12", pkgver:"4.0.24-10ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmysqlclient12-dev", pkgver:"4.0.24-10ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mysql-client", pkgver:"4.0.24-10ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mysql-common", pkgver:"4.0.24-10ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mysql-server", pkgver:"4.0.24-10ubuntu2.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient12 / libmysqlclient12-dev / mysql-client / etc");
}
