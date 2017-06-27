#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-118-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20506);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 16:14:08 $");

  script_cve_id("CVE-2005-1409", "CVE-2005-1410");
  script_xref(name:"USN", value:"118-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : postgresql vulnerabilities (USN-118-1)");
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
"It was discovered that unprivileged users were allowed to call
internal character conversion functions. However, since these
functions were not designed to be safe against malicious choices of
argument values, this could potentially be exploited to execute
arbitrary code with the privileges of the PostgreSQL server (user
'postgres'). (CAN-2005-1409)

Another vulnerability was found in the 'tsearch2' module of
postgresql-contrib. This module declared several functions as
internal, although they did not accept any internal argument; this
breaks the type safety of 'internal' by allowing users to construct
SQL commands that invoke other functions accepting 'internal'
arguments. This could eventually be exploited to crash the server, or
possibly even execute arbitrary code with the privileges of the
PostgreSQL server. (CAN-2005-1410)

These vulnerabilities must also be fixed in all existing databases
when upgrading. The post-installation script of the updated package
attempts to do this automatically; if the package installs without any
error, all existing databases have been updated to be safe against
above vulnerabilities. Should the installation fail, please contact
the Ubuntu security team (security@ubuntu.com) immediately.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtcl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libecpg-dev", pkgver:"7.4.5-3ubuntu0.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libecpg4", pkgver:"7.4.5-3ubuntu0.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libpgtcl", pkgver:"7.4.5-3ubuntu0.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libpgtcl-dev", pkgver:"7.4.5-3ubuntu0.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libpq3", pkgver:"7.4.5-3ubuntu0.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql", pkgver:"7.4.5-3ubuntu0.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql-client", pkgver:"7.4.5-3ubuntu0.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql-contrib", pkgver:"7.4.5-3ubuntu0.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql-dev", pkgver:"7.4.5-3ubuntu0.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql-doc", pkgver:"7.4.5-3ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libecpg-dev", pkgver:"7.4.7-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libecpg4", pkgver:"7.4.7-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpgtcl", pkgver:"7.4.7-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpgtcl-dev", pkgver:"7.4.7-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpq3", pkgver:"7.4.7-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql", pkgver:"7.4.7-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-client", pkgver:"7.4.7-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-contrib", pkgver:"7.4.7-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-dev", pkgver:"7.4.7-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-doc", pkgver:"7.4.7-2ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libecpg-dev / libecpg4 / libpgtcl / libpgtcl-dev / libpq3 / etc");
}
