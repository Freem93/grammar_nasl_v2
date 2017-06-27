#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-369-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27950);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_cve_id("CVE-2006-5540", "CVE-2006-5541", "CVE-2006-5542");
  script_osvdb_id(30019);
  script_xref(name:"USN", value:"369-2");

  script_name(english:"Ubuntu 6.10 : postgresql-8.1 vulnerabilities (USN-369-2)");
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
"USN-369-1 fixed three minor PostgreSQL 8.1 vulnerabilities for Ubuntu
6.06 LTS. This update provides the corresponding update for Ubuntu
6.10.

Michael Fuhr discovered an incorrect type check when handling unknown
literals. By attempting to coerce such a literal to the ANYARRAY type,
a local authenticated attacker could cause a server crash.
(CVE-2006-5541)

Josh Drake and Alvaro Herrera reported a crash when using
aggregate functions in UPDATE statements. A local
authenticated attacker could exploit this to crash the
server backend. This update disables this construct, since
it is not very well defined and forbidden by the SQL
standard. (CVE-2006-5540)

Sergey Koposov discovered a flaw in the duration logging.
This could cause a server crash under certain circumstances.
(CVE-2006-5542)

Please note that these flaws can usually not be exploited
through web and other applications that use a database and
are exposed to untrusted input, so these flaws do not pose a
threat in usual setups.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-compat2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtypes2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-contrib-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-doc-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.10", pkgname:"libecpg-compat2", pkgver:"8.1.4-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libecpg-dev", pkgver:"8.1.4-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libecpg5", pkgver:"8.1.4-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpgtypes2", pkgver:"8.1.4-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpq-dev", pkgver:"8.1.4-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpq4", pkgver:"8.1.4-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"postgresql-8.1", pkgver:"8.1.4-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"postgresql-client-8.1", pkgver:"8.1.4-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"postgresql-contrib-8.1", pkgver:"8.1.4-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"postgresql-doc-8.1", pkgver:"8.1.4-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"postgresql-plperl-8.1", pkgver:"8.1.4-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"postgresql-plpython-8.1", pkgver:"8.1.4-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"postgresql-pltcl-8.1", pkgver:"8.1.4-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"postgresql-server-dev-8.1", pkgver:"8.1.4-7ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libecpg-compat2 / libecpg-dev / libecpg5 / libpgtypes2 / libpq-dev / etc");
}
