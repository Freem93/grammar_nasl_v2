#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-79-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20702);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2005-0244", "CVE-2005-0245", "CVE-2005-0246", "CVE-2005-0247");
  script_xref(name:"USN", value:"79-1");

  script_name(english:"Ubuntu 4.10 : postgresql vulnerabilities (USN-79-1)");
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
"The execution of custom PostgreSQL functions can be restricted with
the EXECUTE privilege. However, previous versions did not check this
privilege when executing a function which was part of an aggregate. As
a result, any database user could circumvent the EXECUTE restriction
of functions with a particular (but very common) parameter structure
by creating an aggregate wrapper around the function. (CAN-2005-0244)

Several buffer overflows have been discovered in the SQL parser. These
could be exploited by any database user to crash the PostgreSQL server
or execute arbitrary code with the privileges of the server.
(CAN-2005-0245, CAN-2005-0247)

Finally, this update fixes a Denial of Service vulnerability of the
contributed 'intagg' module. By constructing specially crafted arrays,
a database user was able to corrupt and crash the PostgreSQL server.
(CAN-2005-0246). Please note that this module is part of the
'postgresql-contrib' package, which is not officially supported by
Ubuntu.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 264);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/10");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libecpg-dev", pkgver:"7.4.5-3ubuntu0.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libecpg4", pkgver:"7.4.5-3ubuntu0.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libpgtcl", pkgver:"7.4.5-3ubuntu0.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libpgtcl-dev", pkgver:"7.4.5-3ubuntu0.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libpq3", pkgver:"7.4.5-3ubuntu0.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql", pkgver:"7.4.5-3ubuntu0.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql-client", pkgver:"7.4.5-3ubuntu0.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql-contrib", pkgver:"7.4.5-3ubuntu0.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql-dev", pkgver:"7.4.5-3ubuntu0.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql-doc", pkgver:"7.4.5-3ubuntu0.4")) flag++;

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
