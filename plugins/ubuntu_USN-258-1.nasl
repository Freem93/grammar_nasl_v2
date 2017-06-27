#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-258-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21066);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2006-0678");
  script_osvdb_id(23224);
  script_xref(name:"USN", value:"258-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : postgresql-7.4, postgresql-8.0, postgresql vulnerability (USN-258-1)");
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
"Akio Ishida discovered that the SET SESSION AUTHORIZATION command did
not properly verify the validity of its argument. An authenticated
PostgreSQL user could exploit this to crash the server.

However, this does not affect the official binary Ubuntu packages. The
crash can only be triggered if the source package is rebuilt with
assertions enabled (which is not the case in the official binary
packages).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-compat2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtcl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtypes2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-contrib-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-contrib-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-doc-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-doc-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/15");
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
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libecpg-dev", pkgver:"7.4.5-3ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libecpg4", pkgver:"7.4.5-3ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libpgtcl", pkgver:"7.4.5-3ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libpgtcl-dev", pkgver:"7.4.5-3ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libpq3", pkgver:"7.4.5-3ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql", pkgver:"7.4.5-3ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql-client", pkgver:"7.4.5-3ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql-contrib", pkgver:"7.4.5-3ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql-dev", pkgver:"7.4.5-3ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"postgresql-doc", pkgver:"7.4.5-3ubuntu0.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libecpg-compat2", pkgver:"8.0.3-15ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libecpg-dev", pkgver:"7.4.7-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libecpg4", pkgver:"7.4.7-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libecpg5", pkgver:"8.0.3-15ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpgtcl", pkgver:"7.4.7-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpgtcl-dev", pkgver:"7.4.7-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpgtypes2", pkgver:"8.0.3-15ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpq-dev", pkgver:"8.0.3-15ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpq3", pkgver:"7.4.7-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpq4", pkgver:"8.0.3-15ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql", pkgver:"7.4.7-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-7.4", pkgver:"7.4.8-17ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-8.0", pkgver:"8.0.3-15ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-client", pkgver:"7.4.7-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-client-7.4", pkgver:"7.4.8-17ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-client-8.0", pkgver:"8.0.3-15ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-contrib", pkgver:"7.4.7-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-contrib-7.4", pkgver:"7.4.8-17ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-contrib-8.0", pkgver:"8.0.3-15ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-dev", pkgver:"7.4.7-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-doc", pkgver:"7.4.7-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-doc-7.4", pkgver:"7.4.8-17ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-doc-8.0", pkgver:"8.0.3-15ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-plperl-7.4", pkgver:"7.4.8-17ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-plperl-8.0", pkgver:"8.0.3-15ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-plpython-7.4", pkgver:"7.4.8-17ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-plpython-8.0", pkgver:"8.0.3-15ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-pltcl-7.4", pkgver:"7.4.8-17ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-pltcl-8.0", pkgver:"8.0.3-15ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-server-dev-7.4", pkgver:"7.4.8-17ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-server-dev-8.0", pkgver:"8.0.3-15ubuntu2.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libecpg-compat2 / libecpg-dev / libecpg4 / libecpg5 / libpgtcl / etc");
}
