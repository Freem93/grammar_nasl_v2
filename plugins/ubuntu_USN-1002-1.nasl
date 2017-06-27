#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1002-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49803);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2010-3433");
  script_bugtraq_id(43747);
  script_osvdb_id(68436);
  script_xref(name:"USN", value:"1002-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.04 / 9.10 / 10.04 LTS : postgresql-8.1, postgresql-8.3, postgresql-8.4 vulnerability (USN-1002-1)");
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
"It was discovered that PostgreSQL did not properly enforce permissions
within sessions when PL/Perl and PL/Tcl functions or operators were
redefined. A remote authenticated attacker could exploit this to
execute arbitrary code with permissions of a different user, possibly
leading to privilege escalation.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-compat2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-compat3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtypes2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtypes3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-8.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-8.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-contrib-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-contrib-8.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-contrib-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-doc-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-doc-8.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-doc-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-8.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython-8.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-8.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-8.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libecpg-compat2", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libecpg-dev", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libecpg5", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpgtypes2", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpq-dev", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpq4", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postgresql-8.1", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postgresql-client-8.1", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postgresql-contrib-8.1", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postgresql-doc-8.1", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postgresql-plperl-8.1", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postgresql-plpython-8.1", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postgresql-pltcl-8.1", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postgresql-server-dev-8.1", pkgver:"8.1.22-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libecpg-compat3", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libecpg-dev", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libecpg6", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpgtypes3", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpq-dev", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpq5", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postgresql", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postgresql-8.3", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postgresql-client", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postgresql-client-8.3", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postgresql-contrib", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postgresql-contrib-8.3", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postgresql-doc", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postgresql-doc-8.3", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postgresql-plperl-8.3", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postgresql-plpython-8.3", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postgresql-pltcl-8.3", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"postgresql-server-dev-8.3", pkgver:"8.3.12-0ubuntu8.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libecpg-compat3", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libecpg-dev", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libecpg6", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpgtypes3", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpq-dev", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpq5", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"postgresql", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"postgresql-8.3", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"postgresql-client", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"postgresql-client-8.3", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"postgresql-contrib", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"postgresql-contrib-8.3", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"postgresql-doc", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"postgresql-doc-8.3", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"postgresql-plperl-8.3", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"postgresql-plpython-8.3", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"postgresql-pltcl-8.3", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"postgresql-server-dev-8.3", pkgver:"8.3.12-0ubuntu9.04")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libecpg-compat3", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libecpg-dev", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libecpg6", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpgtypes3", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpq-dev", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpq5", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"postgresql", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"postgresql-8.4", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"postgresql-client", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"postgresql-client-8.4", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"postgresql-contrib", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"postgresql-contrib-8.4", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"postgresql-doc", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"postgresql-doc-8.4", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"postgresql-plperl-8.4", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"postgresql-plpython-8.4", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"postgresql-pltcl-8.4", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"postgresql-server-dev-8.4", pkgver:"8.4.5-0ubuntu9.10")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libecpg-compat3", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libecpg-dev", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libecpg6", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpgtypes3", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpq-dev", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpq5", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"postgresql", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"postgresql-8.4", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"postgresql-client", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"postgresql-client-8.4", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"postgresql-contrib", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"postgresql-contrib-8.4", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"postgresql-doc", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"postgresql-doc-8.4", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"postgresql-plperl-8.4", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"postgresql-plpython-8.4", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"postgresql-pltcl-8.4", pkgver:"8.4.5-0ubuntu10.04")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"postgresql-server-dev-8.4", pkgver:"8.4.5-0ubuntu10.04")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libecpg-compat2 / libecpg-compat3 / libecpg-dev / libecpg5 / etc");
}
