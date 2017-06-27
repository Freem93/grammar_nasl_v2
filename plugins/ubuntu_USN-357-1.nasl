#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-357-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27937);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:21:17 $");

  script_cve_id("CVE-2006-5072");
  script_osvdb_id(29504);
  script_xref(name:"USN", value:"357-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS : mono vulnerability (USN-357-1)");
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
"Sebastian Krahmer of the SuSE security team discovered that the
System.CodeDom.Compiler classes used temporary files in an insecure
way. This could allow a symbolic link attack to create or overwrite
arbitrary files with the privileges of the user invoking the program.
Under some circumstances, a local attacker could also exploit this to
inject arbitrary code into running Mono processes.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-assemblies-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-classlib-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-classlib-1.0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-classlib-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-classlib-2.0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-gmcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-jay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-jit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-mcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/04");
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
if (! ereg(pattern:"^(5\.10|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"libmono-dev", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmono0", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono-assemblies-base", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono-classlib-1.0", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono-classlib-1.0-dbg", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono-classlib-2.0", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono-classlib-2.0-dbg", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono-common", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono-devel", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono-gac", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono-gmcs", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono-jay", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono-jit", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono-mcs", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"mono-utils", pkgver:"1.1.8.3-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmono-dev", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmono0", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-assemblies-base", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-classlib-1.0", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-classlib-1.0-dbg", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-classlib-2.0", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-classlib-2.0-dbg", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-common", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-devel", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-gac", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-gmcs", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-jay", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-jit", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-mcs", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-utils", pkgver:"1.1.13.6-0ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmono-dev / libmono0 / mono / mono-assemblies-base / etc");
}
