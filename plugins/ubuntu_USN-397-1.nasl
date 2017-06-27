#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-397-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27983);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_cve_id("CVE-2006-6104");
  script_bugtraq_id(21687);
  script_osvdb_id(32391, 32392);
  script_xref(name:"USN", value:"397-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 : mono vulnerability (USN-397-1)");
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
"Jose Ramon Palanco discovered that the mono System.Web class did not
consistently verify local file paths. As a result, the source code for
mono web applications could be retrieved remotely, possibly leading to
further compromise via the application's source.

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-accessibility1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-accessibility2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-bytefx0.7.6.1-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-bytefx0.7.6.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-c5-1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-cairo1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-cairo2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-corlib1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-corlib2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-cscompmgd7.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-cscompmgd8.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-data-tds1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-data-tds2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-firebirdsql1.7-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-ldap1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-ldap2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft-build2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft7.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft8.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-npgsql1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-npgsql2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-oracle1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-oracle2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-peapi1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-peapi2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-relaxng1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-relaxng2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-security1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-security2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-sharpzip0.6-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-sharpzip0.84-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-sharpzip2.6-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-sharpzip2.84-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-sqlite1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-sqlite2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-data1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-data2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-ldap1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-ldap2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-messaging1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-messaging2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-runtime1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-runtime2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-winforms1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-winforms2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono2.0-cil");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-mjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/20");
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
if (! ereg(pattern:"^(6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libmono-dev", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmono0", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-assemblies-base", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-classlib-1.0", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-classlib-1.0-dbg", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-classlib-2.0", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-classlib-2.0-dbg", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-common", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-devel", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-gac", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-gmcs", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-jay", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-jit", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-mcs", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mono-utils", pkgver:"1.1.13.6-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-accessibility1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-accessibility2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-bytefx0.7.6.1-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-bytefx0.7.6.2-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-c5-1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-cairo1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-cairo2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-corlib1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-corlib2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-cscompmgd7.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-cscompmgd8.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-data-tds1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-data-tds2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-dev", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-firebirdsql1.7-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-ldap1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-ldap2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-microsoft-build2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-microsoft7.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-microsoft8.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-npgsql1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-npgsql2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-oracle1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-oracle2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-peapi1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-peapi2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-relaxng1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-relaxng2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-security1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-security2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-sharpzip0.6-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-sharpzip0.84-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-sharpzip2.6-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-sharpzip2.84-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-sqlite1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-sqlite2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-system-data1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-system-data2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-system-ldap1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-system-ldap2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-system-messaging1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-system-messaging2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-system-runtime1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-system-runtime2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-system-web1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-system-web2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-system1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-system2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-winforms1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono-winforms2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono0", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono1.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmono2.0-cil", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mono", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mono-classlib-1.0", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mono-classlib-2.0", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mono-common", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mono-devel", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mono-gac", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mono-gmcs", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mono-jay", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mono-jit", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mono-mcs", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mono-mjs", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mono-runtime", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mono-utils", pkgver:"1.1.17.1-1ubuntu7.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmono-accessibility1.0-cil / libmono-accessibility2.0-cil / etc");
}
