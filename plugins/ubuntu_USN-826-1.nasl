#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-826-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40794);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-3422", "CVE-2008-3906", "CVE-2009-0217");
  script_bugtraq_id(35671);
  script_osvdb_id(47562, 47563, 47564, 47565, 47566, 47855, 55895, 55907, 56243);
  script_xref(name:"USN", value:"826-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : mono vulnerabilities (USN-826-1)");
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
"It was discovered that the XML HMAC signature system did not correctly
check certain lengths. If an attacker sent a truncated HMAC, it could
bypass authentication, leading to potential privilege escalation.
(CVE-2009-0217)

It was discovered that Mono did not properly escape certain attributes
in the ASP.net class libraries which could result in browsers becoming
vulnerable to cross-site scripting attacks when processing the output.
With cross-site scripting vulnerabilities, if a user were tricked into
viewing server output during a crafted server request, a remote
attacker could exploit this to modify the contents, or steal
confidential data (such as passwords), within the same domain. This
issue only affected Ubuntu 8.04 LTS. (CVE-2008-3422)

It was discovered that Mono did not properly filter CRLF injections in
the query string. If a user were tricked into viewing server output
during a crafted server request, a remote attacker could exploit this
to modify the contents, steal confidential data (such as passwords),
or perform cross-site request forgeries. This issue only affected
Ubuntu 8.04 LTS. (CVE-2008-3906).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-corlib2.1-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-cscompmgd7.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-cscompmgd8.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-data-tds1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-data-tds2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-data1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-data2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-db2-1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-firebirdsql1.7-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-getoptions1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-getoptions2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-i18n1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-i18n2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-ldap1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-ldap2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft-build2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft7.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft8.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-mozilla0.1-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-mozilla0.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-npgsql1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-npgsql2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-nunit2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-oracle1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-oracle2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-peapi1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-peapi2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-posix1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-posix2.0-cil");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system2.1-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-webbrowser0.5-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-winforms1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-winforms2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-1.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-1.0-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-1.0-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-1.0-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-2.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-2.0-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-2.0-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-2.0-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-gmcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-jay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-jit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-jit-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-mcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-mjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-smcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-xbuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:prj2make-sharp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libmono-accessibility1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-accessibility2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-bytefx0.7.6.1-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-bytefx0.7.6.2-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-c5-1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-cairo1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-cairo2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-corlib1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-corlib2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-corlib2.1-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-cscompmgd7.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-cscompmgd8.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-data-tds1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-data-tds2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-db2-1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-dev", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-firebirdsql1.7-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-i18n1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-i18n2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-ldap1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-ldap2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-microsoft-build2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-microsoft7.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-microsoft8.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-mozilla0.1-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-npgsql1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-npgsql2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-oracle1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-oracle2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-peapi1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-peapi2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-relaxng1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-relaxng2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-security1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-security2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-sharpzip0.6-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-sharpzip0.84-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-sharpzip2.6-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-sharpzip2.84-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-sqlite1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-sqlite2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-system-data1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-system-data2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-system-ldap1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-system-ldap2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-system-messaging1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-system-messaging2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-system-runtime1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-system-runtime2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-system-web1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-system-web2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-system1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-system2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-system2.1-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-winforms1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono-winforms2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono0", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono0-dbg", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono1.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmono2.0-cil", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-1.0-devel", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-1.0-service", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-2.0-devel", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-2.0-service", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-common", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-dbg", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-gac", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-gmcs", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-jay", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-jit", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-jit-dbg", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-mcs", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-mjs", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-runtime", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-smcs", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-utils", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mono-xbuild", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"prj2make-sharp", pkgver:"1.2.6+dfsg-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-accessibility1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-accessibility2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-bytefx0.7.6.1-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-bytefx0.7.6.2-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-c5-1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-cairo1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-cairo2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-corlib1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-corlib2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-corlib2.1-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-cscompmgd7.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-cscompmgd8.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-data-tds1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-data-tds2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-db2-1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-dev", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-firebirdsql1.7-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-i18n1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-i18n2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-ldap1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-ldap2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-microsoft-build2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-microsoft7.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-microsoft8.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-mozilla0.2-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-npgsql1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-npgsql2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-nunit2.2-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-oracle1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-oracle2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-peapi1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-peapi2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-relaxng1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-relaxng2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-security1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-security2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-sharpzip0.6-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-sharpzip0.84-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-sharpzip2.6-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-sharpzip2.84-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-sqlite1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-sqlite2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-system-data1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-system-data2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-system-ldap1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-system-ldap2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-system-messaging1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-system-messaging2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-system-runtime1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-system-runtime2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-system-web1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-system-web2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-system1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-system2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-system2.1-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-winforms1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono-winforms2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono0", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono0-dbg", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono1.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmono2.0-cil", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-1.0-devel", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-1.0-service", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-2.0-devel", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-2.0-service", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-common", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-dbg", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-gac", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-gmcs", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-jay", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-jit", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-jit-dbg", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-mcs", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-mjs", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-runtime", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-smcs", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-utils", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mono-xbuild", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"prj2make-sharp", pkgver:"1.9.1+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-accessibility1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-accessibility2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-bytefx0.7.6.1-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-bytefx0.7.6.2-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-c5-1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-cairo1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-cairo2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-corlib1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-corlib2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-corlib2.1-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-cscompmgd7.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-cscompmgd8.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-data-tds1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-data-tds2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-data1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-data2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-db2-1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-dev", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-firebirdsql1.7-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-getoptions1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-getoptions2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-i18n1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-i18n2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-ldap1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-ldap2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-microsoft-build2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-microsoft7.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-microsoft8.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-npgsql1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-npgsql2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-nunit2.2-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-oracle1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-oracle2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-peapi1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-peapi2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-posix1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-posix2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-relaxng1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-relaxng2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-security1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-security2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-sharpzip0.6-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-sharpzip0.84-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-sharpzip2.6-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-sharpzip2.84-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-sqlite1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-sqlite2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-system-data1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-system-data2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-system-ldap1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-system-ldap2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-system-messaging1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-system-messaging2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-system-runtime1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-system-runtime2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-system-web1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-system-web2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-system1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-system2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-system2.1-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-webbrowser0.5-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-winforms1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono-winforms2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono0", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono0-dbg", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono1.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmono2.0-cil", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-1.0-devel", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-1.0-gac", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-1.0-runtime", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-1.0-service", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-2.0-devel", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-2.0-gac", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-2.0-runtime", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-2.0-service", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-common", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-dbg", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-devel", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-gac", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-gmcs", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-jay", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-jit", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-jit-dbg", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-mcs", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-mjs", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-runtime", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-smcs", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-utils", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mono-xbuild", pkgver:"2.0.1-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"prj2make-sharp", pkgver:"2.0.1-4ubuntu0.1")) flag++;

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
