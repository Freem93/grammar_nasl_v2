#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1517-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60126);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/25 16:19:24 $");

  script_cve_id("CVE-2010-1459", "CVE-2010-4159", "CVE-2012-3382");
  script_bugtraq_id(40351, 54344);
  script_osvdb_id(65051, 83683);
  script_xref(name:"USN", value:"1517-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : mono vulnerabilities (USN-1517-1)");
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
"It was discovered that the Mono System.Web library incorrectly
filtered certain error messages related to forbidden files. If a user
were tricked into opening a specially crafted URL, an attacker could
possibly exploit this to conduct cross-site scripting (XSS) attacks.
(CVE-2012-3382)

It was discovered that the Mono System.Web library incorrectly handled
the EnableViewStateMac property. If a user were tricked into opening a
specially crafted URL, an attacker could possibly exploit this to
conduct cross-site scripting (XSS) attacks. This issue only affected
Ubuntu 10.04 LTS. (CVE-2010-4159).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libmono-system-web1.0-cil,
libmono-system-web2.0-cil and / or libmono-system-web4.0-cil packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web4.0-cil");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libmono-system-web1.0-cil", pkgver:"2.4.4~svn151842-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmono-system-web2.0-cil", pkgver:"2.4.4~svn151842-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libmono-system-web1.0-cil", pkgver:"2.6.7-5ubuntu3.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libmono-system-web2.0-cil", pkgver:"2.6.7-5ubuntu3.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libmono-system-web2.0-cil", pkgver:"2.10.5-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libmono-system-web4.0-cil", pkgver:"2.10.5-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libmono-system-web2.0-cil", pkgver:"2.10.8.1-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libmono-system-web4.0-cil", pkgver:"2.10.8.1-1ubuntu2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmono-system-web1.0-cil / libmono-system-web2.0-cil / etc");
}
