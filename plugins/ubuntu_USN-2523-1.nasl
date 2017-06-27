#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2523-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81755);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/07/18 15:54:02 $");

  script_cve_id("CVE-2013-5704", "CVE-2014-3581", "CVE-2014-3583", "CVE-2014-8109", "CVE-2015-0228");
  script_bugtraq_id(66550, 71656, 71657);
  script_osvdb_id(105190, 112168, 114570, 115375, 119066);
  script_xref(name:"USN", value:"2523-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 14.04 LTS / 14.10 : apache2 vulnerabilities (USN-2523-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Martin Holst Swende discovered that the mod_headers module allowed
HTTP trailers to replace HTTP headers during request processing. A
remote attacker could possibly use this issue to bypass RequestHeaders
directives. (CVE-2013-5704)

Mark Montague discovered that the mod_cache module incorrectly handled
empty HTTP Content-Type headers. A remote attacker could use this
issue to cause the server to stop responding, leading to a denial of
service. This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10.
(CVE-2014-3581)

Teguh P. Alko discovered that the mod_proxy_fcgi module incorrectly
handled long response headers. A remote attacker could use this issue
to cause the server to stop responding, leading to a denial of
service. This issue only affected Ubuntu 14.10. (CVE-2014-3583)

It was discovered that the mod_lua module incorrectly handled
different arguments within different contexts. A remote attacker could
possibly use this issue to bypass intended access restrictions. This
issue only affected Ubuntu 14.10. (CVE-2014-8109)

Guido Vranken discovered that the mod_lua module incorrectly handled a
specially crafted websocket PING in certain circumstances. A remote
attacker could possibly use this issue to cause the server to stop
responding, leading to a denial of service. This issue only affected
Ubuntu 14.10. (CVE-2015-0228).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2.2-bin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2.2-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|12\.04|14\.04|14\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 14.04 / 14.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"apache2.2-bin", pkgver:"2.2.14-5ubuntu8.15")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"apache2.2-bin", pkgver:"2.2.22-1ubuntu1.8")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"apache2.2-bin", pkgver:"2.4.7-1ubuntu4.4")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"apache2.2-bin", pkgver:"2.4.10-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2.2-bin");
}
