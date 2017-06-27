#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-177-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20587);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2004-0700", "CVE-2004-0885", "CVE-2005-2700", "CVE-2005-2728");
  script_xref(name:"USN", value:"177-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : apache2, libapache-mod-ssl vulnerabilities (USN-177-1)");
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
"Apache did not honour the 'SSLVerifyClient require' directive within a
<Location> block if the surrounding <VirtualHost> block contained a
directive 'SSLVerifyClient optional'. This allowed clients to bypass
client certificate validation on servers with the above configuration.
(CAN-2005-2700)

Filip Sneppe discovered a Denial of Service vulnerability in the byte
range filter handler. By requesting certain large byte ranges, a
remote attacker could cause memory exhaustion in the server.
(CAN-2005-2728)

The updated libapache-mod-ssl also fixes two older Denial of Service
vulnerabilities: A format string error in the ssl_log() function which
could be exploited to crash the server (CAN-2004-0700), and a flaw in
the SSL cipher negotiation which could be exploited to terminate a
session (CAN-2004-0885). Please note that Apache 1.3 and
libapache-mod-ssl are not officially supported (they are in the
'universe' component of the Ubuntu archive).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-perchild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-threadpool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-prefork-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-threaded-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache-mod-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache-mod-ssl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapr0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/07");
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

if (ubuntu_check(osver:"4.10", pkgname:"apache2", pkgver:"2.0.50-12ubuntu4.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-common", pkgver:"2.0.50-12ubuntu4.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-doc", pkgver:"2.0.50-12ubuntu4.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-mpm-perchild", pkgver:"2.0.50-12ubuntu4.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-mpm-prefork", pkgver:"2.0.50-12ubuntu4.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-mpm-threadpool", pkgver:"2.0.50-12ubuntu4.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-mpm-worker", pkgver:"2.0.50-12ubuntu4.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-prefork-dev", pkgver:"2.0.50-12ubuntu4.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-threaded-dev", pkgver:"2.0.50-12ubuntu4.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libapache-mod-ssl", pkgver:"2.8.18-1ubuntu1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libapache-mod-ssl-doc", pkgver:"2.8.18-1ubuntu1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libapr0", pkgver:"2.0.50-12ubuntu4.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libapr0-dev", pkgver:"2.0.50-12ubuntu4.8")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2", pkgver:"2.0.53-5ubuntu5.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-common", pkgver:"2.0.53-5ubuntu5.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-doc", pkgver:"2.0.53-5ubuntu5.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-mpm-perchild", pkgver:"2.0.53-5ubuntu5.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-mpm-prefork", pkgver:"2.0.53-5ubuntu5.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-mpm-threadpool", pkgver:"2.0.53-5ubuntu5.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-mpm-worker", pkgver:"2.0.53-5ubuntu5.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-prefork-dev", pkgver:"2.0.53-5ubuntu5.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-threaded-dev", pkgver:"2.0.53-5ubuntu5.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-utils", pkgver:"2.0.53-5ubuntu5.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libapache-mod-ssl", pkgver:"2.8.22-1ubuntu1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libapache-mod-ssl-doc", pkgver:"2.8.22-1ubuntu1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libapr0", pkgver:"2.0.53-5ubuntu5.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libapr0-dev", pkgver:"2.0.53-5ubuntu5.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-common / apache2-doc / apache2-mpm-perchild / etc");
}
