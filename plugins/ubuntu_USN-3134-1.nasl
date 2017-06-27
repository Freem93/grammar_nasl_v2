#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3134-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95284);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2016/12/07 21:18:29 $");

  script_cve_id("CVE-2016-0772", "CVE-2016-1000110", "CVE-2016-5636", "CVE-2016-5699");
  script_osvdb_id(115884, 140038, 140125, 141671);
  script_xref(name:"USN", value:"3134-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS : python2.7, python3.2, python3.4, python3.5 vulnerabilities (USN-3134-1) (httpoxy)");
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
"It was discovered that the smtplib library in Python did not return an
error when StartTLS fails. A remote attacker could possibly use this
to expose sensitive information. (CVE-2016-0772)

Remi Rampin discovered that Python would not protect CGI applications
from contents of the HTTP_PROXY environment variable when based on the
contents of the Proxy header from HTTP requests. A remote attacker
could possibly use this to cause a CGI application to redirect
outgoing HTTP requests. (CVE-2016-1000110)

Insu Yun discovered an integer overflow in the zipimporter module in
Python that could lead to a heap-based overflow. An attacker could use
this to craft a special zip file that when read by Python could
possibly execute arbitrary code. (CVE-2016-5636)

Guido Vranken discovered that the urllib modules in Python did not
properly handle carriage return line feed (CRLF) in headers. A remote
attacker could use this to craft URLs that inject arbitrary HTTP
headers. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04
LTS. (CVE-2016-5699).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.2-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/23");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libpython2.7", pkgver:"2.7.3-0ubuntu3.9")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libpython3.2", pkgver:"3.2.3-0ubuntu3.8")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python2.7", pkgver:"2.7.3-0ubuntu3.9")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python2.7-minimal", pkgver:"2.7.3-0ubuntu3.9")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python3.2", pkgver:"3.2.3-0ubuntu3.8")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python3.2-minimal", pkgver:"3.2.3-0ubuntu3.8")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpython2.7", pkgver:"2.7.6-8ubuntu0.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpython2.7-minimal", pkgver:"2.7.6-8ubuntu0.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpython2.7-stdlib", pkgver:"2.7.6-8ubuntu0.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpython3.4", pkgver:"3.4.3-1ubuntu1~14.04.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpython3.4-minimal", pkgver:"3.4.3-1ubuntu1~14.04.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpython3.4-stdlib", pkgver:"3.4.3-1ubuntu1~14.04.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python2.7", pkgver:"2.7.6-8ubuntu0.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python2.7-minimal", pkgver:"2.7.6-8ubuntu0.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python3.4", pkgver:"3.4.3-1ubuntu1~14.04.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python3.4-minimal", pkgver:"3.4.3-1ubuntu1~14.04.5")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libpython2.7", pkgver:"2.7.12-1ubuntu0~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libpython2.7-minimal", pkgver:"2.7.12-1ubuntu0~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libpython2.7-stdlib", pkgver:"2.7.12-1ubuntu0~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libpython3.5", pkgver:"3.5.2-2ubuntu0~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libpython3.5-minimal", pkgver:"3.5.2-2ubuntu0~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libpython3.5-stdlib", pkgver:"3.5.2-2ubuntu0~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python2.7", pkgver:"2.7.12-1ubuntu0~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python2.7-minimal", pkgver:"2.7.12-1ubuntu0~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python3.5", pkgver:"3.5.2-2ubuntu0~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python3.5-minimal", pkgver:"3.5.2-2ubuntu0~16.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpython2.7 / libpython2.7-minimal / libpython2.7-stdlib / etc");
}
