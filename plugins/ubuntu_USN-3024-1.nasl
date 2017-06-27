#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3024-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91954);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5346", "CVE-2015-5351", "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763", "CVE-2016-3092");
  script_osvdb_id(134823, 134824, 134825, 134826, 134827, 134828, 134829, 140354);
  script_xref(name:"USN", value:"3024-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 / 16.04 LTS : tomcat6, tomcat7 vulnerabilities (USN-3024-1)");
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
"It was discovered that Tomcat incorrectly handled pathnames used by
web applications in a getResource, getResourceAsStream, or
getResourcePaths call. A remote attacker could use this issue to
possibly list a parent directory . This issue only affected Ubuntu
12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-5174)

It was discovered that the Tomcat mapper component incorrectly handled
redirects. A remote attacker could use this issue to determine the
existence of a directory. This issue only affected Ubuntu 12.04 LTS,
Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-5345)

It was discovered that Tomcat incorrectly handled different session
settings when multiple versions of the same web application was
deployed. A remote attacker could possibly use this issue to hijack
web sessions. This issue only affected Ubuntu 14.04 LTS and Ubuntu
15.10. (CVE-2015-5346)

It was discovered that the Tomcat Manager and Host Manager
applications incorrectly handled new requests. A remote attacker could
possibly use this issue to bypass CSRF protection mechanisms. This
issue only affected Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-5351)

It was discovered that Tomcat did not place StatusManagerServlet on
the RestrictedServlets list. A remote attacker could possibly use this
issue to read arbitrary HTTP requests, including session ID values.
This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu
15.10. (CVE-2016-0706)

It was discovered that the Tomcat session-persistence implementation
incorrectly handled session attributes. A remote attacker could
possibly use this issue to execute arbitrary code in a privileged
context. This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS
and Ubuntu 15.10. (CVE-2016-0714)

It was discovered that the Tomcat setGlobalContext method incorrectly
checked if callers were authorized. A remote attacker could possibly
use this issue to read or wite to arbitrary application data, or cause
a denial of service. This issue only affected Ubuntu 12.04 LTS, Ubuntu
14.04 LTS and Ubuntu 15.10. (CVE-2016-0763)

It was discovered that the Tomcat Fileupload library incorrectly
handled certain upload requests. A remote attacker could possibly use
this issue to cause a denial of service. (CVE-2016-3092).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtomcat6-java and / or libtomcat7-java packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat6-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat7-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/06");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.10|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.10 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libtomcat6-java", pkgver:"6.0.35-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libtomcat7-java", pkgver:"7.0.52-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libtomcat7-java", pkgver:"7.0.64-1ubuntu0.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libtomcat7-java", pkgver:"7.0.68-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtomcat6-java / libtomcat7-java");
}
