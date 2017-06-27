#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3177-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96978);
  script_version("$Revision: 3.11 $");
  script_cvs_date("$Date: 2017/04/15 13:47:38 $");

  script_cve_id("CVE-2016-0762", "CVE-2016-5018", "CVE-2016-5388", "CVE-2016-6794", "CVE-2016-6796", "CVE-2016-6797", "CVE-2016-6816", "CVE-2016-8735", "CVE-2016-8745", "CVE-2016-9774", "CVE-2016-9775");
  script_osvdb_id(141670, 144341, 146348, 146354, 146355, 146356, 146357, 147617, 147619, 148477);
  script_xref(name:"USN", value:"3177-2");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS : tomcat6, tomcat7 regression (USN-3177-2) (httpoxy)");
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
"USN-3177-1 fixed vulnerabilities in Tomcat. The update introduced a
regression in environments where Tomcat is started with a security
manager. This update fixes the problem.

We apologize for the inconvenience.

It was discovered that the Tomcat realm implementations incorrectly
handled passwords when a username didn't exist. A remote attacker
could possibly use this issue to enumerate usernames. This issue only
applied to Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-0762)

Alvaro Munoz and Alexander Mirosh discovered that Tomcat
incorrectly limited use of a certain utility method. A
malicious application could possibly use this to bypass
Security Manager restrictions. This issue only applied to
Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-5018)

It was discovered that Tomcat did not protect applications
from untrusted data in the HTTP_PROXY environment variable.
A remote attacker could possibly use this issue to redirect
outbound traffic to an arbitrary proxy server. This issue
only applied to Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and
Ubuntu 16.04 LTS. (CVE-2016-5388)

It was discovered that Tomcat incorrectly controlled reading
system properties. A malicious application could possibly
use this to bypass Security Manager restrictions. This issue
only applied to Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and
Ubuntu 16.04 LTS. (CVE-2016-6794)

It was discovered that Tomcat incorrectly controlled certain
configuration parameters. A malicious application could
possibly use this to bypass Security Manager restrictions.
This issue only applied to Ubuntu 12.04 LTS, Ubuntu 14.04
LTS and Ubuntu 16.04 LTS. (CVE-2016-6796)

It was discovered that Tomcat incorrectly limited access to
global JNDI resources. A malicious application could use
this to access any global JNDI resource without an explicit
ResourceLink. This issue only applied to Ubuntu 12.04 LTS,
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-6797)

Regis Leroy discovered that Tomcat incorrectly filtered
certain invalid characters from the HTTP request line. A
remote attacker could possibly use this issue to inject data
into HTTP responses. (CVE-2016-6816)

Pierre Ernst discovered that the Tomcat
JmxRemoteLifecycleListener did not implement a recommended
fix. A remote attacker could possibly use this issue to
execute arbitrary code. (CVE-2016-8735)

It was discovered that Tomcat incorrectly handled error
handling in the send file code. A remote attacker could
possibly use this issue to access information from other
requests. (CVE-2016-8745)

Paul Szabo discovered that the Tomcat package incorrectly
handled upgrades and removals. A local attacker could
possibly use this issue to obtain root privileges.
(CVE-2016-9774, CVE-2016-9775).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat6-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat7-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libtomcat6-java", pkgver:"6.0.35-1ubuntu3.10")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"tomcat6", pkgver:"6.0.35-1ubuntu3.10")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libtomcat7-java", pkgver:"7.0.52-1ubuntu0.9")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"tomcat7", pkgver:"7.0.52-1ubuntu0.9")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtomcat6-java / libtomcat7-java / tomcat6 / tomcat7");
}
