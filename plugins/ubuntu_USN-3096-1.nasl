#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3096-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93896);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2017/04/21 13:44:39 $");

  script_cve_id("CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8158", "CVE-2016-0727", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1550", "CVE-2016-2516", "CVE-2016-2518", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956");
  script_osvdb_id(133378, 133382, 133383, 133384, 133385, 133386, 133387, 133388, 133391, 133414, 133516, 137711, 137712, 137714, 137732, 137734, 139280, 139281, 139282);
  script_xref(name:"USN", value:"3096-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS : ntp vulnerabilities (USN-3096-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Aanchal Malhotra discovered that NTP incorrectly handled authenticated
broadcast mode. A remote attacker could use this issue to perform a
replay attack. (CVE-2015-7973)

Matt Street discovered that NTP incorrectly verified peer associations
of symmetric keys. A remote attacker could use this issue to perform
an impersonation attack. (CVE-2015-7974)

Jonathan Gardner discovered that the NTP ntpq utility incorrectly
handled memory. An attacker could possibly use this issue to cause
ntpq to crash, resulting in a denial of service. This issue only
affected Ubuntu 16.04 LTS. (CVE-2015-7975)

Jonathan Gardner discovered that the NTP ntpq utility incorrectly
handled dangerous characters in filenames. An attacker could possibly
use this issue to overwrite arbitrary files. (CVE-2015-7976)

Stephen Gray discovered that NTP incorrectly handled large restrict
lists. An attacker could use this issue to cause NTP to crash,
resulting in a denial of service. (CVE-2015-7977, CVE-2015-7978)

Aanchal Malhotra discovered that NTP incorrectly handled authenticated
broadcast mode. A remote attacker could use this issue to cause NTP to
crash, resulting in a denial of service. (CVE-2015-7979)

Jonathan Gardner discovered that NTP incorrectly handled origin
timestamp checks. A remote attacker could use this issue to spoof peer
servers. (CVE-2015-8138)

Jonathan Gardner discovered that the NTP ntpq utility did not properly
handle certain incorrect values. An attacker could possibly use this
issue to cause ntpq to hang, resulting in a denial of service.
(CVE-2015-8158)

It was discovered that the NTP cronjob incorrectly cleaned up the
statistics directory. A local attacker could possibly use this to
escalate privileges. (CVE-2016-0727)

Stephen Gray and Matthew Van Gundy discovered that NTP incorrectly
validated crypto-NAKs. A remote attacker could possibly use this issue
to prevent clients from synchronizing. (CVE-2016-1547)

Miroslav Lichvar and Jonathan Gardner discovered that NTP incorrectly
handled switching to interleaved symmetric mode. A remote attacker
could possibly use this issue to prevent clients from synchronizing.
(CVE-2016-1548)

Matthew Van Gundy, Stephen Gray and Loganaden Velvindron discovered
that NTP incorrectly handled message authentication. A remote attacker
could possibly use this issue to recover the message digest key.
(CVE-2016-1550)

Yihan Lian discovered that NTP incorrectly handled duplicate IPs on
unconfig directives. An authenticated remote attacker could possibly
use this issue to cause NTP to crash, resulting in a denial of
service. (CVE-2016-2516)

Yihan Lian discovered that NTP incorrectly handled certail peer
associations. A remote attacker could possibly use this issue to cause
NTP to crash, resulting in a denial of service. (CVE-2016-2518)

Jakub Prokes discovered that NTP incorrectly handled certain spoofed
packets. A remote attacker could possibly use this issue to cause a
denial of service. (CVE-2016-4954)

Miroslav Lichvar discovered that NTP incorrectly handled certain
packets when autokey is enabled. A remote attacker could possibly use
this issue to cause a denial of service. (CVE-2016-4955)

Miroslav Lichvar discovered that NTP incorrectly handled certain
spoofed broadcast packets. A remote attacker could possibly use this
issue to cause a denial of service. (CVE-2016-4956)

In the default installation, attackers would be isolated by the NTP
AppArmor profile.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:X/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016-2017 Canonical, Inc. / NASL script (C) 2016-2017 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"12.04", pkgname:"ntp", pkgver:"1:4.2.6.p3+dfsg-1ubuntu3.11")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"ntp", pkgver:"1:4.2.6.p5+dfsg-3ubuntu2.14.04.10")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"ntp", pkgver:"1:4.2.8p4+dfsg-3ubuntu5.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
