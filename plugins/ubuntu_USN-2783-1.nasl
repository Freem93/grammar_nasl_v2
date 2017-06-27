#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2783-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86630);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/06/13 13:30:10 $");

  script_cve_id("CVE-2015-5146", "CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5196", "CVE-2015-5219", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7850", "CVE-2015-7852", "CVE-2015-7853", "CVE-2015-7855", "CVE-2015-7871");
  script_osvdb_id(116071, 123974, 126663, 126664, 126665, 126666, 129298, 129299, 129301, 129302, 129304, 129307, 129309, 129310, 129311, 129315);
  script_xref(name:"TRA", value:"TRA-2015-04");
  script_xref(name:"USN", value:"2783-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 / 15.10 : ntp vulnerabilities (USN-2783-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Aleksis Kauppinen discovered that NTP incorrectly handled certain
remote config packets. In a non-default configuration, a remote
authenticated attacker could possibly use this issue to cause NTP to
crash, resulting in a denial of service. (CVE-2015-5146)

Miroslav Lichvar discovered that NTP incorrectly handled logconfig
directives. In a non-default configuration, a remote authenticated
attacker could possibly use this issue to cause NTP to crash,
resulting in a denial of service. (CVE-2015-5194)

Miroslav Lichvar discovered that NTP incorrectly handled certain
statistics types. In a non-default configuration, a remote
authenticated attacker could possibly use this issue to cause NTP to
crash, resulting in a denial of service. (CVE-2015-5195)

Miroslav Lichvar discovered that NTP incorrectly handled certain file
paths. In a non-default configuration, a remote authenticated attacker
could possibly use this issue to cause NTP to crash, resulting in a
denial of service, or overwrite certain files. (CVE-2015-5196,
CVE-2015-7703)

Miroslav Lichvar discovered that NTP incorrectly handled certain
packets. A remote attacker could possibly use this issue to cause NTP
to hang, resulting in a denial of service. (CVE-2015-5219)

Aanchal Malhotra, Isaac E. Cohen, and Sharon Goldberg discovered that
NTP incorrectly handled restarting after hitting a panic threshold. A
remote attacker could possibly use this issue to alter the system time
on clients. (CVE-2015-5300)

It was discovered that NTP incorrectly handled autokey data packets. A
remote attacker could possibly use this issue to cause NTP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2015-7691, CVE-2015-7692, CVE-2015-7702)

It was discovered that NTP incorrectly handled memory when processing
certain autokey messages. A remote attacker could possibly use this
issue to cause NTP to consume memory, resulting in a denial of
service. (CVE-2015-7701)

Aanchal Malhotra, Isaac E. Cohen, and Sharon Goldberg discovered that
NTP incorrectly handled rate limiting. A remote attacker could
possibly use this issue to cause clients to stop updating their clock.
(CVE-2015-7704, CVE-2015-7705)

Yves Younan discovered that NTP incorrectly handled logfile and
keyfile directives. In a non-default configuration, a remote
authenticated attacker could possibly use this issue to cause NTP to
enter a loop, resulting in a denial of service. (CVE-2015-7850)

Yves Younan and Aleksander Nikolich discovered that NTP incorrectly
handled ascii conversion. A remote attacker could possibly use this
issue to cause NTP to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2015-7852)

Yves Younan discovered that NTP incorrectly handled reference clock
memory. A malicious refclock could possibly use this issue to cause
NTP to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2015-7853)

John D 'Doug' Birdwell discovered that NTP incorrectly handled
decoding certain bogus values. An attacker could possibly use this
issue to cause NTP to crash, resulting in a denial of service.
(CVE-2015-7855)

Stephen Gray discovered that NTP incorrectly handled symmetric
association authentication. A remote attacker could use this issue to
possibly bypass authentication and alter the system clock.
(CVE-2015-7871)

In the default installation, attackers would be isolated by the NTP
AppArmor profile.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/28");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"ntp", pkgver:"1:4.2.6.p3+dfsg-1ubuntu3.6")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"ntp", pkgver:"1:4.2.6.p5+dfsg-3ubuntu2.14.04.5")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"ntp", pkgver:"1:4.2.6.p5+dfsg-3ubuntu6.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"ntp", pkgver:"1:4.2.6.p5+dfsg-3ubuntu8.1")) flag++;

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
