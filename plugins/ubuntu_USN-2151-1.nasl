#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2151-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73148);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/26 16:22:49 $");

  script_cve_id("CVE-2014-1493", "CVE-2014-1497", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514");
  script_bugtraq_id(66425);
  script_osvdb_id(103268, 104590, 104591, 104592, 104593, 104594, 104621, 104622, 104629, 104631);
  script_xref(name:"USN", value:"2151-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.10 : thunderbird vulnerabilities (USN-2151-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Benoit Jacob, Olli Pettay, Jan Varga, Jan de Mooij, Jesse Ruderman,
Dan Gohman and Christoph Diehl discovered multiple memory safety
issues in Thunderbird. If a user were tricked in to opening a
specially crafted message with scripting enabled, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user
invoking Thunderbird. (CVE-2014-1493)

Atte Kettunen discovered an out-of-bounds read during WAV file
decoding. If a user had enabled audio, an attacker could potentially
exploit this to cause a denial of service via application crash.
(CVE-2014-1497)

Robert O'Callahan discovered a mechanism for timing attacks involving
SVG filters and displacements input to feDisplacementMap. If a user
had enabled scripting, an attacker could potentially exploit this to
steal confidential information across domains. (CVE-2014-1505)

Tyson Smith and Jesse Schwartzentruber discovered an out-of-bounds
read during polygon rendering in MathML. If a user had enabled
scripting, an attacker could potentially exploit this to steal
confidential information across domains. (CVE-2014-1508)

John Thomson discovered a memory corruption bug in the Cairo graphics
library. If a user had a malicious extension installed, an attacker
could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of
the user invoking Thunderbird. (CVE-2014-1509)

Mariusz Mlynski discovered that web content could open a chrome
privileged page and bypass the popup blocker in some circumstances. If
a user had enabled scripting, an attacker could potentially exploit
this to execute arbitrary code with the privileges of the user
invoking Thunderbird. (CVE-2014-1510, CVE-2014-1511)

It was discovered that memory pressure during garbage collection
resulted in memory corruption in some circumstances. If a user had
enabled scripting, an attacker could potentially exploit this to cause
a denial of service via application crash or execute arbitrary code
with the privileges of the user invoking Thunderbird. (CVE-2014-1512)

Juri Aedla discovered out-of-bounds reads and writes with
TypedArrayObject in some circumstances. If a user had enabled
scripting, an attacker could potentially exploit this to cause a
denial of service via application crash or execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2014-1513)

George Hotz discovered an out-of-bounds write with TypedArrayObject.
If a user had enabled scripting, an attacker could potentially exploit
this to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2014-1514).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox WebIDL Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|12\.10|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"thunderbird", pkgver:"1:24.4.0+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"thunderbird", pkgver:"1:24.4.0+build1-0ubuntu0.12.10.1")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"thunderbird", pkgver:"1:24.4.0+build1-0ubuntu0.13.10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
