#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3016-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91873);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2016-4482", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4913", "CVE-2016-4951", "CVE-2016-4997", "CVE-2016-4998");
  script_osvdb_id(137963, 138383, 138444, 138785, 138920, 140493, 140494);
  script_xref(name:"USN", value:"3016-1");

  script_name(english:"Ubuntu 16.04 LTS : linux vulnerabilities (USN-3016-1)");
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
"Jesse Hertz and Tim Newsham discovered that the Linux netfilter
implementation did not correctly perform validation when handling 32
bit compatibility IPT_SO_SET_REPLACE events on 64 bit platforms. A
local unprivileged attacker could use this to cause a denial of
service (system crash) or execute arbitrary code with administrative
privileges. (CVE-2016-4997)

Kangjie Lu discovered an information leak in the core USB
implementation in the Linux kernel. A local attacker could use this to
obtain potentially sensitive information from kernel memory.
(CVE-2016-4482)

Kangjie Lu discovered an information leak in the timer handling
implementation in the Advanced Linux Sound Architecture (ALSA)
subsystem of the Linux kernel. A local attacker could use this to
obtain potentially sensitive information from kernel memory.
(CVE-2016-4569, CVE-2016-4578)

Kangjie Lu discovered an information leak in the X.25 Call Request
handling in the Linux kernel. A local attacker could use this to
obtain potentially sensitive information from kernel memory.
(CVE-2016-4580)

It was discovered that an information leak exists in the Rock Ridge
implementation in the Linux kernel. A local attacker who is able to
mount a malicious iso9660 file system image could exploit this flaw to
obtain potentially sensitive information from kernel memory.
(CVE-2016-4913)

Baozeng Ding discovered that the Transparent Inter-process
Communication (TIPC) implementation in the Linux kernel did not verify
socket existence before use in some situations. A local attacker could
use this to cause a denial of service (system crash). (CVE-2016-4951)

Jesse Hertz and Tim Newsham discovered that the Linux netfilter
implementation did not correctly perform validation when handling
IPT_SO_SET_REPLACE events. A local unprivileged attacker could use
this to cause a denial of service (system crash) or obtain potentially
sensitive information from kernel memory. (CVE-2016-4998).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-4.4-generic,
linux-image-4.4-generic-lpae and / or linux-image-4.4-lowlatency
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/28");
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
if (! ereg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-28-generic", pkgver:"4.4.0-28.47")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-28-generic-lpae", pkgver:"4.4.0-28.47")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-28-lowlatency", pkgver:"4.4.0-28.47")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.4-generic / linux-image-4.4-generic-lpae / etc");
}
