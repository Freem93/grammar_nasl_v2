#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1211-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56256);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/26 14:05:57 $");

  script_cve_id("CVE-2011-1020", "CVE-2011-1493", "CVE-2011-1833", "CVE-2011-2492", "CVE-2011-2689", "CVE-2011-2699", "CVE-2011-2918", "CVE-2011-3637", "CVE-2011-4914");
  script_bugtraq_id(46567, 46935, 48441, 48677, 48802, 49152);
  script_xref(name:"USN", value:"1211-1");

  script_name(english:"Ubuntu 11.04 : linux vulnerabilities (USN-1211-1)");
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
"It was discovered that the /proc filesystem did not correctly handle
permission changes when programs executed. A local attacker could hold
open files to examine details about programs running with higher
privileges, potentially increasing the chances of exploiting
additional vulnerabilities. (CVE-2011-1020)

Dan Rosenberg discovered that the X.25 Rose network stack did not
correctly handle certain fields. If a system was running with Rose
enabled, a remote attacker could send specially crafted traffic to
gain root privileges. (CVE-2011-1493)

Vasiliy Kulikov and Dan Rosenberg discovered that ecryptfs did not
correctly check the origin of mount points. A local attacker could
exploit this to trick the system into unmounting arbitrary mount
points, leading to a denial of service. (CVE-2011-1833)

It was discovered that Bluetooth l2cap and rfcomm did not correctly
initialize structures. A local attacker could exploit this to read
portions of the kernel stack, leading to a loss of privacy.
(CVE-2011-2492)

It was discovered that GFS2 did not correctly check block sizes. A
local attacker could exploit this to crash the system, leading to a
denial of service. (CVE-2011-2689)

Fernando Gont discovered that the IPv6 stack used predictable fragment
identification numbers. A remote attacker could exploit this to
exhaust network resources, leading to a denial of service.
(CVE-2011-2699)

The performance counter subsystem did not correctly handle certain
counters. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-2918)

A flaw was found in the Linux kernel's /proc/*/*map* interface. A
local, unprivileged user could exploit this flaw to cause a denial of
service. (CVE-2011-3637)

Ben Hutchings discovered several flaws in the Linux Rose (X.25 PLP)
layer. A local user or a remote user on an X.25 network could exploit
these flaws to execute arbitrary code as root. (CVE-2011-4914).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-11-generic", pkgver:"2.6.38-11.50")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-11-generic-pae", pkgver:"2.6.38-11.50")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-11-server", pkgver:"2.6.38-11.50")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-11-versatile", pkgver:"2.6.38-11.50")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-11-virtual", pkgver:"2.6.38-11.50")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-generic / linux-image-2.6-generic-pae / etc");
}
