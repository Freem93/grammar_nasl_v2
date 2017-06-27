# This script was automatically generated from Ubuntu Security
# Notice USN-1394-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(58289);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

 script_cve_id("CVE-2010-4250", "CVE-2010-4650", "CVE-2011-0006", "CVE-2011-0716", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1759", "CVE-2011-1927", "CVE-2011-2182", "CVE-2011-3619", "CVE-2011-4621", "CVE-2012-0038", "CVE-2012-0044");
  script_xref(name:"USN", value:"1394-1");

  script_name(english:"USN-1394-1 : Linux kernel (OMAP4) vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Aristide Fattori and Roberto Paleari reported a flaw in the Linux
kernel's handling of IPv4 icmp packets. A remote user could exploit
this to cause a denial of service. (CVE-2011-1927)

Vegard Nossum discovered a leak in the kernel's inotify_init() system
call. A local, unprivileged user could exploit this to cause a denial
of service. (CVE-2010-4250)

An error was discovered in the kernel's handling of CUSE (Character
device in Userspace). A local attacker might exploit this flaw to
escalate privilege, if access to /dev/cuse has been modified to allow
non-root users. (CVE-2010-4650)

A flaw was found in the kernel's Integrity Measurement Architecture
(IMA). Changes made by an attacker might not be discovered by IMA, if
SELinux was disabled, and a new IMA rule was loaded. (CVE-2011-0006)

A flaw was found in the Linux Ethernet bridge's handling of IGMP
(Internet Group Management Protocol) packets. An unprivileged local
user could exploit this flaw to crash the system. (CVE-2011-0716)

Dan Rosenberg reported errors in the OSS (Open Sound System) MIDI
interface. A local attacker on non-x86 systems might be able to cause
a denial of service. (CVE-2011-1476)

Dan Rosenberg reported errors in the kernel's OSS (Open Sound System)
driver for Yamaha FM synthesizer chips. A local user can exploit this
to cause memory corruption, causing a denial of service or privilege
escalation. (CVE-2011-1477)

Dan Rosenberg reported an error in the old ABI compatibility layer of
ARM kernels. A local attacker could exploit this flaw to cause a
denial of service or gain root privileges. (CVE-2011-1759)

Ben Hutchings reported a flaw in the kernel's handling of corrupt LDM
partitions. A local user could exploit this to cause a denial of
service or escalate privileges. (CVE-2011-2182)

A flaw was discovered in the Linux kernel's AppArmor security
interface when invalid information was written to it. An unprivileged
local user could use this to cause a denial of service on the system.
(CVE-2011-3619)

It was discovered that some import kernel threads can be blocked by a
user level process. An unprivileged local user could exploit this
flaw to cause a denial of service. (CVE-2011-4621)

A flaw was discovered in the XFS filesystem. If a local user mounts a
specially crafted XFS image it could potential execute arbitrary code
on the system. (CVE-2012-0038)

Chen Haogang discovered an integer overflow that could result in
memory corruption. A local unprivileged user could use this to crash
the system. (CVE-2012-0044)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1394-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/08");
  script_end_attributes();
    
  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright("Ubuntu Security Notice (C) 2012 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include("ubuntu.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Ubuntu/release")) exit(0, "The host is not running Ubuntu.");
if (!get_kb_item("Host/Debian/dpkg-l")) exit(1, "Could not obtain the list of installed packages.");

flag = 0;

if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-903-omap4", pkgver:"2.6.35-903.32")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
