# This script was automatically generated from Ubuntu Security
# Notice USN-1383-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(58264);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

 script_cve_id("CVE-2011-1759", "CVE-2011-1927", "CVE-2011-2182", "CVE-2011-2498", "CVE-2011-2518", "CVE-2011-3619");
  script_xref(name:"USN", value:"1383-1");

  script_name(english:"USN-1383-1 : linux-ti-omap4 vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Aristide Fattori and Roberto Paleari reported a flaw in the Linux
kernel's handling of IPv4 icmp packets. A remote user could exploit
this to cause a denial of service. (CVE-2011-1927)

Dan Rosenberg reported an error in the old ABI compatibility layer of
ARM kernels. A local attacker could exploit this flaw to cause a
denial of service or gain root privileges. (CVE-2011-1759)

Ben Hutchings reported a flaw in the kernel's handling of corrupt LDM
partitions. A local user could exploit this to cause a denial of
service or escalate privileges. (CVE-2011-2182)

The linux kernel did not properly account for PTE pages when deciding
which task to kill in out of memory conditions. A local, unprivileged
could exploit this flaw to cause a denial of service. (CVE-2011-2498)

A flaw was discovered in the TOMOYO LSM's handling of mount system
calls. An unprivileged user could oops the system causing a denial of
service. (CVE-2011-2518)

A flaw was discovered in the Linux kernel's AppArmor security
interface when invalid information was written to it. An unprivileged
local user could use this to cause a denial of service on the system.
(CVE-2011-3619)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1383-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/06");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/07");
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

if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-1209-omap4", pkgver:"2.6.38-1209.22")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
