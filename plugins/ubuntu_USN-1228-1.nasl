# This script was automatically generated from Ubuntu Security
# Notice USN-1228-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(56479);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

  script_cve_id("CVE-2011-1776", "CVE-2011-2213", "CVE-2011-2497", "CVE-2011-2695", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2928", "CVE-2011-3188", "CVE-2011-3191");
  script_xref(name:"USN", value:"1228-1");

  script_name(english:"USN-1228-1 : linux-ti-omap4 vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Timo Warns discovered that the EFI GUID partition table was not
correctly parsed. A physically local attacker that could insert
mountable devices could exploit this to crash the system or possibly
gain root privileges. (CVE-2011-1776)

Dan Rosenberg discovered that the IPv4 diagnostic routines did not
correctly validate certain requests. A local attacker could exploit
this to consume CPU resources, leading to a denial of service.
(CVE-2011-2213)

Dan Rosenberg discovered that the Bluetooth stack incorrectly handled
certain L2CAP requests. If a system was using Bluetooth, a remote
attacker could send specially crafted traffic to crash the system or
gain root privileges. (CVE-2011-2497)

It was discovered that the EXT4 filesystem contained multiple
off-by-one flaws. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2011-2695)

Mauro Carvalho Chehab discovered that the si4713 radio driver did not
correctly check the length of memory copies. If this hardware was
available, a local attacker could exploit this to crash the system or
gain root privileges. (CVE-2011-2700)

Herbert Xu discovered that certain fields were incorrectly handled
when Generic Receive Offload (CVE-2011-2723)

Time Warns discovered that long symlinks were incorrectly handled on
Be filesystems. A local attacker could exploit this with a malformed
Be filesystem and crash the system, leading to a denial of service.
(CVE-2011-2928)

Dan Kaminsky discovered that the kernel incorrectly handled random
sequence number generation. An attacker could use this flaw to
possibly predict sequence numbers and inject packets. (CVE-2011-3188)

Darren Lavender discovered that the CIFS client incorrectly handled
certain large values. A remote attacker with a malicious server could
exploit this to crash the system or possibly execute arbitrary code
as the root user. (CVE-2011-3191)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1228-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/12");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2011/10/13");
  script_end_attributes();
    
  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright("Ubuntu Security Notice (C) 2011 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include("ubuntu.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Ubuntu/release")) exit(0, "The host is not running Ubuntu.");
if (!get_kb_item("Host/Debian/dpkg-l")) exit(1, "Could not obtain the list of installed packages.");

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-1209-omap4", pkgver:"2.6.38-1209.16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
