# This script was automatically generated from Ubuntu Security
# Notice USN-1302-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(57303);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

 script_cve_id("CVE-2011-4077", "CVE-2011-4081", "CVE-2011-4132", "CVE-2011-4326", "CVE-2011-4330");
  script_xref(name:"USN", value:"1302-1");

  script_name(english:"USN-1302-1 : linux-ti-omap4 vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A bug was discovered in the XFS filesystem's handling of pathnames. A
local attacker could exploit this to crash the system, leading to a
denial of service, or gain root privileges. (CVE-2011-4077)

Nick Bowler discovered the kernel GHASH message digest algorithm
incorrectly handled error conditions. A local attacker could exploit
this to cause a kernel oops. (CVE-2011-4081)

A flaw was found in the Journaling Block Device (JBD). A local
attacker able to mount ext3 or ext4 file systems could exploit this
to crash the system, leading to a denial of service. (CVE-2011-4132)

A bug was found in the way headroom check was performed in
udp6_ufo_fragment() function. A remote attacker could use this flaw
to crash the system. (CVE-2011-4326)

Clement Lecigne discovered a bug in the HFS file system bounds
checking. When a malformed HFS file system is mounted a local user
could crash the system or gain root privileges. (CVE-2011-4330)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1302-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/14");
  script_end_attributes();
    
  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright("Ubuntu Security Notice (C) 2011-2012 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include("ubuntu.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Ubuntu/release")) exit(0, "The host is not running Ubuntu.");
if (!get_kb_item("Host/Debian/dpkg-l")) exit(1, "Could not obtain the list of installed packages.");

flag = 0;

if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-903-omap4", pkgver:"2.6.35-903.28")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
