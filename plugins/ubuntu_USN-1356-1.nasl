# This script was automatically generated from Ubuntu Security
# Notice USN-1356-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(57856);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/09/06 20:42:52 $");

 script_cve_id("CVE-2012-0038", "CVE-2012-0044", "CVE-2012-0207");
  script_xref(name:"USN", value:"1356-1");

  script_name(english:"USN-1356-1 : linux-ti-omap4 vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A flaw was discovered in the XFS filesystem. If a local user mounts a
specially crafted XFS image it could potential execute arbitrary code
on the system. (CVE-2012-0038)

Chen Haogang discovered an integer overflow that could result in
memory corruption. A local unprivileged user could use this to crash
the system. (CVE-2012-0044)

A flaw was found in the linux kernels IPv4 IGMP query processing. A
remote attacker could exploit this to cause a denial of service.
(CVE-2012-0207)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1356-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/06");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/07");
  script_end_attributes();
    
  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright("Ubuntu Security Notice (C) 2012 Canonical, Inc. / NASL script (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include("ubuntu.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Ubuntu/release")) exit(0, "The host is not running Ubuntu.");
if (!get_kb_item("Host/Debian/dpkg-l")) exit(1, "Could not obtain the list of installed packages.");

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-1209-omap4", pkgver:"2.6.38-1209.21")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
