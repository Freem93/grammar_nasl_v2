# This script was automatically generated from Ubuntu Security
# Notice USN-1364-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(57938);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

 script_cve_id("CVE-2012-0038", "CVE-2012-0055", "CVE-2012-0056", "CVE-2012-0207");
  script_xref(name:"USN", value:"1364-1");

  script_name(english:"USN-1364-1 : linux-ti-omap4 vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A flaw was discovered in the XFS filesystem. If a local user mounts a
specially crafted XFS image it could potential execute arbitrary code
on the system. (CVE-2012-0038)

Andy Whitcroft discovered a that the Overlayfs filesystem was not
doing the extended permission checks needed by cgroups and Linux
Security Modules (LSMs). A local user could exploit this to by-pass
security policy and access files that should not be accessible.
(CVE-2012-0055)

Juri Aedla discovered that the kernel incorrectly handled
/proc/<pid>/mem permissions. A local attacker could exploit this and
gain root privileges. (CVE-2012-0056)

A flaw was found in the linux kernels IPv4 IGMP query processing. A
remote attacker could exploit this to cause a denial of service.
(CVE-2012-0207)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1364-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/13");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");
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

if (ubuntu_check(osver:"11.10", pkgname:"linux-image-3.0.0-1207-omap4", pkgver:"3.0.0-1207.16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
