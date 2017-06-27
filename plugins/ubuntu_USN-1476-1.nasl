# This script was automatically generated from Ubuntu Security
# Notice USN-1476-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(59553);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

 script_cve_id("CVE-2011-4131", "CVE-2012-2121", "CVE-2012-2133", "CVE-2012-2313", "CVE-2012-2319", "CVE-2012-2383", "CVE-2012-2384");
  script_xref(name:"USN", value:"1476-1");

  script_name(english:"USN-1476-1 : linux-ti-omap4 vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Andy Adamson discovered a flaw in the Linux kernel's NFSv4
implementation. A remote NFS server (attacker) could exploit this
flaw to cause a denial of service. (CVE-2011-4131)

A flaw was discovered in the Linux kernel's KVM (kernel virtual
machine). An administrative user in the guest OS could leverage this
flaw to cause a denial of service in the host OS. (CVE-2012-2121)

Schacher Raindel discovered a flaw in the Linux kernel's memory
handling when hugetlb is enabled. An unprivileged local attacker
could exploit this flaw to cause a denial of service and potentially
gain higher privileges. (CVE-2012-2133)

Stephan Mueller reported a flaw in the Linux kernel's dl2k network
driver's handling of ioctls. An unprivileged local user could
leverage this flaw to cause a denial of service. (CVE-2012-2313)

Timo Warns reported multiple flaws in the Linux kernel's hfsplus
filesystem. An unprivileged local user could exploit these flaws to
gain root system priviliges. (CVE-2012-2319)

Xi Wang discovered a flaw in the Linux kernel's i915 graphics driver
handling of cliprect on 32 bit systems. An unprivileged local
attacker could leverage this flaw to cause a denial of service or
potentially gain root privileges. (CVE-2012-2383)

Xi Wang discovered a flaw in the Linux kernel's i915 graphics driver
handling of buffer_count on 32 bit systems. An unprivileged local
attacker could leverage this flaw to cause a denial of service or
potentially gain root privileges. (CVE-2012-2384)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1476-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/15");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/18");
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

if (ubuntu_check(osver:"11.10", pkgname:"linux-image-3.0.0-1211-omap4", pkgver:"3.0.0-1211.23")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
