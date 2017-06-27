# This script was automatically generated from Ubuntu Security
# Notice USN-1577-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(62238);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

 script_cve_id("CVE-2012-2121", "CVE-2012-3412", "CVE-2012-3430", "CVE-2012-3511");
  script_xref(name:"USN", value:"1577-1");

  script_name(english:"USN-1577-1 : linux-ti-omap4 vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A flaw was discovered in the Linux kernel's KVM (kernel virtual
machine). An administrative user in the guest OS could leverage this
flaw to cause a denial of service in the host OS. (CVE-2012-2121)

Ben Hutchings reported a flaw in the Linux kernel with some network
drivers that support TSO (TCP segment offload). A local or peer user
could exploit this flaw to to cause a denial of service.
(CVE-2012-3412)

Jay Fenlason and Doug Ledford discovered a bug in the Linux kernel
implementation of RDS sockets. A local unprivileged user could
potentially use this flaw to read privileged information from the
kernel. (CVE-2012-3430)

A flaw was discovered in the madvise feature of the Linux kernel's
memory subsystem. An unprivileged local use could exploit the flaw to
cause a denial of service (crash the system). (CVE-2012-3511)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1577-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/24");
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

if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-1209-omap4", pkgver:"2.6.38-1209.26")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
