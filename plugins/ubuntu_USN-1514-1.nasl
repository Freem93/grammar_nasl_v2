# This script was automatically generated from Ubuntu Security
# Notice USN-1514-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(61506);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

 script_cve_id("CVE-2012-2119", "CVE-2012-2136", "CVE-2012-2137", "CVE-2012-2372", "CVE-2012-2373", "CVE-2012-3364", "CVE-2012-3375", "CVE-2012-3400");
  script_xref(name:"USN", value:"1514-1");

  script_name(english:"USN-1514-1 : linux-ti-omap4 vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A flaw was discovered in the Linux kernel's macvtap device driver,
which is used in KVM (Kernel-based Virtual Machine) to create a
network bridge between host and guest. A privleged user in a guest
could exploit this flaw to crash the host, if the vhost_net module is
loaded with the experimental_zcopytx option enabled. (CVE-2012-2119)

An error was discovered in the Linux kernel's network TUN/TAP device
implementation. A local user with access to the TUN/TAP interface
(which is not available to unprivileged users until granted by a root
user) could exploit this flaw to crash the system or potential gain
administrative privileges. (CVE-2012-2136)

A flaw was found in how the Linux kernel's KVM (Kernel-based Virtual
Machine) subsystem handled MSI (Message Signaled Interrupts). A local
unprivileged user could exploit this flaw to cause a denial of
service or potentially elevate privileges. (CVE-2012-2137)

A flaw was found in the Linux kernel's Reliable Datagram Sockets
(RDS) protocol implementation. A local, unprivileged user could use
this flaw to cause a denial of service. (CVE-2012-2372)

Ulrich Obergfell discovered an error in the Linux kernel's memory
management subsystem on 32 bit PAE systems with more than 4GB of
memory installed. A local unprivileged user could exploit this flaw
to crash the system. (CVE-2012-2373)

Dan Rosenberg discovered flaws in the Linux kernel's NCI (Near Field
Communication Controller Interface). A remote attacker could exploit
these flaws to crash the system or potentially execute privileged
code. (CVE-2012-3364)

A flaw was discovered in the Linux kernel's epoll system call. An
unprivileged local user could use this flaw to crash the system.
(CVE-2012-3375)

Some errors where discovered in the Linux kernel's UDF file system,
which is used to mount some CD-ROMs and DVDs. An unprivileged local
user could use these flaws to crash the system. (CVE-2012-3400)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1514-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/10");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/13");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-1417-omap4", pkgver:"3.2.0-1417.23")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
