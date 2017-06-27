# This script was automatically generated from Ubuntu Security
# Notice USN-1119-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(55077);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

  script_cve_id("CVE-2010-2954", "CVE-2010-2955", "CVE-2010-2960", "CVE-2010-2962", "CVE-2010-2963", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3081", "CVE-2010-3437", "CVE-2010-3705", "CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-3861", "CVE-2010-3865", "CVE-2010-3873", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3904", "CVE-2010-4072", "CVE-2010-4079", "CVE-2010-4158", "CVE-2010-4164", "CVE-2010-4165", "CVE-2010-4249", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4527", "CVE-2010-4529");
  script_xref(name:"USN", value:"1119-1");

  script_name(english:"USN-1119-1 : linux-ti-omap4 vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Dan Rosenberg discovered that the RDS network protocol did not
correctly check certain parameters. A local attacker could exploit
this gain root privileges. (CVE-2010-3904)

Nelson Elhage discovered several problems with the Acorn Econet
protocol driver. A local user could cause a denial of service via a
NULL pointer dereference, escalate privileges by overflowing the
kernel stack, and assign Econet addresses to arbitrary interfaces.
(CVE-2010-3848, CVE-2010-3849, CVE-2010-3850)

Ben Hawkes discovered that the Linux kernel did not correctly
validate memory ranges on 64bit kernels when allocating memory on
behalf of 32bit system calls. On a 64bit system, a local attacker
could perform malicious multicast getsockopt calls to gain root
privileges. (CVE-2010-3081)

Tavis Ormandy discovered that the IRDA subsystem did not correctly
shut down. A local attacker could exploit this to cause the system to
crash or possibly gain root privileges. (CVE-2010-2954)

Brad Spengler discovered that the wireless extensions did not
correctly validate certain request sizes. A local attacker could
exploit this to read portions of kernel memory, leading to a loss of
privacy. (CVE-2010-2955)

Tavis Ormandy discovered that the session keyring did not correctly
check for its parent. On systems without a default session keyring, a
local attacker could exploit this to crash the system, leading to a
denial of service. (CVE-2010-2960)

Kees Cook discovered that the Intel i915 graphics driver did not
correctly validate memory regions. A local attacker with access to
the video card could read and write arbitrary kernel memory to gain
root privileges. (CVE-2010-2962)

Kees Cook discovered that the V4L1 32bit compat interface did not
correctly validate certain parameters. A local attacker on a 64bit
system with access to a video device could exploit this to gain root
privileges. (CVE-2010-2963)

Robert Swiecki discovered that ftrace did not correctly handle
mutexes. A local attacker could exploit this to crash the kernel,
leading to a denial of service. (CVE-2010-3079)

Tavis Ormandy discovered that the OSS sequencer device did not
correctly shut down. A local attacker could exploit this to crash the
system or possibly gain root privileges. (CVE-2010-3080)

Dan Rosenberg discovered that the CD driver did not correctly check
parameters. A local attacker could exploit this to read arbitrary
kernel memory, leading to a loss of privacy. (CVE-2010-3437)

Dan Rosenberg discovered that SCTP did not correctly handle HMAC
calculations. A remote attacker could send specially crafted traffic
that would crash the system, leading to a denial of service.
(CVE-2010-3705)

Kees Cook discovered that the ethtool interface did not correctly
clear kernel memory. A local attacker could read kernel heap memory,
leading to a loss of privacy. (CVE-2010-3861)

Thomas Pollet discovered that the RDS network protocol did not check
certain iovec buffers. A local attacker could exploit this to crash
the system or possibly execute arbitrary code as the root user.
(CVE-2010-3865)

Dan Rosenberg discovered that the Linux kernel X.25 implementation
incorrectly parsed facilities. A remote attacker could exploit this
to crash the kernel, leading to a denial of service. (CVE-2010-3873)

Vasiliy Kulikov discovered that the Linux kernel X.25 implementation
did not correctly clear kernel memory. A local attacker could exploit
this to read kernel stack memory, leading to a loss of privacy.
(CVE-2010-3875)

Vasiliy Kulikov discovered that the Linux kernel sockets
implementation did not properly initialize certain structures. A
local attacker could exploit this to read kernel stack memory,
leading to a loss of privacy. (CVE-2010-3876)

Vasiliy Kulikov discovered that the TIPC interface did not correctly
initialize certain structures. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-3877)

Kees Cook and Vasiliy Kulikov discovered that the shm interface did
not clear kernel memory correctly. A local attacker could exploit
this to read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4072)

Dan Rosenberg discovered that the ivtv V4L driver did not correctly
initialize certian structures. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4079)

Dan Rosenberg discovered that the socket filters did not correctly
initialize structure memory. A local attacker could create malicious
filters to read portions of kernel stack memory, leading to a loss of
privacy. (CVE-2010-4158)

Dan Rosenberg discovered multiple flaws in the X.25 facilities
parsing. If a system was using X.25, a remote attacker could exploit
this to crash the system, leading to a denial of service.
(CVE-2010-4164)

Steve Chen discovered that setsockopt did not correctly check MSS
values. A local attacker could make a specially crafted socket call
to crash the system, leading to a denial of service. (CVE-2010-4165)

Vegard Nossum discovered that memory garbage collection was not
handled correctly for active sockets. A local attacker could exploit
this to allocate all available kernel memory, leading to a denial of
service. (CVE-2010-4249)

Nelson Elhage discovered that Econet did not correctly handle AUN
packets over UDP. A local attacker could send specially crafted
traffic to crash the system, leading to a denial of service.
(CVE-2010-4342)

Tavis Ormandy discovered that the install_special_mapping function
could bypass the mmap_min_addr restriction. A local attacker could
exploit this to mmap 4096 bytes below the mmap_min_addr area,
possibly improving the chances of performing NULL pointer dereference
attacks. (CVE-2010-4346)

Dan Rosenberg discovered that the OSS subsystem did not handle name
termination correctly. A local attacker could exploit this crash the
system or gain root privileges. (CVE-2010-4527)

Dan Rosenberg discovered that IRDA did not correctly check the size
of buffers. On non-x86 systems, a local attacker could exploit this
to read kernel heap memory, leading to a loss of privacy.
(CVE-2010-4529)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1119-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/20");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2011/06/13");
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

if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-903-omap4", pkgver:"2.6.35-903.22")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
