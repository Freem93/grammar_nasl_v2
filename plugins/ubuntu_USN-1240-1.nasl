#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1240-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56639);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/03/09 00:53:51 $");

  script_cve_id("CVE-2011-1576", "CVE-2011-1833", "CVE-2011-2494", "CVE-2011-2495", "CVE-2011-2497", "CVE-2011-2695", "CVE-2011-2699", "CVE-2011-2905", "CVE-2011-2928", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3353", "CVE-2011-3593");
  script_xref(name:"USN", value:"1240-1");

  script_name(english:"Ubuntu 10.04 LTS : linux-mvl-dove vulnerabilities (USN-1240-1)");
  script_summary(english:"Checks dpkg output for updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ryan Sweat discovered that the kernel incorrectly handled certain VLAN
packets. On some systems, a remote attacker could send specially
crafted traffic to crash the system, leading to a denial of service.
(CVE-2011-1576)

Vasiliy Kulikov and Dan Rosenberg discovered that ecryptfs did not
correctly check the origin of mount points. A local attacker could
exploit this to trick the system into unmounting arbitrary mount
points, leading to a denial of service. (CVE-2011-1833)

Vasiliy Kulikov discovered that taskstats did not enforce access
restrictions. A local attacker could exploit this to read certain
information, leading to a loss of privacy. (CVE-2011-2494)

Vasiliy Kulikov discovered that /proc/PID/io did not enforce access
restrictions. A local attacker could exploit this to read certain
information, leading to a loss of privacy. (CVE-2011-2495)

Dan Rosenberg discovered that the Bluetooth stack incorrectly handled
certain L2CAP requests. If a system was using Bluetooth, a remote
attacker could send specially crafted traffic to crash the system or
gain root privileges. (CVE-2011-2497)

It was discovered that the EXT4 filesystem contained multiple
off-by-one flaws. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2011-2695)

Fernando Gont discovered that the IPv6 stack used predictable fragment
identification numbers. A remote attacker could exploit this to
exhaust network resources, leading to a denial of service.
(CVE-2011-2699)

Christian Ohm discovered that the perf command looks for configuration
files in the current directory. If a privileged user were tricked into
running perf in a directory containing a malicious configuration file,
an attacker could run arbitrary commands and possibly gain privileges.
(CVE-2011-2905)

Time Warns discovered that long symlinks were incorrectly handled on
Be filesystems. A local attacker could exploit this with a malformed
Be filesystem and crash the system, leading to a denial of service.
(CVE-2011-2928)

Dan Kaminsky discovered that the kernel incorrectly handled random
sequence number generation. An attacker could use this flaw to
possibly predict sequence numbers and inject packets. (CVE-2011-3188)

Darren Lavender discovered that the CIFS client incorrectly handled
certain large values. A remote attacker with a malicious server could
exploit this to crash the system or possibly execute arbitrary code as
the root user. (CVE-2011-3191)

Han-Wen Nienhuys reported a flaw in the FUSE kernel module. A local
user who can mount a FUSE file system could cause a denial of service.
(CVE-2011-3353)

Gideon Naim discovered a flaw in the Linux kernel's handling VLAN 0
frames. An attacker on the local network could exploit this flaw to
cause a denial of service. (CVE-2011-3593)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected linux-image-2.6.32-219-dove package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2013 Canonical, Inc. / NASL script (C) 2011-2013 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}



include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/Ubuntu/release") ) audit(AUDIT_OS_NOT, "Ubuntu");
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-219-dove", pkgver:"2.6.32-219.37")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
