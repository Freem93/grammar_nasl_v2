#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1000-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50044);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/10/26 14:05:56 $");

  script_cve_id("CVE-2009-4895", "CVE-2010-2066", "CVE-2010-2226", "CVE-2010-2248", "CVE-2010-2478", "CVE-2010-2495", "CVE-2010-2521", "CVE-2010-2524", "CVE-2010-2525", "CVE-2010-2798", "CVE-2010-2942", "CVE-2010-2946", "CVE-2010-2954", "CVE-2010-2955", "CVE-2010-2960", "CVE-2010-2963", "CVE-2010-3015", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3080", "CVE-2010-3084", "CVE-2010-3310", "CVE-2010-3432", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3477", "CVE-2010-3705", "CVE-2010-3904");
  script_bugtraq_id(40867, 40920, 41077, 41223, 41466, 41904, 42124, 42242, 42249, 42477, 42529, 42589, 42885, 42900, 42932, 43022, 43062, 43098, 43353, 43368, 43480, 43551, 43701, 43787, 44219);
  script_osvdb_id(67243, 67244, 67327, 67881, 68163, 68177, 68289, 68370, 69117, 69424);
  script_xref(name:"USN", value:"1000-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.04 / 9.10 / 10.04 LTS / 10.10 : linux, linux-ec2, linux-source-2.6.15 vulnerabilities (USN-1000-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dan Rosenberg discovered that the RDS network protocol did not
correctly check certain parameters. A local attacker could exploit
this gain root privileges. (CVE-2010-3904)

Al Viro discovered a race condition in the TTY driver. A local
attacker could exploit this to crash the system, leading to a denial
of service. (CVE-2009-4895)

Dan Rosenberg discovered that the MOVE_EXT ext4 ioctl did not
correctly check file permissions. A local attacker could overwrite
append-only files, leading to potential data loss. (CVE-2010-2066)

Dan Rosenberg discovered that the swapexit xfs ioctl did not correctly
check file permissions. A local attacker could exploit this to read
from write-only files, leading to a loss of privacy. (CVE-2010-2226)

Suresh Jayaraman discovered that CIFS did not correctly validate
certain response packats. A remote attacker could send specially
crafted traffic that would crash the system, leading to a denial of
service. (CVE-2010-2248)

Ben Hutchings discovered that the ethtool interface did not correctly
check certain sizes. A local attacker could perform malicious ioctl
calls that could crash the system, leading to a denial of service.
(CVE-2010-2478, CVE-2010-3084)

James Chapman discovered that L2TP did not correctly evaluate checksum
capabilities. If an attacker could make malicious routing changes,
they could crash the system, leading to a denial of service.
(CVE-2010-2495)

Neil Brown discovered that NFSv4 did not correctly check certain write
requests. A remote attacker could send specially crafted traffic that
could crash the system or possibly gain root privileges.
(CVE-2010-2521)

David Howells discovered that DNS resolution in CIFS could be spoofed.
A local attacker could exploit this to control DNS replies, leading to
a loss of privacy and possible privilege escalation. (CVE-2010-2524)

Dan Rosenberg discovered a flaw in gfs2 file system's handling of acls
(access control lists). An unprivileged local attacker could exploit
this flaw to gain access or execute any file stored in the gfs2 file
system. (CVE-2010-2525)

Bob Peterson discovered that GFS2 rename operations did not correctly
validate certain sizes. A local attacker could exploit this to crash
the system, leading to a denial of service. (CVE-2010-2798)

Eric Dumazet discovered that many network functions could leak kernel
stack contents. A local attacker could exploit this to read portions
of kernel memory, leading to a loss of privacy. (CVE-2010-2942,
CVE-2010-3477)

Sergey Vlasov discovered that JFS did not correctly handle certain
extended attributes. A local attacker could bypass namespace access
rules, leading to a loss of privacy. (CVE-2010-2946)

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

Kees Cook discovered that the V4L1 32bit compat interface did not
correctly validate certain parameters. A local attacker on a 64bit
system with access to a video device could exploit this to gain root
privileges. (CVE-2010-2963)

Toshiyuki Okajima discovered that ext4 did not correctly check certain
parameters. A local attacker could exploit this to crash the system or
overwrite the last block of large files. (CVE-2010-3015)

Tavis Ormandy discovered that the AIO subsystem did not correctly
validate certain parameters. A local attacker could exploit this to
crash the system or possibly gain root privileges. (CVE-2010-3067)

Dan Rosenberg discovered that certain XFS ioctls leaked kernel stack
contents. A local attacker could exploit this to read portions of
kernel memory, leading to a loss of privacy. (CVE-2010-3078)

Tavis Ormandy discovered that the OSS sequencer device did not
correctly shut down. A local attacker could exploit this to crash the
system or possibly gain root privileges. (CVE-2010-3080)

Dan Rosenberg discovered that the ROSE driver did not correctly check
parameters. A local attacker with access to a ROSE network device
could exploit this to crash the system or possibly gain root
privileges. (CVE-2010-3310)

Thomas Dreibholz discovered that SCTP did not correctly handle
appending packet chunks. A remote attacker could send specially
crafted traffic to crash the system, leading to a denial of service.
(CVE-2010-3432)

Dan Rosenberg discovered that the CD driver did not correctly check
parameters. A local attacker could exploit this to read arbitrary
kernel memory, leading to a loss of privacy. (CVE-2010-3437)

Dan Rosenberg discovered that the Sound subsystem did not correctly
validate parameters. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-3442)

Dan Rosenberg discovered that SCTP did not correctly handle HMAC
calculations. A remote attacker could send specially crafted traffic
that would crash the system, leading to a denial of service.
(CVE-2010-3705)

Joel Becker discovered that OCFS2 did not correctly validate on-disk
symlink structures. If an attacker were able to trick a user or
automated system into mounting a specially crafted filesystem, it
could crash the system or expose kernel memory, leading to a loss of
privacy. (CVE-2010-NNN2).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-source-2.6.31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-source-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(6\.06|8\.04|9\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-386", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-686", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-server", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-server", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-386", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-686", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-server", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-server", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-55.89")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-386", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-generic", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-openvz", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-rt", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-server", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-virtual", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-28-xen", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-386", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-generic", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-lpia", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-lpiacompat", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-openvz", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-rt", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-server", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-virtual", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-28-xen", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-28-386", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-28-generic", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-28-server", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-28-virtual", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-28.80")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-doc-2.6.28", pkgver:"2.6.28-19.66")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-19", pkgver:"2.6.28-19.66")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-19-generic", pkgver:"2.6.28-19.66")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-19-server", pkgver:"2.6.28-19.66")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-19-generic", pkgver:"2.6.28-19.66")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-19-lpia", pkgver:"2.6.28-19.66")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-19-server", pkgver:"2.6.28-19.66")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-19-versatile", pkgver:"2.6.28-19.66")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-19-virtual", pkgver:"2.6.28-19.66")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-libc-dev", pkgver:"2.6.28-19.66")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-source-2.6.28", pkgver:"2.6.28-19.66")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-doc", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-ec2-doc", pkgver:"2.6.31-307.21")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-ec2-source-2.6.31", pkgver:"2.6.31-307.21")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-386", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-generic", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-generic-pae", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-server", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-307", pkgver:"2.6.31-307.21")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-307-ec2", pkgver:"2.6.31-307.21")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-386", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-generic", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-generic-pae", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-lpia", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-server", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-virtual", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-307-ec2", pkgver:"2.6.31-307.21")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-libc-dev", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-source-2.6.31", pkgver:"2.6.31-22.67")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-doc", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-ec2-doc", pkgver:"2.6.32-309.18")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-ec2-source-2.6.32", pkgver:"2.6.32-309.18")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-25", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-25-386", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-25-generic", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-25-generic-pae", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-25-preempt", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-25-server", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-309", pkgver:"2.6.32-309.18")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-309-ec2", pkgver:"2.6.32-309.18")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-25-386", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-25-generic", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-25-generic-pae", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-25-lpia", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-25-preempt", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-25-server", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-25-versatile", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-25-virtual", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-309-ec2", pkgver:"2.6.32-309.18")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-libc-dev", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-source-2.6.32", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-tools-2.6.32-25", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-tools-common", pkgver:"2.6.32-25.45")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-doc", pkgver:"2.6.35-22.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-22", pkgver:"2.6.35-22.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-22-generic", pkgver:"2.6.35-22.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-22-generic-pae", pkgver:"2.6.35-22.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-22-server", pkgver:"2.6.35-22.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-22-virtual", pkgver:"2.6.35-22.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-22-generic", pkgver:"2.6.35-22.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-22-generic-pae", pkgver:"2.6.35-22.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-22-server", pkgver:"2.6.35-22.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-22-versatile", pkgver:"2.6.35-22.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-22-virtual", pkgver:"2.6.35-22.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-libc-dev", pkgver:"2.6.35-1022.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-source-2.6.35", pkgver:"2.6.35-22.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-tools-2.6.35-22", pkgver:"2.6.35-22.35")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-tools-common", pkgver:"2.6.35-22.35")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc / linux-doc-2.6.15 / linux-doc-2.6.24 / linux-doc-2.6.28 / etc");
}
