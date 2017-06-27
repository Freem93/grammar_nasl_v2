#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1041-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51453);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/26 14:05:56 $");

  script_cve_id("CVE-2010-2537", "CVE-2010-2538", "CVE-2010-2943", "CVE-2010-2962", "CVE-2010-3079", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3298", "CVE-2010-3301", "CVE-2010-3698", "CVE-2010-3858", "CVE-2010-3861", "CVE-2010-4072", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4157", "CVE-2010-4242", "CVE-2010-4655");
  script_bugtraq_id(41847, 41854, 42527, 43221, 43226, 43229, 43355, 43684, 44067, 44301, 44427, 45054);
  script_osvdb_id(68303, 68306, 69551);
  script_xref(name:"USN", value:"1041-1");

  script_name(english:"Ubuntu 9.10 / 10.04 LTS / 10.10 : linux, linux-ec2 vulnerabilities (USN-1041-1)");
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
"Ben Hawkes discovered that the Linux kernel did not correctly filter
registers on 64bit kernels when performing 32bit system calls. On a
64bit system, a local attacker could manipulate 32bit system calls to
gain root privileges. (CVE-2010-3301)

Dan Rosenberg discovered that the btrfs filesystem did not correctly
validate permissions when using the clone function. A local attacker
could overwrite the contents of file handles that were opened for
append-only, or potentially read arbitrary contents, leading to a loss
of privacy. (CVE-2010-2537, CVE-2010-2538)

Dave Chinner discovered that the XFS filesystem did not correctly
order inode lookups when exported by NFS. A remote attacker could
exploit this to read or write disk blocks that had changed file
assignment or had become unlinked, leading to a loss of privacy.
(CVE-2010-2943)

Kees Cook discovered that the Intel i915 graphics driver did not
correctly validate memory regions. A local attacker with access to the
video card could read and write arbitrary kernel memory to gain root
privileges. (CVE-2010-2962)

Robert Swiecki discovered that ftrace did not correctly handle
mutexes. A local attacker could exploit this to crash the kernel,
leading to a denial of service. (CVE-2010-3079)

Dan Rosenberg discovered that several network ioctls did not clear
kernel memory correctly. A local user could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-3296,
CVE-2010-3297, CVE-2010-3298)

It was discovered that KVM did not correctly initialize certain CPU
registers. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-3698)

Brad Spengler discovered that stack memory for new a process was not
correctly calculated. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-3858)

Kees Cook discovered that the ethtool interface did not correctly
clear kernel memory. A local attacker could read kernel heap memory,
leading to a loss of privacy. (CVE-2010-3861)

Kees Cook and Vasiliy Kulikov discovered that the shm interface did
not clear kernel memory correctly. A local attacker could exploit this
to read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4072)

Dan Rosenberg discovered that the RME Hammerfall DSP audio interface
driver did not correctly clear kernel memory. A local attacker could
exploit this to read kernel stack memory, leading to a loss of
privacy. (CVE-2010-4080, CVE-2010-4081)

James Bottomley discovered that the ICP vortex storage array
controller driver did not validate certain sizes. A local attacker on
a 64bit system could exploit this to crash the kernel, leading to a
denial of service. (CVE-2010-4157)

Alan Cox discovered that the HCI UART driver did not correctly check
if a write operation was available. If the mmap_min-addr sysctl was
changed from the Ubuntu default to a value of 0, a local attacker
could exploit this flaw to gain root privileges. (CVE-2010-4242)

Kees Cook discovered that some ethtool functions did not correctly
clear heap memory. A local attacker with CAP_NET_ADMIN privileges
could exploit this to read portions of kernel heap memory, leading to
a loss of privacy. (CVE-2010-4655).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-source-2.6.31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-source-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.10", pkgname:"linux-doc", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-ec2-doc", pkgver:"2.6.31-307.23")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-ec2-source-2.6.31", pkgver:"2.6.31-307.23")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-386", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-generic", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-generic-pae", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-server", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-307", pkgver:"2.6.31-307.23")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-307-ec2", pkgver:"2.6.31-307.23")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-386", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-generic", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-generic-pae", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-lpia", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-server", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-virtual", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-307-ec2", pkgver:"2.6.31-307.23")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-libc-dev", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-source-2.6.31", pkgver:"2.6.31-22.70")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-doc", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-ec2-doc", pkgver:"2.6.32-311.23")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-ec2-source-2.6.32", pkgver:"2.6.32-311.23")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-27", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-27-386", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-27-generic", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-27-generic-pae", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-27-preempt", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-27-server", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-311", pkgver:"2.6.32-311.23")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-311-ec2", pkgver:"2.6.32-311.23")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-27-386", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-27-generic", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-27-generic-pae", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-27-lpia", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-27-preempt", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-27-server", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-27-versatile", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-27-virtual", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-311-ec2", pkgver:"2.6.32-311.23")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-libc-dev", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-source-2.6.32", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-tools-2.6.32-27", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-tools-common", pkgver:"2.6.32-27.49")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-doc", pkgver:"2.6.35-24.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-24", pkgver:"2.6.35-24.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-24-generic", pkgver:"2.6.35-24.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-24-generic-pae", pkgver:"2.6.35-24.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-24-server", pkgver:"2.6.35-24.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-24-virtual", pkgver:"2.6.35-24.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-24-generic", pkgver:"2.6.35-24.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-24-generic-pae", pkgver:"2.6.35-24.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-24-server", pkgver:"2.6.35-24.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-24-versatile", pkgver:"2.6.35-24.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-24-virtual", pkgver:"2.6.35-24.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-libc-dev", pkgver:"2.6.35-1024.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-source-2.6.35", pkgver:"2.6.35-24.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-tools-2.6.35-24", pkgver:"2.6.35-24.42")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-tools-common", pkgver:"2.6.35-24.42")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc / linux-ec2-doc / linux-ec2-source-2.6.31 / etc");
}
