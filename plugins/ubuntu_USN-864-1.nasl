#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-864-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43026);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2009-2909", "CVE-2009-2910", "CVE-2009-3080", "CVE-2009-3228", "CVE-2009-3547", "CVE-2009-3612", "CVE-2009-3613", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3623", "CVE-2009-3624", "CVE-2009-3638", "CVE-2009-3722", "CVE-2009-3725", "CVE-2009-3726", "CVE-2009-3888", "CVE-2009-3889", "CVE-2009-3939", "CVE-2009-4005", "CVE-2009-4026", "CVE-2009-4027");
  script_bugtraq_id(36304, 36576, 36635, 36706, 36723, 36793, 36803, 36824, 36827, 36901, 36936, 37019, 37036, 37068, 37170, 37221);
  script_osvdb_id(57821, 59070, 59877, 60311);
  script_xref(name:"USN", value:"864-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 / 9.10 : linux, linux-source-2.6.15 vulnerabilities (USN-864-1)");
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
"It was discovered that the AX.25 network subsystem did not correctly
check integer signedness in certain setsockopt calls. A local attacker
could exploit this to crash the system, leading to a denial of
service. Ubuntu 9.10 was not affected. (CVE-2009-2909)

Jan Beulich discovered that the kernel could leak register contents to
32-bit processes that were switched to 64-bit mode. A local attacker
could run a specially crafted binary to read register values from an
earlier process, leading to a loss of privacy. (CVE-2009-2910)

Dave Jones discovered that the gdth SCSI driver did not correctly
validate array indexes in certain ioctl calls. A local attacker could
exploit this to crash the system or gain elevated privileges.
(CVE-2009-3080)

Eric Dumazet and Jiri Pirko discovered that the TC and CLS subsystems
would leak kernel memory via uninitialized structure members. A local
attacker could exploit this to read several bytes of kernel memory,
leading to a loss of privacy. (CVE-2009-3228, CVE-2009-3612)

Earl Chew discovered race conditions in pipe handling. A local
attacker could exploit anonymous pipes via /proc/*/fd/ and crash the
system or gain root privileges. (CVE-2009-3547)

Dave Jones and Francois Romieu discovered that the r8169 network
driver could be made to leak kernel memory. A remote attacker could
send a large number of jumbo frames until the system memory was
exhausted, leading to a denial of service. Ubuntu 9.10 was not
affected. (CVE-2009-3613).

Ben Hutchings discovered that the ATI Rage 128 video driver did not
correctly validate initialization states. A local attacker could make
specially crafted ioctl calls to crash the system or gain root
privileges. (CVE-2009-3620)

Tomoki Sekiyama discovered that Unix sockets did not correctly verify
namespaces. A local attacker could exploit this to cause a system
hang, leading to a denial of service. (CVE-2009-3621)

J. Bruce Fields discovered that NFSv4 did not correctly use the
credential cache. A local attacker using a mount with AUTH_NULL
authentication could exploit this to crash the system or gain root
privileges. Only Ubuntu 9.10 was affected. (CVE-2009-3623)

Alexander Zangerl discovered that the kernel keyring did not correctly
reference count. A local attacker could issue a series of specially
crafted keyring calls to crash the system or gain root privileges.
Only Ubuntu 9.10 was affected. (CVE-2009-3624)

David Wagner discovered that KVM did not correctly bounds-check CPUID
entries. A local attacker could exploit this to crash the system or
possibly gain elevated privileges. Ubuntu 6.06 and 9.10 were not
affected. (CVE-2009-3638)

Avi Kivity discovered that KVM did not correctly check privileges when
accessing debug registers. A local attacker could exploit this to
crash a host system from within a guest system, leading to a denial of
service. Ubuntu 6.06 and 9.10 were not affected. (CVE-2009-3722)

Philip Reisner discovered that the connector layer for uvesafb,
pohmelfs, dst, and dm did not correctly check capabilties. A local
attacker could exploit this to crash the system or gain elevated
privileges. Ubuntu 6.06 was not affected. (CVE-2009-3725)

Trond Myklebust discovered that NFSv4 clients did not robustly verify
attributes. A malicious remote NFSv4 server could exploit this to
crash a client or gain root privileges. Ubuntu 9.10 was not affected.
(CVE-2009-3726)

Robin Getz discovered that NOMMU systems did not correctly validate
NULL pointers in do_mmap_pgoff calls. A local attacker could attempt
to allocate large amounts of memory to crash the system, leading to a
denial of service. Only Ubuntu 6.06 and 9.10 were affected.
(CVE-2009-3888)

Joseph Malicki discovered that the MegaRAID SAS driver had
world-writable option files. A local attacker could exploit these to
disrupt the behavior of the controller, leading to a denial of
service. (CVE-2009-3889, CVE-2009-3939)

Roel Kluin discovered that the Hisax ISDN driver did not correctly
check the size of packets. A remote attacker could send specially
crafted packets to cause a system crash, leading to a denial of
service. (CVE-2009-4005)

Lennert Buytenhek discovered that certain 802.11 states were not
handled correctly. A physically-proximate remote attacker could send
specially crafted wireless traffic that would crash the system,
leading to a denial of service. Only Ubuntu 9.10 was affected.
(CVE-2009-4026, CVE-2009-4027).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 119, 189, 200, 264, 287, 310, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-openvz");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-openvz");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.31");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-386", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-686", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-server", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-server", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-386", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-686", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-server", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-server", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-55.81")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-26", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-26-386", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-26-generic", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-26-openvz", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-26-rt", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-26-server", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-26-virtual", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-26-xen", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-26-386", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-26-generic", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-26-lpia", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-26-lpiacompat", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-26-openvz", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-26-rt", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-26-server", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-26-virtual", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-26-xen", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-26-386", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-26-generic", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-26-server", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-26-virtual", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-26.64")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-doc-2.6.27", pkgver:"2.6.27-16.44")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-16", pkgver:"2.6.27-16.44")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-16-generic", pkgver:"2.6.27-16.44")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-16-server", pkgver:"2.6.27-16.44")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-16-generic", pkgver:"2.6.27-16.44")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-16-server", pkgver:"2.6.27-16.44")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-16-virtual", pkgver:"2.6.27-16.44")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-libc-dev", pkgver:"2.6.27-16.44")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-source-2.6.27", pkgver:"2.6.27-16.44")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-doc-2.6.28", pkgver:"2.6.28-17.58")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-17", pkgver:"2.6.28-17.58")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-17-generic", pkgver:"2.6.28-17.58")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-17-server", pkgver:"2.6.28-17.58")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-17-generic", pkgver:"2.6.28-17.58")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-17-lpia", pkgver:"2.6.28-17.58")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-17-server", pkgver:"2.6.28-17.58")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-17-versatile", pkgver:"2.6.28-17.58")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-17-virtual", pkgver:"2.6.28-17.58")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-libc-dev", pkgver:"2.6.28-17.58")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-source-2.6.28", pkgver:"2.6.28-17.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-doc", pkgver:"2.6.31-16.52")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-16", pkgver:"2.6.31-16.52")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-16-386", pkgver:"2.6.31-16.52")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-16-generic", pkgver:"2.6.31-16.52")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-16-generic-pae", pkgver:"2.6.31-16.52")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-16-server", pkgver:"2.6.31-16.52")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-16-386", pkgver:"2.6.31-16.52")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-16-generic", pkgver:"2.6.31-16.52")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-16-generic-pae", pkgver:"2.6.31-16.52")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-16-lpia", pkgver:"2.6.31-16.52")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-16-server", pkgver:"2.6.31-16.52")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-16-virtual", pkgver:"2.6.31-16.52")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-libc-dev", pkgver:"2.6.31-16.52")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-source-2.6.31", pkgver:"2.6.31-16.52")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc / linux-doc-2.6.15 / linux-doc-2.6.24 / linux-doc-2.6.27 / etc");
}
