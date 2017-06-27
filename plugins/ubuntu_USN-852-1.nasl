#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-852-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42209);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-1883", "CVE-2009-2584", "CVE-2009-2695", "CVE-2009-2698", "CVE-2009-2767", "CVE-2009-2846", "CVE-2009-2847", "CVE-2009-2848", "CVE-2009-2849", "CVE-2009-2903", "CVE-2009-2908", "CVE-2009-3001", "CVE-2009-3002", "CVE-2009-3238", "CVE-2009-3286", "CVE-2009-3288", "CVE-2009-3290");
  script_bugtraq_id(35930, 36004, 36108, 36176, 36379, 36472, 36512, 36639);
  script_osvdb_id(56293, 56822, 57208, 57209, 57210, 57264, 57427, 57428, 57462, 57757, 58102, 58214, 58234, 58235, 58322, 58323, 58880);
  script_xref(name:"USN", value:"852-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : linux, linux-source-2.6.15 vulnerabilities (USN-852-1)");
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
"Solar Designer discovered that the z90crypt driver did not correctly
check capabilities. A local attacker could exploit this to shut down
the device, leading to a denial of service. Only affected Ubuntu 6.06.
(CVE-2009-1883)

Michael Buesch discovered that the SGI GRU driver did not correctly
check the length when setting options. A local attacker could exploit
this to write to the kernel stack, leading to root privilege
escalation or a denial of service. Only affected Ubuntu 8.10 and 9.04.
(CVE-2009-2584)

It was discovered that SELinux did not fully implement the
mmap_min_addr restrictions. A local attacker could exploit this to
allocate the NULL memory page which could lead to further attacks
against kernel NULL-dereference vulnerabilities. Ubuntu 6.06 was not
affected. (CVE-2009-2695)

Cagri Coltekin discovered that the UDP stack did not correctly handle
certain flags. A local user could send specially crafted commands and
traffic to gain root privileges or crash the systeam, leading to a
denial of service. Only affected Ubuntu 6.06. (CVE-2009-2698)

Hiroshi Shimamoto discovered that monotonic timers did not correctly
validate parameters. A local user could make a specially crafted timer
request to gain root privileges or crash the system, leading to a
denial of service. Only affected Ubuntu 9.04. (CVE-2009-2767)

Michael Buesch discovered that the HPPA ISA EEPROM driver did not
correctly validate positions. A local user could make a specially
crafted request to gain root privileges or crash the system, leading
to a denial of service. (CVE-2009-2846)

Ulrich Drepper discovered that kernel signal stacks were not being
correctly padded on 64-bit systems. A local attacker could send
specially crafted calls to expose 4 bytes of kernel stack memory,
leading to a loss of privacy. (CVE-2009-2847)

Jens Rosenboom discovered that the clone method did not correctly
clear certain fields. A local attacker could exploit this to gain
privileges or crash the system, leading to a denial of service.
(CVE-2009-2848)

It was discovered that the MD driver did not check certain sysfs
files. A local attacker with write access to /sys could exploit this
to cause a system crash, leading to a denial of service. Ubuntu 6.06
was not affected. (CVE-2009-2849)

Mark Smith discovered that the AppleTalk stack did not correctly
manage memory. A remote attacker could send specially crafted traffic
to cause the system to consume all available memory, leading to a
denial of service. (CVE-2009-2903)

Loic Minier discovered that eCryptfs did not correctly handle writing
to certain deleted files. A local attacker could exploit this to gain
root privileges or crash the system, leading to a denial of service.
Ubuntu 6.06 was not affected. (CVE-2009-2908)

It was discovered that the LLC, AppleTalk, IR, EConet, Netrom, and
ROSE network stacks did not correctly initialize their data
structures. A local attacker could make specially crafted calls to
read kernel memory, leading to a loss of privacy. (CVE-2009-3001,
CVE-2009-3002)

It was discovered that the randomization used for Address Space Layout
Randomization was predictable within a small window of time. A local
attacker could exploit this to leverage further attacks that require
knowledge of userspace memory layouts. (CVE-2009-3238)

Eric Paris discovered that NFSv4 did not correctly handle file
creation failures. An attacker with write access to an NFSv4 share
could exploit this to create files with arbitrary mode bits, leading
to privilege escalation or a loss of privacy. (CVE-2009-3286)

Bob Tracy discovered that the SCSI generic driver did not correctly
use the right index for array access. A local attacker with write
access to a CDR could exploit this to crash the system, leading to a
denial of service. Only Ubuntu 9.04 was affected. (CVE-2009-3288)

Jan Kiszka discovered that KVM did not correctly validate certain
hypercalls. A local unprivileged attacker in a virtual guest could
exploit this to crash the guest kernel, leading to a denial of
service. Ubuntu 6.06 was not affected. (CVE-2009-3290).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 189, 200, 264, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/22");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-386", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-686", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-server", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-server", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-386", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-686", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-server", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-server", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-55.80")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-25", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-25-386", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-25-generic", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-25-openvz", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-25-rt", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-25-server", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-25-virtual", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-25-xen", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-25-386", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-25-generic", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-25-lpia", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-25-lpiacompat", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-25-openvz", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-25-rt", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-25-server", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-25-virtual", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-25-xen", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-25-386", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-25-generic", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-25-server", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-25-virtual", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-25.63")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-doc-2.6.27", pkgver:"2.6.27-15.43")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-15", pkgver:"2.6.27-15.43")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-15-generic", pkgver:"2.6.27-15.43")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-15-server", pkgver:"2.6.27-15.43")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-15-generic", pkgver:"2.6.27-15.43")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-15-server", pkgver:"2.6.27-15.43")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-15-virtual", pkgver:"2.6.27-15.43")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-libc-dev", pkgver:"2.6.27-15.43")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-source-2.6.27", pkgver:"2.6.27-15.43")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-doc-2.6.28", pkgver:"2.6.28-16.55")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-16", pkgver:"2.6.28-16.55")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-16-generic", pkgver:"2.6.28-16.55")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-16-server", pkgver:"2.6.28-16.55")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-16-generic", pkgver:"2.6.28-16.55")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-16-lpia", pkgver:"2.6.28-16.55")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-16-server", pkgver:"2.6.28-16.55")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-16-versatile", pkgver:"2.6.28-16.55")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-16-virtual", pkgver:"2.6.28-16.55")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-libc-dev", pkgver:"2.6.28-16.55")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-source-2.6.28", pkgver:"2.6.28-16.55")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.15 / linux-doc-2.6.24 / linux-doc-2.6.27 / etc");
}
