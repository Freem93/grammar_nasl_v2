#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-894-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44399);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2009-4020", "CVE-2009-4021", "CVE-2009-4031", "CVE-2009-4138", "CVE-2009-4141", "CVE-2009-4308", "CVE-2009-4536", "CVE-2009-4538", "CVE-2010-0003", "CVE-2010-0006", "CVE-2010-0007", "CVE-2010-0291");
  script_bugtraq_id(37069, 37339, 37906);
  script_osvdb_id(60558, 60559, 60795, 61035, 61309, 61670, 61687, 61769, 61788, 61876, 61984);
  script_xref(name:"USN", value:"894-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 / 9.10 : linux, linux-source-2.6.15 vulnerabilities (USN-894-1)");
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
"Amerigo Wang and Eric Sesterhenn discovered that the HFS and ext4
filesystems did not correctly check certain disk structures. If a user
were tricked into mounting a specially crafted filesystem, a remote
attacker could crash the system or gain root privileges.
(CVE-2009-4020, CVE-2009-4308)

It was discovered that FUSE did not correctly check certain requests.
A local attacker with access to FUSE mounts could exploit this to
crash the system or possibly gain root privileges. Ubuntu 9.10 was not
affected. (CVE-2009-4021)

It was discovered that KVM did not correctly decode certain guest
instructions. A local attacker in a guest could exploit this to
trigger high scheduling latency in the host, leading to a denial of
service. Ubuntu 6.06 was not affected. (CVE-2009-4031)

It was discovered that the OHCI fireware driver did not correctly
handle certain ioctls. A local attacker could exploit this to crash
the system, or possibly gain root privileges. Ubuntu 6.06 was not
affected. (CVE-2009-4138)

Tavis Ormandy discovered that the kernel did not correctly handle
O_ASYNC on locked files. A local attacker could exploit this to gain
root privileges. Only Ubuntu 9.04 and 9.10 were affected.
(CVE-2009-4141)

Neil Horman and Eugene Teo discovered that the e1000 and e1000e
network drivers did not correctly check the size of Ethernet frames.
An attacker on the local network could send specially crafted traffic
to bypass packet filters, crash the system, or possibly gain root
privileges. (CVE-2009-4536, CVE-2009-4538)

It was discovered that 'print-fatal-signals' reporting could show
arbitrary kernel memory contents. A local attacker could exploit this,
leading to a loss of privacy. By default this is disabled in Ubuntu
and did not affect Ubuntu 6.06. (CVE-2010-0003)

Olli Jarva and Tuomo Untinen discovered that IPv6 did not correctly
handle jumbo frames. A remote attacker could exploit this to crash the
system, leading to a denial of service. Only Ubuntu 9.04 and 9.10 were
affected. (CVE-2010-0006)

Florian Westphal discovered that bridging netfilter rules could be
modified by unprivileged users. A local attacker could disrupt network
traffic, leading to a denial of service. (CVE-2010-0007)

Al Viro discovered that certain mremap operations could leak kernel
memory. A local attacker could exploit this to consume all available
memory, leading to a denial of service. (CVE-2010-0291).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-source-2.6.31");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-dove");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-dove-z0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-ec2");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/05");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-386", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-686", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-server", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-server", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-386", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-686", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-server", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-server", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-55.82")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-386", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-generic", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-openvz", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-rt", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-server", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-virtual", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-xen", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-386", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-generic", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-lpia", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-lpiacompat", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-openvz", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-rt", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-server", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-virtual", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-xen", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-27-386", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-27-generic", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-27-server", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-27-virtual", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-27.65")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-doc-2.6.27", pkgver:"2.6.27-17.45")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-17", pkgver:"2.6.27-17.45")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-17-generic", pkgver:"2.6.27-17.45")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-17-server", pkgver:"2.6.27-17.45")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-17-generic", pkgver:"2.6.27-17.45")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-17-server", pkgver:"2.6.27-17.45")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-17-virtual", pkgver:"2.6.27-17.45")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-libc-dev", pkgver:"2.6.27-17.45")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-source-2.6.27", pkgver:"2.6.27-17.45")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-doc-2.6.28", pkgver:"2.6.28-18.59")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-18", pkgver:"2.6.28-18.59")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-18-generic", pkgver:"2.6.28-18.59")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-18-server", pkgver:"2.6.28-18.59")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-18-generic", pkgver:"2.6.28-18.59")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-18-lpia", pkgver:"2.6.28-18.59")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-18-server", pkgver:"2.6.28-18.59")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-18-versatile", pkgver:"2.6.28-18.59")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-18-virtual", pkgver:"2.6.28-18.59")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-libc-dev", pkgver:"2.6.28-18.59")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-source-2.6.28", pkgver:"2.6.28-18.59")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-doc", pkgver:"2.6.31-19.56")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-ec2-doc", pkgver:"2.6.31-304.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-ec2-source-2.6.31", pkgver:"2.6.31-304.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-19", pkgver:"2.6.31-19.56")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-19-386", pkgver:"2.6.31-19.56")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-19-generic", pkgver:"2.6.31-19.56")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-19-generic-pae", pkgver:"2.6.31-19.56")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-19-server", pkgver:"2.6.31-19.56")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-304", pkgver:"2.6.31-304.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-304-ec2", pkgver:"2.6.31-304.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-19-386", pkgver:"2.6.31-19.56")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-19-generic", pkgver:"2.6.31-19.56")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-19-generic-pae", pkgver:"2.6.31-19.56")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-19-lpia", pkgver:"2.6.31-19.56")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-19-server", pkgver:"2.6.31-19.56")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-19-virtual", pkgver:"2.6.31-19.56")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-211-dove", pkgver:"2.6.31-211.22")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-211-dove-z0", pkgver:"2.6.31-211.22")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-304-ec2", pkgver:"2.6.31-304.10")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-libc-dev", pkgver:"2.6.31-19.56")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-source-2.6.31", pkgver:"2.6.31-19.56")) flag++;

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
