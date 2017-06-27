#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-395-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27981);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/10/26 14:26:01 $");

  script_cve_id("CVE-2006-4572", "CVE-2006-4813", "CVE-2006-4997", "CVE-2006-5158", "CVE-2006-5173", "CVE-2006-5619", "CVE-2006-5648", "CVE-2006-5649", "CVE-2006-5701", "CVE-2006-5751", "CVE-2006-5755", "CVE-2006-5871");
  script_bugtraq_id(20363, 20847, 20955, 21353, 21522, 21523);
  script_osvdb_id(29539, 30002, 30066, 30192, 30725, 30923, 31372, 31373, 31374, 31376, 31464, 31465);
  script_xref(name:"USN", value:"395-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS / 6.10 : linux-source-2.6.12/-2.6.15/-2.6.17 vulnerabilities (USN-395-1)");
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
"Mark Dowd discovered that the netfilter iptables module did not
correcly handle fragmented packets. By sending specially crafted
packets, a remote attacker could exploit this to bypass firewall
rules. This has only be fixed for Ubuntu 6.10; the corresponding fix
for Ubuntu 5.10 and 6.06 will follow soon. (CVE-2006-4572)

Dmitriy Monakhov discovered an information leak in the
__block_prepare_write() function. During error recovery, this function
did not properly clear memory buffers which could allow local users to
read portions of unlinked files. This only affects Ubuntu 5.10.
(CVE-2006-4813)

ADLab Venustech Info Ltd discovered that the ATM network driver
referenced an already released pointer in some circumstances. By
sending specially crafted packets to a host over ATM, a remote
attacker could exploit this to crash that host. This does not affect
Ubuntu 6.10. (CVE-2006-4997)

Matthias Andree discovered that the NFS locking management daemon
(lockd) did not correctly handle mixing of 'lock' and 'nolock' option
mounts on the same client. A remote attacker could exploit this to
crash lockd and thus rendering the NFS imports inaccessible. This only
affects Ubuntu 5.10. (CVE-2006-5158)

The task switching code did not save and restore EFLAGS of processes.
By starting a specially crafted executable, a local attacker could
exploit this to eventually crash many other running processes. This
does not affect Ubuntu 6.10. (CVE-2006-5173)

James Morris discovered that the ip6fl_get_n() function incorrectly
handled flow labels. A local attacker could exploit this to crash the
kernel. (CVE-2006-5619)

Fabio Massimo Di Nitto discovered that the sys_get_robust_list and
sys_set_robust_list system calls lacked proper lock handling on the
powerpc platform. A local attacker could exploit this to create
unkillable processes, drain all available CPU/memory, and render the
machine unrebootable. This only affects Ubuntu 6.10. (CVE-2006-5648)

Fabio Massimo Di Nitto discovered a flaw in the alignment check
exception handling on the powerpc platform. A local attacker could
exploit this to cause a kernel panic and crash the machine.
(CVE-2006-5649)

Certain corrupted squashfs file system images caused a memory
allocation to be freed twice. By mounting a specially crafted squashfs
file system, a local attacker could exploit this to crash the kernel.
This does not affect Ubuntu 5.10. (CVE-2006-5701)

An integer overflow was found in the get_fdb_entries() function of the
network bridging code. By executing a specially crafted ioctl, a local
attacker could exploit this to execute arbitrary code with root
privileges. (CVE-2006-5751).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-ubuntu-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.10|6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"linux-doc-2.6.12", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-386", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686-smp", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-386", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686-smp", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-patch-ubuntu-2.6.12", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-source-2.6.12", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-tree-2.6.12", pkgver:"2.6.12-10.42")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-27", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-27-386", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-27-686", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-27-amd64-generic", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-27-amd64-k8", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-27-amd64-server", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-27-amd64-xeon", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-27-server", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-27-386", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-27-686", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-27-amd64-generic", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-27-amd64-k8", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-27-amd64-server", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-27-amd64-xeon", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-27-server", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-27.50")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-doc-2.6.17", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-10", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-10-386", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-10-generic", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-10-server", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-10-386", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-10-generic", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-10-server", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-10-386", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-10-generic", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-10-server", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-kdump", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-kernel-devel", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-libc-dev", pkgver:"2.6.17.1-10.34")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-source-2.6.17", pkgver:"2.6.17.1-10.34")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.12 / linux-doc-2.6.15 / linux-doc-2.6.17 / etc");
}
