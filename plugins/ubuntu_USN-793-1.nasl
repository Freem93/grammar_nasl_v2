#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-793-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39586);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-1072", "CVE-2009-1184", "CVE-2009-1192", "CVE-2009-1242", "CVE-2009-1265", "CVE-2009-1336", "CVE-2009-1337", "CVE-2009-1338", "CVE-2009-1360", "CVE-2009-1385", "CVE-2009-1439", "CVE-2009-1630", "CVE-2009-1633", "CVE-2009-1914", "CVE-2009-1961");
  script_bugtraq_id(34205, 34405, 34453, 34612, 34654, 34673, 34934, 35143, 35185);
  script_xref(name:"USN", value:"793-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : linux, linux-source-2.6.15 vulnerabilities (USN-793-1)");
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
"Igor Zhbanov discovered that NFS clients were able to create device
nodes even when root_squash was enabled. An authenticated remote
attacker could create device nodes with open permissions, leading to a
loss of privacy or escalation of privileges. Only Ubuntu 8.10 and 9.04
were affected. (CVE-2009-1072)

Dan Carpenter discovered that SELinux did not correctly handle certain
network checks when running with compat_net=1. A local attacker could
exploit this to bypass network checks. Default Ubuntu installations do
not enable SELinux, and only Ubuntu 8.10 and 9.04 were affected.
(CVE-2009-1184)

Shaohua Li discovered that memory was not correctly initialized in the
AGP subsystem. A local attacker could potentially read kernel memory,
leading to a loss of privacy. (CVE-2009-1192)

Benjamin Gilbert discovered that the VMX implementation of KVM did not
correctly handle certain registers. An attacker in a guest VM could
exploit this to cause a host system crash, leading to a denial of
service. This only affected 32bit hosts. Ubuntu 6.06 was not affected.
(CVE-2009-1242)

Thomas Pollet discovered that the Amateur Radio X.25 Packet Layer
Protocol did not correctly validate certain fields. A remote attacker
could exploit this to read kernel memory, leading to a loss of
privacy. (CVE-2009-1265)

Trond Myklebust discovered that NFS did not correctly handle certain
long filenames. An authenticated remote attacker could exploit this to
cause a system crash, leading to a denial of service. Only Ubuntu 6.06
was affected. (CVE-2009-1336)

Oleg Nesterov discovered that the kernel did not correctly handle
CAP_KILL. A local user could exploit this to send signals to arbitrary
processes, leading to a denial of service. (CVE-2009-1337)

Daniel Hokka Zakrisson discovered that signal handling was not
correctly limited to process namespaces. A local user could bypass
namespace restrictions, possibly leading to a denial of service. Only
Ubuntu 8.04 was affected. (CVE-2009-1338)

Pavel Emelyanov discovered that network namespace support for IPv6 was
not correctly handled. A remote attacker could send specially crafted
IPv6 traffic that would cause a system crash, leading to a denial of
service. Only Ubuntu 8.10 and 9.04 were affected. (CVE-2009-1360)

Neil Horman discovered that the e1000 network driver did not correctly
validate certain fields. A remote attacker could send a specially
crafted packet that would cause a system crash, leading to a denial of
service. (CVE-2009-1385)

Pavan Naregundi discovered that CIFS did not correctly check lengths
when handling certain mount requests. A remote attacker could send
specially crafted traffic to cause a system crash, leading to a denial
of service. (CVE-2009-1439)

Simon Vallet and Frank Filz discovered that execute permissions were
not correctly handled by NFSv4. A local user could bypass permissions
and run restricted programs, possibly leading to an escalation of
privileges. (CVE-2009-1630)

Jeff Layton and Suresh Jayaraman discovered buffer overflows in the
CIFS client code. A malicious remote server could exploit this to
cause a system crash or execute arbitrary code as root.
(CVE-2009-1633)

Mikulas Patocka discovered that /proc/iomem was not correctly
initialized on Sparc. A local attacker could use this file to crash
the system, leading to a denial of service. Ubuntu 6.06 was not
affected. (CVE-2009-1914)

Miklos Szeredi discovered that OCFS2 did not correctly handle certain
splice operations. A local attacker could exploit this to cause a
system hang, leading to a denial of service. Ubuntu 6.06 was not
affected. (CVE-2009-1961).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 20, 119, 189, 264, 362);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/02");
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

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-386", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-686", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-amd64-generic", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-amd64-k8", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-amd64-server", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-amd64-xeon", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-server", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-386", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-686", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-amd64-generic", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-amd64-k8", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-amd64-server", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-amd64-xeon", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-server", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-54.77")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-386", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-generic", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-openvz", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-rt", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-server", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-virtual", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-xen", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-386", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-generic", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-lpia", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-lpiacompat", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-openvz", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-rt", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-server", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-virtual", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-xen", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-24-386", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-24-generic", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-24-server", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-24-virtual", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-24.55")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-doc-2.6.27", pkgver:"2.6.27-14.35")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-14", pkgver:"2.6.27-14.35")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-14-generic", pkgver:"2.6.27-14.35")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-14-server", pkgver:"2.6.27-14.35")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-14-generic", pkgver:"2.6.27-14.35")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-14-server", pkgver:"2.6.27-14.35")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-14-virtual", pkgver:"2.6.27-14.35")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-libc-dev", pkgver:"2.6.27-14.35")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-source-2.6.27", pkgver:"2.6.27-14.35")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-doc-2.6.28", pkgver:"2.6.28-13.45")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-13", pkgver:"2.6.28-13.45")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-13-generic", pkgver:"2.6.28-13.45")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-13-server", pkgver:"2.6.28-13.45")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-13-generic", pkgver:"2.6.28-13.45")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-13-lpia", pkgver:"2.6.28-13.45")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-13-server", pkgver:"2.6.28-13.45")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-13-versatile", pkgver:"2.6.28-13.45")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-13-virtual", pkgver:"2.6.28-13.45")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-libc-dev", pkgver:"2.6.28-13.45")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-source-2.6.28", pkgver:"2.6.28-13.45")) flag++;

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
