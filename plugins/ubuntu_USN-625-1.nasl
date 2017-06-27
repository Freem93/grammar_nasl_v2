#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-625-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33531);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2007-6282", "CVE-2007-6712", "CVE-2008-0598", "CVE-2008-1615", "CVE-2008-1673", "CVE-2008-2136", "CVE-2008-2137", "CVE-2008-2148", "CVE-2008-2358", "CVE-2008-2365", "CVE-2008-2729", "CVE-2008-2750", "CVE-2008-2826");
  script_bugtraq_id(29081, 29086, 29235, 29589, 29603, 29747, 29942);
  script_osvdb_id(44688, 44930, 44992, 45186, 45421, 45764, 46104, 46164, 46309, 48114, 48115, 48563, 48781);
  script_xref(name:"USN", value:"625-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : linux, linux-source-2.6.15/20/22 vulnerabilities (USN-625-1)");
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
"Dirk Nehring discovered that the IPsec protocol stack did not
correctly handle fragmented ESP packets. A remote attacker could
exploit this to crash the system, leading to a denial of service.
(CVE-2007-6282)

Johannes Bauer discovered that the 64bit kernel did not correctly
handle hrtimer updates. A local attacker could request a large
expiration value and cause the system to hang, leading to a denial of
service. (CVE-2007-6712)

Tavis Ormandy discovered that the ia32 emulation under 64bit kernels
did not fully clear uninitialized data. A local attacker could read
private kernel memory, leading to a loss of privacy. (CVE-2008-0598)

Jan Kratochvil discovered that PTRACE did not correctly handle certain
calls when running under 64bit kernels. A local attacker could exploit
this to crash the system, leading to a denial of service.
(CVE-2008-1615)

Wei Wang discovered that the ASN.1 decoding routines in CIFS and SNMP
NAT did not correctly handle certain length values. Remote attackers
could exploit this to execute arbitrary code or crash the system.
(CVE-2008-1673)

Paul Marks discovered that the SIT interfaces did not correctly manage
allocated memory. A remote attacker could exploit this to fill all
available memory, leading to a denial of service. (CVE-2008-2136)

David Miller and Jan Lieskovsky discovered that the Sparc kernel did
not correctly range-check memory regions allocated with mmap. A local
attacker could exploit this to crash the system, leading to a denial
of service. (CVE-2008-2137)

The sys_utimensat system call did not correctly check file permissions
in certain situations. A local attacker could exploit this to modify
the file times of arbitrary files which could lead to a denial of
service. (CVE-2008-2148)

Brandon Edwards discovered that the DCCP system in the kernel did not
correctly check feature lengths. A remote attacker could exploit this
to execute arbitrary code. (CVE-2008-2358)

A race condition was discovered between ptrace and utrace in the
kernel. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2008-2365)

The copy_to_user routine in the kernel did not correctly clear memory
destination addresses when running on 64bit kernels. A local attacker
could exploit this to gain access to sensitive kernel memory, leading
to a loss of privacy. (CVE-2008-2729)

The PPP over L2TP routines in the kernel did not correctly handle
certain messages. A remote attacker could send a specially crafted
packet that could crash the system or execute arbitrary code.
(CVE-2008-2750)

Gabriel Campana discovered that SCTP routines did not correctly check
for large addresses. A local user could exploit this to allocate all
available memory, leading to a denial of service. (CVE-2008-2826).

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
  script_cwe_id(16, 20, 119, 189, 200, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-cell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-386", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-686", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-generic", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-k8", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-server", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-xeon", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-server", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-386", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-686", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-generic", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-k8", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-server", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-xeon", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-server", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-52.69")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-doc-2.6.20", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17-386", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17-generic", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17-lowlatency", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17-server", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-17-386", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-17-generic", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-17-lowlatency", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-17-server", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-17-386", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-17-generic", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-17-lowlatency", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-17-server", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-kernel-devel", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-libc-dev", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-source-2.6.20", pkgver:"2.6.20-17.37")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-doc-2.6.22", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-386", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-generic", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-rt", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-server", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-ume", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-virtual", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-xen", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-386", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-cell", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-generic", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-lpia", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-lpiacompat", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-rt", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-server", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-ume", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-virtual", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-xen", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-386", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-generic", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-server", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-virtual", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-kernel-devel", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-libc-dev", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-source-2.6.22", pkgver:"2.6.22-15.56")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-386", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-generic", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-openvz", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-rt", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-server", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-virtual", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-19-xen", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-386", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-generic", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-lpia", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-lpiacompat", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-openvz", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-rt", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-server", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-virtual", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-19-xen", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-19-386", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-19-generic", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-19-server", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-19-virtual", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-19.36")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-19.36")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.15 / linux-doc-2.6.20 / linux-doc-2.6.22 / etc");
}
