#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-914-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45081);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2010-0307", "CVE-2010-0309", "CVE-2010-0410", "CVE-2010-0415", "CVE-2010-0622", "CVE-2010-0623");
  script_bugtraq_id(38027, 38058, 38144, 38165);
  script_xref(name:"USN", value:"914-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 / 9.10 : linux, linux-source-2.6.15 vulnerabilities (USN-914-1)");
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
"Mathias Krause discovered that the Linux kernel did not correctly
handle missing ELF interpreters. A local attacker could exploit this
to cause the system to crash, leading to a denial of service.
(CVE-2010-0307)

Marcelo Tosatti discovered that the Linux kernel's hardware
virtualization did not correctly handle reading the /dev/port special
device. A local attacker in a guest operating system could issue a
specific read that would cause the host system to crash, leading to a
denial of service. (CVE-2010-0309)

Sebastian Krahmer discovered that the Linux kernel did not correctly
handle netlink connector messages. A local attacker could exploit this
to consume kernel memory, leading to a denial of service.
(CVE-2010-0410)

Ramon de Carvalho Valle discovered that the Linux kernel did not
correctly validate certain memory migration calls. A local attacker
could exploit this to read arbitrary kernel memory or cause a system
crash, leading to a denial of service. (CVE-2010-0415)

Jermome Marchand and Mikael Pettersson discovered that the Linux
kernel did not correctly handle certain futex operations. A local
attacker could exploit this to cause a system crash, leading to a
denial of service. (CVE-2010-0622, CVE-2010-0623).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/17");
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

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-386", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-686", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-server", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-55-server", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-386", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-686", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-generic", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-k8", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-server", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-amd64-xeon", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-55-server", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-55.83")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-386", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-generic", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-openvz", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-rt", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-server", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-virtual", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-27-xen", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-386", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-generic", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-lpia", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-lpiacompat", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-openvz", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-rt", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-server", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-virtual", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-27-xen", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-27-386", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-27-generic", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-27-server", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-27-virtual", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-27.68")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-doc-2.6.27", pkgver:"2.6.27-17.46")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-17", pkgver:"2.6.27-17.46")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-17-generic", pkgver:"2.6.27-17.46")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-17-server", pkgver:"2.6.27-17.46")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-17-generic", pkgver:"2.6.27-17.46")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-17-server", pkgver:"2.6.27-17.46")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-17-virtual", pkgver:"2.6.27-17.46")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-libc-dev", pkgver:"2.6.27-17.46")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-source-2.6.27", pkgver:"2.6.27-17.46")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-doc-2.6.28", pkgver:"2.6.28-18.60")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-18", pkgver:"2.6.28-18.60")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-18-generic", pkgver:"2.6.28-18.60")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-18-server", pkgver:"2.6.28-18.60")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-18-generic", pkgver:"2.6.28-18.60")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-18-lpia", pkgver:"2.6.28-18.60")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-18-server", pkgver:"2.6.28-18.60")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-18-versatile", pkgver:"2.6.28-18.60")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-18-virtual", pkgver:"2.6.28-18.60")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-libc-dev", pkgver:"2.6.28-18.60")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-source-2.6.28", pkgver:"2.6.28-18.60")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-doc", pkgver:"2.6.31-20.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-ec2-doc", pkgver:"2.6.31-305.13")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-ec2-source-2.6.31", pkgver:"2.6.31-305.13")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-20", pkgver:"2.6.31-20.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-20-386", pkgver:"2.6.31-20.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-20-generic", pkgver:"2.6.31-20.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-20-generic-pae", pkgver:"2.6.31-20.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-20-server", pkgver:"2.6.31-20.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-305", pkgver:"2.6.31-305.13")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-305-ec2", pkgver:"2.6.31-305.13")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-20-386", pkgver:"2.6.31-20.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-20-generic", pkgver:"2.6.31-20.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-20-generic-pae", pkgver:"2.6.31-20.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-20-lpia", pkgver:"2.6.31-20.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-20-server", pkgver:"2.6.31-20.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-20-virtual", pkgver:"2.6.31-20.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-212-dove", pkgver:"2.6.31-212.26")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-212-dove-z0", pkgver:"2.6.31-212.26")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-305-ec2", pkgver:"2.6.31-305.13")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-libc-dev", pkgver:"2.6.31-20.58")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-source-2.6.31", pkgver:"2.6.31-20.58")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
