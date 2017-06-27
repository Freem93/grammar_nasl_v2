#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2409-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79244);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/24 17:37:07 $");

  script_cve_id("CVE-2014-3615", "CVE-2014-3640", "CVE-2014-3689", "CVE-2014-5263", "CVE-2014-5388", "CVE-2014-7815");
  script_xref(name:"USN", value:"2409-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 14.04 LTS / 14.10 : qemu, qemu-kvm vulnerabilities (USN-2409-1)");
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
"Laszlo Ersek discovered that QEMU incorrectly handled memory in the
vga device. A malicious guest could possibly use this issue to read
arbitrary host memory. This issue only affected Ubuntu 14.04 LTS and
Ubuntu 14.10. (CVE-2014-3615)

Xavier Mehrenberger and Stephane Duverger discovered that QEMU
incorrectly handled certain udp packets when using guest networking. A
malicious guest could possibly use this issue to cause a denial of
service. (CVE-2014-3640)

It was discovered that QEMU incorrectly handled parameter validation
in the vmware_vga device. A malicious guest could possibly use this
issue to write into memory of the host, leading to privilege
escalation. (CVE-2014-3689)

It was discovered that QEMU incorrectly handled USB xHCI controller
live migration. An attacker could possibly use this issue to cause a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 14.04 LTS. (CVE-2014-5263)

Michael S. Tsirkin discovered that QEMU incorrectly handled memory in
the ACPI PCI hotplug interface. A malicious guest could possibly use
this issue to access memory of the host, leading to information
disclosure or privilege escalation. This issue only affected Ubuntu
14.04 LTS. (CVE-2014-5388)

James Spadaro discovered that QEMU incorrectly handled certain VNC
bytes_per_pixel values. An attacker having access to a VNC console
could possibly use this issue to cause a guest to crash, resulting in
a denial of service. (CVE-2014-7815).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|12\.04|14\.04|14\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 14.04 / 14.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"qemu-kvm", pkgver:"0.12.3+noroms-0ubuntu9.25")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"qemu-kvm", pkgver:"1.0+noroms-0ubuntu14.19")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system", pkgver:"2.0.0+dfsg-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-aarch64", pkgver:"2.0.0+dfsg-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-arm", pkgver:"2.0.0+dfsg-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-mips", pkgver:"2.0.0+dfsg-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-misc", pkgver:"2.0.0+dfsg-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-ppc", pkgver:"2.0.0+dfsg-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-sparc", pkgver:"2.0.0+dfsg-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-x86", pkgver:"2.0.0+dfsg-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"qemu-system", pkgver:"2.1+dfsg-4ubuntu6.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"qemu-system-aarch64", pkgver:"2.1+dfsg-4ubuntu6.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"qemu-system-arm", pkgver:"2.1+dfsg-4ubuntu6.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"qemu-system-mips", pkgver:"2.1+dfsg-4ubuntu6.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"qemu-system-misc", pkgver:"2.1+dfsg-4ubuntu6.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"qemu-system-ppc", pkgver:"2.1+dfsg-4ubuntu6.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"qemu-system-sparc", pkgver:"2.1+dfsg-4ubuntu6.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"qemu-system-x86", pkgver:"2.1+dfsg-4ubuntu6.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-kvm / qemu-system / qemu-system-aarch64 / qemu-system-arm / etc");
}
