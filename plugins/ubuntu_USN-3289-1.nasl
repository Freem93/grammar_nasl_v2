#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3289-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100250);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/17 14:19:07 $");

  script_cve_id("CVE-2017-7377", "CVE-2017-7718", "CVE-2017-7980", "CVE-2017-8086", "CVE-2017-8309", "CVE-2017-8379");
  script_xref(name:"USN", value:"3289-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 16.10 / 17.04 : qemu vulnerabilities (USN-3289-1)");
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
"Li Qiang discovered that QEMU incorrectly handled VirtFS directory
sharing. A privileged attacker inside the guest could use this issue
to cause QEMU to crash, resulting in a denial of service.
(CVE-2017-7377, CVE-2017-8086)

Jiangxin discovered that QEMU incorrectly handled the Cirrus VGA
device. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service. (CVE-2017-7718)

Li Qiang and Jiangxin discovered that QEMU incorrectly handled the
Cirrus VGA device when being used with a VNC connection. A privileged
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service, or possibly execute arbitrary code
on the host. In the default installation, when QEMU is used with
libvirt, attackers would be isolated by the libvirt AppArmor profile.
(CVE-2017-7980)

Jiang Xin discovered that QEMU incorrectly handled the audio
subsystem. A privileged attacker inside the guest could use this issue
to cause QEMU to crash, resulting in a denial of service.
(CVE-2017-8309)

Jiang Xin discovered that QEMU incorrectly handled the input
subsystem. A privileged attacker inside the guest could use this issue
to cause QEMU to crash, resulting in a denial of service. This issue
only affected Ubuntu 16.04 LTS, Ubuntu 16.10 and Ubuntu 17.04.
(CVE-2017-8379).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04|16\.04|16\.10|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 16.10 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"qemu-system", pkgver:"2.0.0+dfsg-2ubuntu1.34")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-aarch64", pkgver:"2.0.0+dfsg-2ubuntu1.34")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-arm", pkgver:"2.0.0+dfsg-2ubuntu1.34")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-mips", pkgver:"2.0.0+dfsg-2ubuntu1.34")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-misc", pkgver:"2.0.0+dfsg-2ubuntu1.34")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-ppc", pkgver:"2.0.0+dfsg-2ubuntu1.34")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-sparc", pkgver:"2.0.0+dfsg-2ubuntu1.34")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-x86", pkgver:"2.0.0+dfsg-2ubuntu1.34")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system", pkgver:"1:2.5+dfsg-5ubuntu10.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-aarch64", pkgver:"1:2.5+dfsg-5ubuntu10.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-arm", pkgver:"1:2.5+dfsg-5ubuntu10.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-mips", pkgver:"1:2.5+dfsg-5ubuntu10.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-misc", pkgver:"1:2.5+dfsg-5ubuntu10.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-ppc", pkgver:"1:2.5+dfsg-5ubuntu10.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-s390x", pkgver:"1:2.5+dfsg-5ubuntu10.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-sparc", pkgver:"1:2.5+dfsg-5ubuntu10.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-x86", pkgver:"1:2.5+dfsg-5ubuntu10.14")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system", pkgver:"1:2.6.1+dfsg-0ubuntu5.5")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-aarch64", pkgver:"1:2.6.1+dfsg-0ubuntu5.5")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-arm", pkgver:"1:2.6.1+dfsg-0ubuntu5.5")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-mips", pkgver:"1:2.6.1+dfsg-0ubuntu5.5")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-misc", pkgver:"1:2.6.1+dfsg-0ubuntu5.5")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-ppc", pkgver:"1:2.6.1+dfsg-0ubuntu5.5")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-s390x", pkgver:"1:2.6.1+dfsg-0ubuntu5.5")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-sparc", pkgver:"1:2.6.1+dfsg-0ubuntu5.5")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-x86", pkgver:"1:2.6.1+dfsg-0ubuntu5.5")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system", pkgver:"1:2.8+dfsg-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-aarch64", pkgver:"1:2.8+dfsg-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-arm", pkgver:"1:2.8+dfsg-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-mips", pkgver:"1:2.8+dfsg-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-misc", pkgver:"1:2.8+dfsg-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-ppc", pkgver:"1:2.8+dfsg-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-s390x", pkgver:"1:2.8+dfsg-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-sparc", pkgver:"1:2.8+dfsg-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-x86", pkgver:"1:2.8+dfsg-3ubuntu2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-system / qemu-system-aarch64 / qemu-system-arm / etc");
}
