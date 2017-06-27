#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2891-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88576);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2017/03/08 15:07:21 $");

  script_cve_id("CVE-2015-7549", "CVE-2015-8504", "CVE-2015-8550", "CVE-2015-8558", "CVE-2015-8567", "CVE-2015-8568", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8666", "CVE-2015-8743", "CVE-2015-8744", "CVE-2015-8745", "CVE-2016-1568", "CVE-2016-1714", "CVE-2016-1922", "CVE-2016-1981", "CVE-2016-2197", "CVE-2016-2198");
  script_osvdb_id(131399, 131668, 131793, 131824, 132029, 132136, 132210, 132257, 132261, 132466, 132467, 132549, 132550, 132759, 132798, 133524, 133811, 133847);
  script_xref(name:"USN", value:"2891-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 : qemu, qemu-kvm vulnerabilities (USN-2891-1)");
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
"Qinghao Tang discovered that QEMU incorrectly handled PCI MSI-X
support. An attacker inside the guest could use this issue to cause
QEMU to crash, resulting in a denial of service. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-7549)

Lian Yihan discovered that QEMU incorrectly handled the VNC server. A
remote attacker could use this issue to cause QEMU to crash, resulting
in a denial of service. (CVE-2015-8504)

Felix Wilhelm discovered a race condition in the Xen paravirtualized
drivers which can cause double fetch vulnerabilities. An attacker in
the paravirtualized guest could exploit this flaw to cause a denial of
service (crash the host) or potentially execute arbitrary code on the
host. (CVE-2015-8550)

Qinghao Tang discovered that QEMU incorrectly handled USB EHCI
emulation support. An attacker inside the guest could use this issue
to cause QEMU to consume resources, resulting in a denial of service.
(CVE-2015-8558)

Qinghao Tang discovered that QEMU incorrectly handled the vmxnet3
device. An attacker inside the guest could use this issue to cause
QEMU to consume resources, resulting in a denial of service. This
issue only affected Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-8567,
CVE-2015-8568)

Qinghao Tang discovered that QEMU incorrectly handled SCSI MegaRAID
SAS HBA emulation. An attacker inside the guest could use this issue
to cause QEMU to crash, resulting in a denial of service. This issue
only affected Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-8613)

Ling Liu discovered that QEMU incorrectly handled the Human Monitor
Interface. A local attacker could use this issue to cause QEMU to
crash, resulting in a denial of service. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-8619, CVE-2016-1922)

David Alan Gilbert discovered that QEMU incorrectly handled the Q35
chipset emulation when performing VM guest migrations. An attacker
could use this issue to cause QEMU to crash, resulting in a denial of
service. This issue only affected Ubuntu 14.04 LTS and Ubuntu 15.10.
(CVE-2015-8666)

Ling Liu discovered that QEMU incorrectly handled the NE2000 device.
An attacker inside the guest could use this issue to cause QEMU to
crash, resulting in a denial of service. (CVE-2015-8743)

It was discovered that QEMU incorrectly handled the vmxnet3 device. An
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service. This issue only affected Ubuntu
14.04 LTS and Ubuntu 15.10. (CVE-2015-8744, CVE-2015-8745)

Qinghao Tang discovered that QEMU incorrect handled IDE AHCI
emulation. An attacker inside the guest could use this issue to cause
a denial of service, or possibly execute arbitrary code on the host as
the user running the QEMU process. In the default installation, when
QEMU is used with libvirt, attackers would be isolated by the libvirt
AppArmor profile. (CVE-2016-1568)

Donghai Zhu discovered that QEMU incorrect handled the firmware
configuration device. An attacker inside the guest could use this
issue to cause a denial of service, or possibly execute arbitrary code
on the host as the user running the QEMU process. In the default
installation, when QEMU is used with libvirt, attackers would be
isolated by the libvirt AppArmor profile. (CVE-2016-1714)

It was discovered that QEMU incorrectly handled the e1000 device. An
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service. (CVE-2016-1981)

Zuozhi Fzz discovered that QEMU incorrectly handled IDE AHCI
emulation. An attacker inside the guest could use this issue to cause
QEMU to crash, resulting in a denial of service. This issue only
affected Ubuntu 15.10. (CVE-2016-2197)

Zuozhi Fzz discovered that QEMU incorrectly handled USB EHCI
emulation. An attacker inside the guest could use this issue to cause
QEMU to crash, resulting in a denial of service. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2016-2198).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016-2017 Canonical, Inc. / NASL script (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"qemu-kvm", pkgver:"1.0+noroms-0ubuntu14.27")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system", pkgver:"2.0.0+dfsg-2ubuntu1.22")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-aarch64", pkgver:"2.0.0+dfsg-2ubuntu1.22")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-arm", pkgver:"2.0.0+dfsg-2ubuntu1.22")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-mips", pkgver:"2.0.0+dfsg-2ubuntu1.22")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-misc", pkgver:"2.0.0+dfsg-2ubuntu1.22")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-ppc", pkgver:"2.0.0+dfsg-2ubuntu1.22")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-sparc", pkgver:"2.0.0+dfsg-2ubuntu1.22")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-x86", pkgver:"2.0.0+dfsg-2ubuntu1.22")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system", pkgver:"1:2.3+dfsg-5ubuntu9.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-aarch64", pkgver:"1:2.3+dfsg-5ubuntu9.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-arm", pkgver:"1:2.3+dfsg-5ubuntu9.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-mips", pkgver:"1:2.3+dfsg-5ubuntu9.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-misc", pkgver:"1:2.3+dfsg-5ubuntu9.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-ppc", pkgver:"1:2.3+dfsg-5ubuntu9.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-sparc", pkgver:"1:2.3+dfsg-5ubuntu9.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-x86", pkgver:"1:2.3+dfsg-5ubuntu9.2")) flag++;

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
