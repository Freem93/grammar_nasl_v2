#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3125-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94669);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2016-5403", "CVE-2016-6833", "CVE-2016-6834", "CVE-2016-6835", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7116", "CVE-2016-7155", "CVE-2016-7156", "CVE-2016-7157", "CVE-2016-7161", "CVE-2016-7170", "CVE-2016-7421", "CVE-2016-7422", "CVE-2016-7423", "CVE-2016-7466", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-7994", "CVE-2016-7995", "CVE-2016-8576", "CVE-2016-8577", "CVE-2016-8578", "CVE-2016-8668", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9101", "CVE-2016-9102", "CVE-2016-9103", "CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106");
  script_osvdb_id(142178, 142870, 142871, 142872, 142873, 143254, 143611, 143827, 143828, 143829, 144061, 144405, 144406, 144407, 144641, 144787, 145043, 145163, 145315, 145316, 145362, 145385, 145397, 145696, 146244, 146245, 146387, 146388, 146389, 146390, 146391, 146392);
  script_xref(name:"USN", value:"3125-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : qemu, qemu-kvm vulnerabilities (USN-3125-1)");
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
"Zhenhao Hong discovered that QEMU incorrectly handled the Virtio
module. A privileged attacker inside the guest could use this issue to
cause QEMU to consume resources, resulting in a denial of service.
(CVE-2016-5403)

Li Qiang discovered that QEMU incorrectly handled VMWARE VMXNET3
network card emulation support. A privileged attacker inside the guest
could use this issue to cause QEMU to crash, resulting in a denial of
service. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS
and Ubuntu 16.10. (CVE-2016-6833, CVE-2016-6834, CVE-2016-6888)

Li Qiang discovered that QEMU incorrectly handled VMWARE VMXNET3
network card emulation support. A privileged attacker inside the guest
could use this issue to cause QEMU to crash, resulting in a denial of
service, or possibly execute arbitrary code on the host. In the
default installation, when QEMU is used with libvirt, attackers would
be isolated by the libvirt AppArmor profile. This issue only affected
Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-6835)

Li Qiang discovered that QEMU incorrectly handled VMWARE VMXNET3
network card emulation support. A privileged attacker inside the guest
could use this issue to possibly to obtain sensitive host memory. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu
16.10. (CVE-2016-6836)

Felix Wilhelm discovered that QEMU incorrectly handled Plan 9 File
System (9pfs) support. A privileged attacker inside the guest could
use this issue to possibly to obtain sensitive host files.
(CVE-2016-7116)

Li Qiang and Tom Victor discovered that QEMU incorrectly handled
VMWARE PVSCSI paravirtual SCSI bus emulation support. A privileged
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service. This issue only affected Ubuntu
14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-7155)

Li Qiang discovered that QEMU incorrectly handled VMWARE PVSCSI
paravirtual SCSI bus emulation support. A privileged attacker inside
the guest could use this issue to cause QEMU to crash, resulting in a
denial of service. This issue only affected Ubuntu 14.04 LTS, Ubuntu
16.04 LTS and Ubuntu 16.10. (CVE-2016-7156, CVE-2016-7421)

Tom Victor discovered that QEMU incorrectly handled LSI SAS1068 host
bus emulation support. A privileged attacker inside the guest could
use this issue to cause QEMU to crash, resulting in a denial of
service. This issue only affected Ubuntu 16.10. (CVE-2016-7157)

Hu Chaojian discovered that QEMU incorrectly handled
xlnx.xps-ethernetlite emulation support. A privileged attacker inside
the guest could use this issue to cause QEMU to crash, resulting in a
denial of service, or possibly execute arbitrary code on the host. In
the default installation, when QEMU is used with libvirt, attackers
would be isolated by the libvirt AppArmor profile. (CVE-2016-7161)

Qinghao Tang and Li Qiang discovered that QEMU incorrectly handled the
VMware VGA module. A privileged attacker inside the guest could use
this issue to cause QEMU to crash, resulting in a denial of service.
(CVE-2016-7170)

Qinghao Tang and Zhenhao Hong discovered that QEMU incorrectly handled
the Virtio module. A privileged attacker inside the guest could use
this issue to cause QEMU to crash, resulting in a denial of service.
This issue only affected Ubuntu 16.10. (CVE-2016-7422)

Li Qiang discovered that QEMU incorrectly handled LSI SAS1068 host bus
emulation support. A privileged attacker inside the guest could use
this issue to cause QEMU to crash, resulting in a denial of service.
This issue only affected Ubuntu 16.10. (CVE-2016-7423)

Li Qiang discovered that QEMU incorrectly handled USB xHCI controller
emulation support. A privileged attacker inside the guest could use
this issue to cause QEMU to crash, resulting in a denial of service.
This issue only affected Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2016-7466)

Li Qiang discovered that QEMU incorrectly handled ColdFire Fast
Ethernet Controller emulation support. A privileged attacker inside
the guest could use this issue to cause QEMU to crash, resulting in a
denial of service. (CVE-2016-7908)

Li Qiang discovered that QEMU incorrectly handled AMD PC-Net II
emulation support. A privileged attacker inside the guest could use
this issue to cause QEMU to crash, resulting in a denial of service.
(CVE-2016-7909)

Li Qiang discovered that QEMU incorrectly handled the Virtio GPU
support. A privileged attacker inside the guest could use this issue
to cause QEMU to consume resources, resulting in a denial of service.
This issue only affected Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2016-7994)

Li Qiang discovered that QEMU incorrectly handled USB EHCI emulation
support. A privileged attacker inside the guest could use this issue
to cause QEMU to consume resources, resulting in a denial of service.
This issue only affected Ubuntu 16.10. (CVE-2016-7995)

Li Qiang discovered that QEMU incorrectly handled USB xHCI controller
support. A privileged attacker inside the guest could use this issue
to cause QEMU to crash, resulting in a denial of service. This issue
only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2016-8576)

Li Qiang discovered that QEMU incorrectly handled Plan 9 File System
(9pfs) support. A privileged attacker inside the guest could use this
issue to cause QEMU to crash, resulting in a denial of service. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu
16.10. (CVE-2016-8577, CVE-2016-8578)

It was discovered that QEMU incorrectly handled Rocker switch
emulation support. A privileged attacker inside the guest could use
this issue to cause QEMU to crash, resulting in a denial of service.
This issue only affected Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2016-8668)

It was discovered that QEMU incorrectly handled Intel HDA controller
emulation support. A privileged attacker inside the guest could use
this issue to cause QEMU to consume resources, resulting in a denial
of service. (CVE-2016-8909)

Andrew Henderson discovered that QEMU incorrectly handled RTL8139
ethernet controller emulation support. A privileged attacker inside
the guest could use this issue to cause QEMU to consume resources,
resulting in a denial of service. (CVE-2016-8910)

Li Qiang discovered that QEMU incorrectly handled Intel i8255x
ethernet controller emulation support. A privileged attacker inside
the guest could use this issue to cause QEMU to consume resources,
resulting in a denial of service. (CVE-2016-9101)

Li Qiang discovered that QEMU incorrectly handled Plan 9 File System
(9pfs) support. A privileged attacker inside the guest could use this
issue to cause QEMU to consume resources, resulting in a denial of
service. (CVE-2016-9102, CVE-2016-9104, CVE-2016-9105)

Li Qiang discovered that QEMU incorrectly handled Plan 9 File System
(9pfs) support. A privileged attacker inside the guest could use this
issue to possibly to obtain sensitive host memory. (CVE-2016-9103)

Li Qiang discovered that QEMU incorrectly handled Plan 9 File System
(9pfs) support. A privileged attacker inside the guest could use this
issue to cause QEMU to consume resources, resulting in a denial of
service. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS
and Ubuntu 16.10. (CVE-2016-9106).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"qemu-kvm", pkgver:"1.0+noroms-0ubuntu14.31")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system", pkgver:"2.0.0+dfsg-2ubuntu1.30")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-aarch64", pkgver:"2.0.0+dfsg-2ubuntu1.30")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-arm", pkgver:"2.0.0+dfsg-2ubuntu1.30")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-mips", pkgver:"2.0.0+dfsg-2ubuntu1.30")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-misc", pkgver:"2.0.0+dfsg-2ubuntu1.30")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-ppc", pkgver:"2.0.0+dfsg-2ubuntu1.30")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-sparc", pkgver:"2.0.0+dfsg-2ubuntu1.30")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-x86", pkgver:"2.0.0+dfsg-2ubuntu1.30")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system", pkgver:"1:2.5+dfsg-5ubuntu10.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-aarch64", pkgver:"1:2.5+dfsg-5ubuntu10.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-arm", pkgver:"1:2.5+dfsg-5ubuntu10.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-mips", pkgver:"1:2.5+dfsg-5ubuntu10.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-misc", pkgver:"1:2.5+dfsg-5ubuntu10.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-ppc", pkgver:"1:2.5+dfsg-5ubuntu10.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-s390x", pkgver:"1:2.5+dfsg-5ubuntu10.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-sparc", pkgver:"1:2.5+dfsg-5ubuntu10.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-x86", pkgver:"1:2.5+dfsg-5ubuntu10.6")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system", pkgver:"1:2.6.1+dfsg-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-aarch64", pkgver:"1:2.6.1+dfsg-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-arm", pkgver:"1:2.6.1+dfsg-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-mips", pkgver:"1:2.6.1+dfsg-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-misc", pkgver:"1:2.6.1+dfsg-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-ppc", pkgver:"1:2.6.1+dfsg-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-s390x", pkgver:"1:2.6.1+dfsg-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-sparc", pkgver:"1:2.6.1+dfsg-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"qemu-system-x86", pkgver:"1:2.6.1+dfsg-0ubuntu5.1")) flag++;

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
