#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2828-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87205);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2015-7295", "CVE-2015-7504", "CVE-2015-7512", "CVE-2015-8345");
  script_osvdb_id(127769, 130703, 130888, 130889);
  script_xref(name:"USN", value:"2828-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 / 15.10 : qemu, qemu-kvm vulnerabilities (USN-2828-1)");
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
"Jason Wang discovered that QEMU incorrectly handled the virtio-net
device. A remote attacker could use this issue to cause guest network
consumption, resulting in a denial of service. (CVE-2015-7295)

Qinghao Tang and Ling Liu discovered that QEMU incorrectly handled the
pcnet driver when used in loopback mode. A malicious guest could use
this issue to cause a denial of service, or possibly execute arbitrary
code on the host as the user running the QEMU process. In the default
installation, when QEMU is used with libvirt, attackers would be
isolated by the libvirt AppArmor profile. (CVE-2015-7504)

Ling Liu and Jason Wang discovered that QEMU incorrectly handled the
pcnet driver. A remote attacker could use this issue to cause a denial
of service, or possibly execute arbitrary code on the host as the user
running the QEMU process. In the default installation, when QEMU is
used with libvirt, attackers would be isolated by the libvirt AppArmor
profile. (CVE-2015-7512)

Qinghao Tang discovered that QEMU incorrectly handled the eepro100
driver. A malicious guest could use this issue to cause an infinite
loop, leading to a denial of service. (CVE-2015-8345).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"qemu-kvm", pkgver:"1.0+noroms-0ubuntu14.26")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system", pkgver:"2.0.0+dfsg-2ubuntu1.21")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-aarch64", pkgver:"2.0.0+dfsg-2ubuntu1.21")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-arm", pkgver:"2.0.0+dfsg-2ubuntu1.21")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-mips", pkgver:"2.0.0+dfsg-2ubuntu1.21")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-misc", pkgver:"2.0.0+dfsg-2ubuntu1.21")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-ppc", pkgver:"2.0.0+dfsg-2ubuntu1.21")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-sparc", pkgver:"2.0.0+dfsg-2ubuntu1.21")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-x86", pkgver:"2.0.0+dfsg-2ubuntu1.21")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"qemu-system", pkgver:"1:2.2+dfsg-5expubuntu9.7")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"qemu-system-aarch64", pkgver:"1:2.2+dfsg-5expubuntu9.7")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"qemu-system-arm", pkgver:"1:2.2+dfsg-5expubuntu9.7")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"qemu-system-mips", pkgver:"1:2.2+dfsg-5expubuntu9.7")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"qemu-system-misc", pkgver:"1:2.2+dfsg-5expubuntu9.7")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"qemu-system-ppc", pkgver:"1:2.2+dfsg-5expubuntu9.7")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"qemu-system-sparc", pkgver:"1:2.2+dfsg-5expubuntu9.7")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"qemu-system-x86", pkgver:"1:2.2+dfsg-5expubuntu9.7")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system", pkgver:"1:2.3+dfsg-5ubuntu9.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-aarch64", pkgver:"1:2.3+dfsg-5ubuntu9.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-arm", pkgver:"1:2.3+dfsg-5ubuntu9.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-mips", pkgver:"1:2.3+dfsg-5ubuntu9.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-misc", pkgver:"1:2.3+dfsg-5ubuntu9.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-ppc", pkgver:"1:2.3+dfsg-5ubuntu9.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-sparc", pkgver:"1:2.3+dfsg-5ubuntu9.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"qemu-system-x86", pkgver:"1:2.3+dfsg-5ubuntu9.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-kvm / qemu-system / qemu-system-aarch64 / qemu-system-arm / etc");
}
