#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-169-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20575);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/10/26 14:05:58 $");

  script_cve_id("CVE-2005-2098", "CVE-2005-2099", "CVE-2005-2456", "CVE-2005-2457", "CVE-2005-2458", "CVE-2005-2459", "CVE-2005-2548", "CVE-2005-2555");
  script_xref(name:"USN", value:"169-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : linux-source-2.6.8.1, linux-source-2.6.10 vulnerabilities (USN-169-1)");
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
"David Howells discovered a local Denial of Service vulnerability in
the key session joining function. Under certain user-triggerable
conditions, a semaphore was not released properly, which caused
processes which also attempted to join a key session to hang forever.
This only affects Ubuntu 5.04 (Hoary Hedgehog). (CAN-2005-2098)

David Howells discovered a local Denial of Service vulnerability in
the keyring allocator. A local attacker could exploit this to crash
the kernel by attempting to add a specially crafted invalid keyring.
This only affects Ubuntu 5.04 (Hoary Hedgehog). (CAN-2005-2099)

Balazs Scheidler discovered a local Denial of Service vulnerability in
the xfrm_compile_policy() function. By calling setsockopt() with an
invalid xfrm_user policy message, a local attacker could cause the
kernel to write to an array beyond its boundaries, thus causing a
kernel crash. (CAN-2005-2456)

Tim Yamin discovered that the driver for compressed ISO file systems
did not sufficiently validate the iput data. By tricking an user into
mounting a malicious CD-ROM with a specially crafted compressed ISO
file system, he could cause a kernel crash. (CAN-2005-2457)

It was discovered that the kernel's embedded zlib compression library
was still vulnerable to two old vulnerabilities of the standalone zlib
library. This library is used by various drivers and can also be used
by third-party modules, so the impact varies. (CAN-2005-2458,
CAN-2005-2459)

Peter Sandstrom discovered a remote Denial of Service vulnerability in
the SNMP handler. Certain UDP packages lead to a function call with
the wrong argument, which resulted in a crash of the network stack.
This only affects Ubuntu 4.10 (Warty Warthog). (CAN-2005-2548)

Herbert Xu discovered that the setsockopt() function was not
restricted to privileged users. This allowed a local attacker to
bypass intended IPSec policies, set invalid policies to exploit flaws
like CAN-2005-2456, or cause a Denial of Service by adding policies
until kernel memory is exhausted. Now the call is restricted to
processes with the CAP_NET_ADMIN capability. (CAN-2005-2555)

The Ubuntu 5.04 kernel update also fixes a memory leak in the 'md'
(Software RAID) driver which eventually lead to kernel memory
exhaustion. Ubuntu 4.10 is not affected by this.
(http://bugs.debian.org/317787)

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-debian-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-ubuntu-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"linux-doc-2.6.8.1", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-386", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-686", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-686-smp", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-generic", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-k8", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-k8-smp", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-xeon", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-386", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-686", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-686-smp", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-generic", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-k8", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-k8-smp", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-xeon", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-patch-debian-2.6.8.1", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-source-2.6.8.1", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-tree-2.6.8.1", pkgver:"2.6.8.1-16.21")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-doc-2.6.10", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-386", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-686", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-686-smp", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-amd64-generic", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-amd64-k8", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-amd64-k8-smp", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-amd64-xeon", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-386", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-686", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-686-smp", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-amd64-generic", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-amd64-k8", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-amd64-k8-smp", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-amd64-xeon", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-patch-ubuntu-2.6.10", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-source-2.6.10", pkgver:"2.6.10-34.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-tree-2.6.10", pkgver:"2.6.10-34.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.10 / linux-doc-2.6.8.1 / linux-headers-2.6 / etc");
}
