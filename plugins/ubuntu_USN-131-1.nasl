#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-131-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20522);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/10/26 14:05:57 $");

  script_cve_id("CVE-2005-0109", "CVE-2005-1041", "CVE-2005-1263", "CVE-2005-1264", "CVE-2005-1368", "CVE-2005-1369", "CVE-2005-1589");
  script_xref(name:"USN", value:"131-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : linux-source-2.6.8.1, linux-source-2.6.10 vulnerabilities (USN-131-1)");
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
"Colin Percival discovered an information disclosure in the 'Hyper
Threading Technology' architecture in processors which are capable of
simultaneous multithreading (in particular Intel Pentium 4, Intel
Mobile Pentium 4, and Intel Xeon processors). This allows a malicious
thread to monitor the execution of another thread on the same CPU.
This could be exploited to steal cryptographic keys, passwords, or
other arbitrary data from unrelated processes. Since it is not
possible to provide a safe patch in a short time, HyperThreading has
been disabled in the updated kernel packages for now. You can manually
enable HyperThreading again by passing the kernel parameter 'ht=on' at
boot. (CAN-2005-0109)

A Denial of Service vulnerability was discovered in the
fib_seq_start() function(). This allowed a local user to crash the
system by reading /proc/net/route in a certain way. (CAN-2005-1041)

Paul Starzetz found an integer overflow in the ELF binary format
loader's core dump function. By creating and executing a specially
crafted ELF executable, a local attacker could exploit this to execute
arbitrary code with root and kernel privileges. However, it is
believed that this flaw is not actually exploitable on 2.6.x kernels
(as shipped by Ubuntu). (CAN-2005-1263)

Alexander Nyberg discovered a flaw in the keyring kernel module. This
allowed a local attacker to cause a kernel crash on SMP machines by
calling key_user_lookup() in a particular way. This vulnerability does
not affect the kernel of Ubuntu 4.10. (CAN-2005-1368)

The it87 and via686a hardware monitoring drivers created a sysfs file
named 'alarms' with write permissions, but they are not designed to be
writeable. This allowed a local user to crash the kernel by attempting
to write to these files. (CAN-2005-1369)

It was discovered that the drivers for raw devices (CAN-2005-1264) and
pktcdvd devices (CAN-2005-1589) used the wrong function to pass
arguments to the underlying block device. This made the kernel address
space accessible to userspace applications. This allowed any local
user with at least read access to a device in /dev/pktcdvd/* (usually
members of the 'cdrom' group) or /dev/raw/* (usually only root) to
execute arbitrary code with kernel privileges. Ubuntu 4.10's kernel is
not affected by the pktcdvd flaw since it does not yet support packet
CD writing.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/23");
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

if (ubuntu_check(osver:"4.10", pkgname:"linux-doc-2.6.8.1", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-386", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-686", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-686-smp", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-generic", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-k8", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-k8-smp", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-xeon", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-386", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-686", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-686-smp", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-generic", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-k8", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-k8-smp", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-xeon", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-patch-debian-2.6.8.1", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-source-2.6.8.1", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-tree-2.6.8.1", pkgver:"2.6.8.1-16.18")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-doc-2.6.10", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-386", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-686", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-686-smp", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-amd64-generic", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-amd64-k8", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-amd64-k8-smp", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-amd64-xeon", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-386", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-686", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-686-smp", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-amd64-generic", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-amd64-k8", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-amd64-k8-smp", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-amd64-xeon", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-patch-ubuntu-2.6.10", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-source-2.6.10", pkgver:"2.6.10-34.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-tree-2.6.10", pkgver:"2.6.10-34.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.10 / linux-doc-2.6.8.1 / linux-headers-2.6 / etc");
}
