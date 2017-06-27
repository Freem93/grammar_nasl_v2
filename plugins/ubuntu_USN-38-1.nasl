#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-38-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20654);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_cve_id("CVE-2004-0814", "CVE-2004-1016", "CVE-2004-1056", "CVE-2004-1058", "CVE-2004-1068", "CVE-2004-1069", "CVE-2004-1137", "CVE-2004-1151");
  script_xref(name:"USN", value:"38-1");

  script_name(english:"Ubuntu 4.10 : linux-source-2.6.8.1 vulnerabilities (USN-38-1)");
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
"CAN-2004-0814 :

Vitaly V. Bursov discovered a Denial of Service vulnerability in the
'serio' code; opening the same tty device twice and doing some
particular operations on it caused a kernel panic and/or a system
lockup. 

Fixing this vulnerability required a change in the
Application Binary Interface (ABI) of the kernel. This means
that third-party user installed modules might not work any
more with the new kernel, so this fixed kernel got a new ABI
version number. You have to recompile and reinstall all
third-party modules.

CAN-2004-1016 :

Paul Starzetz discovered a buffer overflow vulnerability in the
'__scm_send' function which handles the sending of UDP network
packets. A wrong validity check of the cmsghdr structure allowed a
local attacker to modify kernel memory, thus causing an endless loop
(Denial of Service) or possibly even root privilege escalation.

CAN-2004-1056 :

Thomas Hellstrom discovered a Denial of Service vulnerability in the
Direct Rendering Manager (DRM) drivers. Due to an insufficient DMA
lock checking, any authorized client could send arbitrary values to
the video card, which could cause an X server crash or modification of
the video output.

CAN-2004-1058 :

Rob Landley discovered a race condition in the handling of
/proc/.../cmdline. Under very rare circumstances an user could read
the environment variables of another process that was still spawning.
Environment variables are often used to pass passwords and other
private information to other processes.

CAN-2004-1068 :

A race condition was discovered in the handling of AF_UNIX network
packets. This reportedly allowed local users to modify arbitrary
kernel memory, facilitating privilege escalation, or possibly allowing
code execution in the context of the kernel.

CAN-2004-1069 :

Ross Kendall Axe discovered a possible kernel panic (causing a Denial
of Service) while sending AF_UNIX network packages if the kernel
options CONFIG_SECURITY_NETWORK and CONFIG_SECURITY_SELINUX are
enabled. This is not the case in the kernel packages shipped in Warty
Warthog; however, if you recompiled the kernel using SELinux, you are
affected by this flaw.

CAN-2004-1137 :

Paul Starzetz discovered several flaws in the IGMP handling code. This
allowed users to provoke a Denial of Service, read kernel memory, and
execute arbitrary code with root privileges. This flaw is also
exploitable remotely if an application has bound a multicast socket.

CAN-2004-1151 :

Jeremy Fitzhardinge discovered two buffer overflows in the
sys32_ni_syscall() and sys32_vm86_warning() functions. This could
possibly be exploited to overwrite kernel memory with
attacker-supplied code and cause root privilege escalation. 

This vulnerability only affects the amd64 architecture.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-control");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-driver-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-4-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-4-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-4-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-4-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-4-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-4-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-4-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-4-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-4-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-4-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-4-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-4-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-4-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-4-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-debian-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6.8.1-4-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6.8.1-4-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6.8.1-4-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6.8.1-4-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6.8.1-4-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6.8.1-4-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6.8.1-4-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2004-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"fglrx-control", pkgver:"2.6.8.1.3-5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"fglrx-driver", pkgver:"2.6.8.1.3-5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"fglrx-driver-dev", pkgver:"2.6.8.1.3-5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-386", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-686", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-686-smp", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-amd64-generic", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-amd64-k8", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-amd64-k8-smp", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-amd64-xeon", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-doc", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-doc-2.6.8.1", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6-386", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6-686", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6-686-smp", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6-amd64-generic", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6-amd64-k8", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6-amd64-k8-smp", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6-amd64-xeon", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-4", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-4-386", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-4-686", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-4-686-smp", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-4-amd64-generic", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-4-amd64-k8", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-4-amd64-k8-smp", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-4-amd64-xeon", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6-386", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6-686", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6-686-smp", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6-amd64-generic", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6-amd64-k8", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6-amd64-k8-smp", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6-amd64-xeon", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-4-386", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-4-686", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-4-686-smp", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-4-amd64-generic", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-4-amd64-k8", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-4-amd64-k8-smp", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-4-amd64-xeon", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-386", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-686", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-686-smp", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-amd64-generic", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-amd64-k8", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-amd64-k8-smp", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-amd64-xeon", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-patch-debian-2.6.8.1", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6-386", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6-686", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6-686-smp", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6-amd64-generic", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6-amd64-k8", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6-amd64-k8-smp", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6-amd64-xeon", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6.8.1-4-386", pkgver:"2.6.8.1.3-5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6.8.1-4-686", pkgver:"2.6.8.1.3-5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6.8.1-4-686-smp", pkgver:"2.6.8.1.3-5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6.8.1-4-amd64-generic", pkgver:"2.6.8.1.3-5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6.8.1-4-amd64-k8", pkgver:"2.6.8.1.3-5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6.8.1-4-amd64-k8-smp", pkgver:"2.6.8.1.3-5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-2.6.8.1-4-amd64-xeon", pkgver:"2.6.8.1.3-5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-386", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-686", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-686-smp", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-amd64-generic", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-amd64-k8", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-amd64-k8-smp", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-restricted-modules-amd64-xeon", pkgver:"2.6.8.1-14")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-source-2.6.8.1", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-tree-2.6.8.1", pkgver:"2.6.8.1-16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"nvidia-glx", pkgver:"1.0.6111-1ubuntu8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"nvidia-glx-dev", pkgver:"1.0.6111-1ubuntu8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"nvidia-kernel-source", pkgver:"1.0.6111-1ubuntu8")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fglrx-control / fglrx-driver / fglrx-driver-dev / linux-386 / etc");
}
