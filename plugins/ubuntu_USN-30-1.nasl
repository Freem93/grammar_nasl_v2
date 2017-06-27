#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-30-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20646);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/25 16:34:55 $");

  script_cve_id("CVE-2004-0882", "CVE-2004-0883", "CVE-2004-0949");
  script_xref(name:"USN", value:"30-1");

  script_name(english:"Ubuntu 4.10 : linux-source-2.6.8.1 vulnerabilities (USN-30-1)");
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
"CAN-2004-0883, CAN-2004-0949 :

During an audit of the smb file system implementation within Linux,
several vulnerabilities were discovered ranging from out of bounds
read accesses to kernel level buffer overflows.

To exploit any of these vulnerabilities, an attacker needs
control over the answers of the connected Samba server. This
could be achieved by man-in-the-middle attacks or by taking
over the Samba server with e. g. the recently disclosed
vulnerability in Samba 3.x (see CAN-2004-0882).

While any of these vulnerabilities can be easily used as
remote denial of service exploits against Linux systems, it
is unclear if it is possible for a skilled local or remote
attacker to use any of the possible buffer overflows for
arbitrary code execution in kernel space. So these bugs may
theoretically lead to privilege escalation and total
compromise of the whole system.

http://isec.pl/vulnerabilities/isec-0017-binfmt_elf.txt :

Several flaws have been found in the Linux ELF binary loader's
handling of setuid binaries. Nowadays ELF is the standard format for
Linux executables and libraries. setuid binaries are programs that
have the 'setuid' file permission bit set; they allow to execute a
program under a user id different from the calling user and are mostly
used to allow executing a program with root privileges to normal
users.

The vulnerabilities that were fixed in these updated kernel
packages could lead Denial of Service attacks. They also
might lead to execution of arbitrary code and privilege
escalation on some platforms if an attacker is able to run
setuid programs under some special system conditions (like
very little remaining memory).

Another flaw could allow an attacker to read supposedly
unreadable, but executable suid binaries. The attacker can
then use this to seek faults within the executable.

http://marc.theaimsgroup.com/?l=linux-kernel&m=109776571411003&w=2 :

Bernard Gagnon discovered a memory leak in the mmap raw packet socket
implementation. When a client application (in ELF format) core dumps,
a region of memory stays allocated as a ring buffer. This could be
exploited by a malicious user who repeatedly crashes certain types of
applications until the memory is exhausted, thus causing a Denial of
Service.

Reverted 486 emulation patch :

Ubuntu kernels for the i386 platforms are compiled using the i486
instruction set for performance reasons. Former Ubuntu kernels
contained code which emulated the missing instructions on real 386
processors. However, several actual and potential security flaws have
been discovered in the code, and it was found to be unsupportable. It
might be possible to exploit these vulnerabilities also on i486 and
higher processors.

Therefore support for real i386 processors has ceased. This
updated kernel will only run on i486 and newer processors.

Other architectures supported by Ubuntu (amd64, powerpc) are
not affected.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-3-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-3-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-3-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-3-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-3-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-3-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-3-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-3-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-3-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-3-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-3-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-3-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-3-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-3-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-debian-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/19");
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

if (ubuntu_check(osver:"4.10", pkgname:"linux-doc-2.6.8.1", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-3", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-3-386", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-3-686", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-3-686-smp", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-3-amd64-generic", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-3-amd64-k8", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-3-amd64-k8-smp", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-3-amd64-xeon", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-3-386", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-3-686", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-3-686-smp", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-3-amd64-generic", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-3-amd64-k8", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-3-amd64-k8-smp", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-3-amd64-xeon", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-patch-debian-2.6.8.1", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-source-2.6.8.1", pkgver:"2.6.8.1-16.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-tree-2.6.8.1", pkgver:"2.6.8.1-16.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.8.1 / linux-headers-2.6.8.1-3 / etc");
}
