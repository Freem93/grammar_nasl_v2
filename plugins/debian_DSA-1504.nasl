#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1504. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31148);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2006-5823", "CVE-2006-6054", "CVE-2006-6058", "CVE-2006-7203", "CVE-2007-1353", "CVE-2007-2172", "CVE-2007-2525", "CVE-2007-3105", "CVE-2007-3739", "CVE-2007-3740", "CVE-2007-3848", "CVE-2007-4133", "CVE-2007-4308", "CVE-2007-4573", "CVE-2007-5093", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6694", "CVE-2008-0007");
  script_osvdb_id(40911, 40913, 42716);
  script_xref(name:"DSA", value:"1504");

  script_name(english:"Debian DSA-1504-1 : kernel-source-2.6.8 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local and remote vulnerabilities have been discovered in the
Linux kernel that may lead to a denial of service or the execution of
arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2006-5823
    LMH reported a potential local DoS which could be
    exploited by a malicious user with the privileges to
    mount and read a corrupted cramfs filesystem.

  - CVE-2006-6054
    LMH reported a potential local DoS which could be
    exploited by a malicious user with the privileges to
    mount and read a corrupted ext2 filesystem.

  - CVE-2006-6058
    LMH reported an issue in the minix filesystem that
    allows local users with mount privileges to create a DoS
    (printk flood) by mounting a specially crafted corrupt
    filesystem.

  - CVE-2006-7203
    OpenVZ Linux kernel team reported an issue in the smbfs
    filesystem which can be exploited by local users to
    cause a DoS (oops) during mount.

  - CVE-2007-1353
    Ilja van Sprundel discovered that kernel memory could be
    leaked via the Bluetooth setsockopt call due to an
    uninitialized stack buffer. This could be used by local
    attackers to read the contents of sensitive kernel
    memory.

  - CVE-2007-2172
    Thomas Graf reported a typo in the DECnet protocol
    handler that could be used by a local attacker to
    overrun an array via crafted packets, potentially
    resulting in a Denial of Service (system crash). A
    similar issue exists in the IPV4 protocol handler and
    will be fixed in a subsequent update.

  - CVE-2007-2525
    Florian Zumbiehl discovered a memory leak in the PPPOE
    subsystem caused by releasing a socket before
    PPPIOCGCHAN is called upon it. This could be used by a
    local user to DoS a system by consuming all available
    memory.

  - CVE-2007-3105
    The PaX Team discovered a potential buffer overflow in
    the random number generator which may permit local users
    to cause a denial of service or gain additional
    privileges. This issue is not believed to effect default
    Debian installations where only root has sufficient
    privileges to exploit it.

  - CVE-2007-3739
    Adam Litke reported a potential local denial of service
    (oops) on powerpc platforms resulting from unchecked VMA
    expansion into address space reserved for hugetlb pages.

  - CVE-2007-3740
    Steve French reported that CIFS filesystems with
    CAP_UNIX enabled were not honoring a process' umask
    which may lead to unintentionally relaxed permissions.

  - CVE-2007-3848
    Wojciech Purczynski discovered that pdeath_signal was
    not being reset properly under certain conditions which
    may allow local users to gain privileges by sending
    arbitrary signals to suid binaries.

  - CVE-2007-4133
    Hugh Dickins discovered a potential local DoS (panic) in
    hugetlbfs. A misconversion of hugetlb_vmtruncate_list to
    prio_tree may allow local users to trigger a BUG_ON()
    call in exit_mmap.

  - CVE-2007-4308
    Alan Cox reported an issue in the aacraid driver that
    allows unprivileged local users to make ioctl calls
    which should be restricted to admin privileges.

  - CVE-2007-4573
    Wojciech Purczynski discovered a vulnerability that can
    be exploited by a local user to obtain superuser
    privileges on x86_64 systems. This resulted from
    improper clearing of the high bits of registers during
    ia32 system call emulation. This vulnerability is
    relevant to the Debian amd64 port as well as users of
    the i386 port who run the amd64 linux-image flavour.

  - CVE-2007-5093
    Alex Smith discovered an issue with the pwc driver for
    certain webcam devices. If the device is removed while a
    userspace application has it open, the driver will wait
    for userspace to close the device, resulting in a
    blocked USB subsystem. This issue is of low security
    impact as it requires the attacker to either have
    physical access to the system or to convince a user with
    local access to remove the device on their behalf.

  - CVE-2007-6063
    Venustech AD-LAB discovered a a buffer overflow in the
    isdn ioctl handling, exploitable by a local user.

  - CVE-2007-6151
    ADLAB discovered a possible memory overrun in the ISDN
    subsystem that may permit a local user to overwrite
    kernel memory by issuing ioctls with unterminated data.

  - CVE-2007-6206
    Blake Frantz discovered that when a core file owned by a
    non-root user exists, and a root-owned process dumps
    core over it, the core file retains its original
    ownership. This could be used by a local user to gain
    access to sensitive information.

  - CVE-2007-6694
    Cyrill Gorcunov reported a NULL pointer dereference in
    code specific to the CHRP PowerPC platforms. Local users
    could exploit this issue to achieve a Denial of Service
    (DoS).

  - CVE-2008-0007
    Nick Piggin of SuSE discovered a number of issues in
    subsystems which register a fault handler for memory
    mapped areas. This issue can be exploited by local users
    to achieve a Denial of Service (DoS) and possibly
    execute arbitrary code.

The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update :

                             Debian 3.1 (sarge)          
  kernel-image-2.6.8-alpha    2.6.8-17sarge1              
  kernel-image-2.6.8-amd64    2.6.8-17sarge1              
  kernel-image-2.6.8-hppa     2.6.8-7sarge1               
  kernel-image-2.6.8-i386     2.6.8-17sarge1              
  kernel-image-2.6.8-ia64     2.6.8-15sarge1              
  kernel-image-2.6.8-m68k     2.6.8-5sarge1               
  kernel-image-2.6.8-s390     2.6.8-6sarge1               
  kernel-image-2.6.8-sparc    2.6.8-16sarge1              
  kernel-patch-powerpc-2.6.8  2.6.8-13sarge1              
  fai-kernels                 1.9.1sarge8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-7203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1504"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel package immediately and reboot the machine. If you
have built a custom kernel from the kernel source package, you will
need to rebuild to take advantage of these fixes."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(16, 20, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.6.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"3.1", prefix:"fai-kernels", reference:"1.9.1sarge8")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4-power3", reference:"2.6.8-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4-power3-smp", reference:"2.6.8-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4-power4", reference:"2.6.8-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4-power4-smp", reference:"2.6.8-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4-powerpc", reference:"2.6.8-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4-powerpc-smp", reference:"2.6.8-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.6.8", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium-smp", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley-smp", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-13", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-13-amd64-generic", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-13-amd64-k8", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-13-amd64-k8-smp", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-13-em64t-p4", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-13-em64t-p4-smp", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-32", reference:"2.6.8-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-32-smp", reference:"2.6.8-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-386", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-64", reference:"2.6.8-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-64-smp", reference:"2.6.8-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-686", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-686-smp", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-generic", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-itanium", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-itanium-smp", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-k7", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-k7-smp", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-mckinley", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-mckinley-smp", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-smp", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-sparc32", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-sparc64", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-sparc64-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium-smp", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley-smp", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-13-amd64-generic", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-13-amd64-k8", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-13-amd64-k8-smp", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-13-em64t-p4", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-13-em64t-p4-smp", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-32", reference:"2.6.8-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-32-smp", reference:"2.6.8-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-386", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-64", reference:"2.6.8-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-64-smp", reference:"2.6.8-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-686", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-686-smp", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-generic", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-itanium", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-itanium-smp", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-k7", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-k7-smp", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-mckinley", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-mckinley-smp", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-power3", reference:"2.6.8-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-power3-smp", reference:"2.6.8-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-power4", reference:"2.6.8-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-power4-smp", reference:"2.6.8-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-powerpc", reference:"2.6.8-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-powerpc-smp", reference:"2.6.8-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-s390", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-s390-tape", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-s390x", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-smp", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-sparc32", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-sparc64", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-sparc64-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-amiga", reference:"2.6.8-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-atari", reference:"2.6.8-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-bvme6000", reference:"2.6.8-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-hp", reference:"2.6.8-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mac", reference:"2.6.8-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme147", reference:"2.6.8-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme16x", reference:"2.6.8-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-q40", reference:"2.6.8-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-sun3", reference:"2.6.8-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.6.8-s390", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-debian-2.6.8", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-source-2.6.8", reference:"2.6.8-17sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-tree-2.6.8", reference:"2.6.8-17sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
