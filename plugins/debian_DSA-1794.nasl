#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1794. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(38722);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-4307", "CVE-2008-5395", "CVE-2008-5701", "CVE-2008-5702", "CVE-2008-5713", "CVE-2009-0028", "CVE-2009-0029", "CVE-2009-0031", "CVE-2009-0065", "CVE-2009-0322", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0834", "CVE-2009-0859", "CVE-2009-1192", "CVE-2009-1265", "CVE-2009-1336", "CVE-2009-1337", "CVE-2009-1439");
  script_bugtraq_id(33113, 33846, 33951, 34020, 34405, 34453, 34654, 34673);
  script_xref(name:"DSA", value:"1794");

  script_name(english:"Debian DSA-1794-1 : linux-2.6 - denial of service/privilege escalation/information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to denial of service, privilege escalation, or information
leak. The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2008-4307
    Bryn M. Reeves reported a denial of service in the NFS
    filesystem. Local users can trigger a kernel BUG() due
    to a race condition in the do_setlk function.

  - CVE-2008-5395
    Helge Deller discovered a denial of service condition
    that allows local users on PA-RISC to crash the system
    by attempting to unwind a stack containing userspace
    addresses.

  - CVE-2008-5701
    Vlad Malov reported an issue on 64-bit MIPS where a
    local user could cause a system crash by crafting a
    malicious binary which makes o32 syscalls with a number
    less than 4000.

  - CVE-2008-5702
    Zvonimir Rakamaric reported an off-by-one error in the
    ib700wdt watchdog driver which allows local users to
    cause a buffer underflow by making a specially crafted
    WDIOC_SETTIMEOUT ioctl call.

  - CVE-2008-5713
    Flavio Leitner discovered that a local user can cause a
    denial of service by generating large amounts of traffic
    on a large SMP system, resulting in soft lockups.

  - CVE-2009-0028
    Chris Evans discovered a situation in which a child
    process can send an arbitrary signal to its parent.

  - CVE-2009-0029
    Christian Borntraeger discovered an issue effecting the
    alpha, mips, powerpc, s390 and sparc64 architectures
    that allows local users to cause a denial of service or
    potentially gain elevated privileges.

  - CVE-2009-0031
    Vegard Nossum discovered a memory leak in the keyctl
    subsystem that allows local users to cause a denial of
    service by consuming all available kernel memory.

  - CVE-2009-0065
    Wei Yongjun discovered a memory overflow in the SCTP
    implementation that can be triggered by remote users,
    permitting remote code execution.

  - CVE-2009-0322
    Pavel Roskin provided a fix for an issue in the dell_rbu
    driver that allows a local user to cause a denial of
    service (oops) by reading 0 bytes from a sysfs entry.

  - CVE-2009-0675
    Roel Kluin discovered inverted logic in the skfddi
    driver that permits local, unprivileged users to reset
    the driver statistics.

  - CVE-2009-0676
    Clement LECIGNE discovered a bug in the sock_getsockopt
    function that may result in leaking sensitive kernel
    memory.

  - CVE-2009-0834
    Roland McGrath discovered an issue on amd64 kernels that
    allows local users to circumvent system call audit
    configurations which filter based on the syscall numbers
    or argument details.

  - CVE-2009-0859
    Jiri Olsa discovered that a local user can cause a
    denial of service (system hang) using a SHM_INFO shmctl
    call on kernels compiled with CONFIG_SHMEM disabled.
    This issue does not affect prebuilt Debian kernels.

  - CVE-2009-1192
    Shaohua Li reported an issue in the AGP subsystem that
    may allow local users to read sensitive kernel memory
    due to a leak of uninitialized memory.

  - CVE-2009-1265
    Thomas Pollet reported an overflow in the af_rose
    implementation that allows remote attackers to retrieve
    uninitialized kernel memory that may contain sensitive
    data.

  - CVE-2009-1336
    Trond Myklebust reported an issue in the encode_lookup()
    function in the nfs server subsystem that allows local
    users to cause a denial of service (oops in
    encode_lookup()) by use of a long filename.

  - CVE-2009-1337
    Oleg Nesterov discovered an issue in the exit_notify
    function that allows local users to send an arbitrary
    signal to a process by running a program that modifies
    the exit_signal field and then uses an exec system call
    to launch a setuid application.

  - CVE-2009-1439
    Pavan Naregundi reported an issue in the CIFS filesystem
    code that allows remote users to overwrite memory via a
    long nativeFileSystem field in a Tree Connect response
    during mount."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1794"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6, fai-kernels, and user-mode-linux packages.

For the oldstable distribution (etch), this problem has been fixed in
version 2.6.18.dfsg.1-24etch2.

Note: Debian carefully tracks all known security issues across every
linux kernel package in all releases under active security support.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, updates for lower priority issues will normally not
be released for all kernels at the same time. Rather, they will be
released in a staggered or 'leap-frog' fashion."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 189, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"fai-kernels", reference:"1.17+etch.24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.18", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-486", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-686", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-686-bigmem", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-alpha", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-amd64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-arm", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-hppa", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-i386", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-ia64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-mips", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-mipsel", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-powerpc", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-s390", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-sparc", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-generic", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-legacy", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-smp", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-amd64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-footbridge", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-iop32x", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-itanium", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-ixp4xx", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-k7", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-mckinley", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc-smp", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc64-smp", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc-miboot", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc-smp", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-prep", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-qemu", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r3k-kn02", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r4k-ip22", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r4k-kn04", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r5k-cobalt", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r5k-ip32", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-rpc", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s390", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s390x", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s3c2410", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sb1-bcm91250a", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sparc32", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sparc64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sparc64-smp", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-686", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-alpha", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-amd64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-k7", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-powerpc", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-powerpc64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-s390x", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-sparc64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-486", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-686", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-686-bigmem", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-generic", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-legacy", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-smp", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-amd64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-footbridge", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-iop32x", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-itanium", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-ixp4xx", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-k7", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-mckinley", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc-smp", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc64-smp", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc-miboot", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc-smp", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-prep", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-qemu", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r3k-kn02", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r4k-ip22", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r4k-kn04", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r5k-cobalt", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r5k-ip32", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-rpc", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390-tape", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390x", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s3c2410", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sb1-bcm91250a", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sparc32", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sparc64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sparc64-smp", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-686", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-alpha", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-amd64", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-k7", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-powerpc", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-powerpc64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-s390x", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-sparc64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.18", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.18", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.18", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.18-6", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.18", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"user-mode-linux", reference:"2.6.18-1um-2etch.24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-24etch2")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-24etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-24etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
