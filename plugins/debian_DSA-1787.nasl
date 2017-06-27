#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1787. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(38668);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-4307", "CVE-2008-5079", "CVE-2008-5395", "CVE-2008-5700", "CVE-2008-5701", "CVE-2008-5702", "CVE-2009-0028", "CVE-2009-0029", "CVE-2009-0031", "CVE-2009-0065", "CVE-2009-0269", "CVE-2009-0322", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0745", "CVE-2009-0834", "CVE-2009-0859", "CVE-2009-1046", "CVE-2009-1192", "CVE-2009-1242", "CVE-2009-1265", "CVE-2009-1337", "CVE-2009-1338", "CVE-2009-1439");
  script_bugtraq_id(32676, 33113, 33672, 33846, 33951, 34020, 34405, 34453, 34654, 34673);
  script_osvdb_id(52862, 54379, 55230, 56430);
  script_xref(name:"DSA", value:"1787");

  script_name(english:"Debian DSA-1787-1 : linux-2.6.24 - denial of service/privilege escalation/information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service or privilege escalation. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2008-4307
    Bryn M. Reeves reported a denial of service in the NFS
    filesystem. Local users can trigger a kernel BUG() due
    to a race condition in the do_setlk function.

  - CVE-2008-5079
    Hugo Dias reported a DoS condition in the ATM subsystem
    that can be triggered by a local user by calling the
    svc_listen function twice on the same socket and reading
    /proc/net/atm/*vc.

  - CVE-2008-5395
    Helge Deller discovered a denial of service condition
    that allows local users on PA-RISC systems to crash a
    system by attempting to unwind a stack containing
    userspace addresses.

  - CVE-2008-5700
    Alan Cox discovered a lack of minimum timeouts on SG_IO
    requests, which allows local users of systems using ATA
    to cause a denial of service by forcing drives into PIO
    mode.

  - CVE-2008-5701
    Vlad Malov reported an issue on 64-bit MIPS systems
    where a local user could cause a system crash by crafing
    a malicious binary which makes o32 syscalls with a
    number less than 4000.

  - CVE-2008-5702
    Zvonimir Rakamaric reported an off-by-one error in the
    ib700wdt watchdog driver which allows local users to
    cause a buffer underflow by making a specially crafted
    WDIOC_SETTIMEOUT ioctl call.

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
    service by consuming all of kernel memory.

  - CVE-2009-0065
    Wei Yongjun discovered a memory overflow in the SCTP
    implementation that can be triggered by remote users,
    permitting remote code execution.

  - CVE-2009-0269
    Duane Griffin provided a fix for an issue in the
    eCryptfs subsystem which allows local users to cause a
    denial of service (fault or memory corruption).

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

  - CVE-2009-0745
    Peter Kerwien discovered an issue in the ext4 filesystem
    that allows local users to cause a denial of service
    (kernel oops) during a resize operation.

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

  - CVE-2009-1046
    Mikulas Patocka reported an issue in the console
    subsystem that allows a local user to cause memory
    corruption by selecting a small number of 3-byte UTF-8
    characters.

  - CVE-2009-1192
    Shaohua Li reported an issue in the AGP subsystem that
    may allow local users to read sensitive kernel memory
    due to a leak of uninitialized memory.

  - CVE-2009-1242
    Benjamin Gilbert reported a local denial of service
    vulnerability in the KVM VMX implementation that allows
    local users to trigger an oops.

  - CVE-2009-1265
    Thomas Pollet reported an overflow in the af_rose
    implementation that allows remote attackers to retrieve
    uninitialized kernel memory that may contain sensitive
    data.

  - CVE-2009-1337
    Oleg Nesterov discovered an issue in the exit_notify
    function that allows local users to send an arbitrary
    signal to a process by running a program that modifies
    the exit_signal field and then uses an exec system call
    to launch a setuid application.

  - CVE-2009-1338
    Daniel Hokka Zakrisson discovered that a kill(-1) is
    permitted to reach processes outside of the current
    process namespace.

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
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5700"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0269"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0745"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1787"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6.24 packages.

For the oldstable distribution (etch), these problems have been fixed
in version 2.6.24-6~etchnhalf.8etch1.

Note: Debian 'etch' includes linux kernel packages based upon both the
2.6.18 and 2.6.24 linux releases. All known security issues are
carefully tracked against both packages and both packages will receive
security updates until security support for Debian 'etch' concludes.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, lower severity 2.6.18 and 2.6.24 updates will
typically release in a staggered or 'leap-frog' fashion."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 119, 189, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6.24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/04");
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
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.24", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-486", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-4kc-malta", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-5kc-malta", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-686", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-686-bigmem", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-alpha", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-amd64", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-arm", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-hppa", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-i386", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-ia64", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-mips", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-mipsel", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-powerpc", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-s390", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-sparc", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-generic", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-legacy", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-smp", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-amd64", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-common", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-footbridge", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-iop32x", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-itanium", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-ixp4xx", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-mckinley", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc-smp", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc64", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc64-smp", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc-miboot", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc-smp", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc64", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-r4k-ip22", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-r5k-cobalt", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-r5k-ip32", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-s390", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-s390x", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sb1-bcm91250a", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sb1a-bcm91480b", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sparc64", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sparc64-smp", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-486", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-4kc-malta", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-5kc-malta", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-686", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-686-bigmem", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-generic", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-legacy", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-smp", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-amd64", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-footbridge", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-iop32x", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-itanium", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-ixp4xx", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-mckinley", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc-smp", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc64", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc64-smp", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc-miboot", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc-smp", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc64", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-r4k-ip22", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-r5k-cobalt", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-r5k-ip32", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-s390", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-s390-tape", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-s390x", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sb1-bcm91250a", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sb1a-bcm91480b", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sparc64", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sparc64-smp", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.24", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.24", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.24", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.24-etchnhalf.1", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.24", reference:"2.6.24-6~etchnhalf.8etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
