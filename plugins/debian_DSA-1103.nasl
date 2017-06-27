#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1103. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22645);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2005-3359", "CVE-2006-0038", "CVE-2006-0039", "CVE-2006-0456", "CVE-2006-0554", "CVE-2006-0555", "CVE-2006-0557", "CVE-2006-0558", "CVE-2006-0741", "CVE-2006-0742", "CVE-2006-0744", "CVE-2006-1056", "CVE-2006-1242", "CVE-2006-1368", "CVE-2006-1523", "CVE-2006-1524", "CVE-2006-1525", "CVE-2006-1857", "CVE-2006-1858", "CVE-2006-1863", "CVE-2006-1864", "CVE-2006-2271", "CVE-2006-2272", "CVE-2006-2274");
  script_osvdb_id(26997, 26998);
  script_xref(name:"DSA", value:"1103");

  script_name(english:"Debian DSA-1103-1 : kernel-source-2.6.8 - several vulnerabilities");
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

  - CVE-2005-3359
    Franz Filz discovered that some socket calls permit
    causing inconsistent reference counts on loadable
    modules, which allows local users to cause a denial of
    service.

  - CVE-2006-0038
    'Solar Designer' discovered that arithmetic computations
    in netfilter's do_replace() function can lead to a
    buffer overflow and the execution of arbitrary code.
    However, the operation requires CAP_NET_ADMIN
    privileges, which is only an issue in virtualization
    systems or fine grained access control systems.

  - CVE-2006-0039
    'Solar Designer' discovered a race condition in
    netfilter's do_add_counters() function, which allows
    information disclosure of kernel memory by exploiting a
    race condition. Likewise, it requires CAP_NET_ADMIN
    privileges. 

  - CVE-2006-0456
    David Howells discovered that the s390 assembly version
    of the strnlen_user() function incorrectly returns some
    string size values.

  - CVE-2006-0554
    It was discovered that the ftruncate() function of XFS
    can expose unallocated blocks, which allows information
    disclosure of previously deleted files.

  - CVE-2006-0555
    It was discovered that some NFS file operations on
    handles mounted with O_DIRECT can force the kernel into
    a crash.

  - CVE-2006-0557
    It was discovered that the code to configure memory
    policies allows tricking the kernel into a crash, thus
    allowing denial of service.

  - CVE-2006-0558
    It was discovered by Cliff Wickman that perfmon for the
    IA64 architecture allows users to trigger a BUG()
    assert, which allows denial of service.

  - CVE-2006-0741
    Intel EM64T systems were discovered to be susceptible to
    a local DoS due to an endless recursive fault related to
    a bad ELF entry address.

  - CVE-2006-0742
    Alan and Gareth discovered that the ia64 platform had an
    incorrectly declared die_if_kernel() function as 'does
    never return' which could be exploited by a local
    attacker resulting in a kernel crash.

  - CVE-2006-0744
    The Linux kernel did not properly handle uncanonical
    return addresses on Intel EM64T CPUs, reporting
    exceptions in the SYSRET instead of the next
    instruction, causing the kernel exception handler to run
    on the user stack with the wrong GS. This may result in
    a DoS due to a local user changing the frames.

  - CVE-2006-1056
    AMD64 machines (and other 7th and 8th generation
    AuthenticAMD processors) were found to be vulnerable to
    sensitive information leakage, due to how they handle
    saving and restoring the FOP, FIP, and FDP x87 registers
    in FXSAVE/FXRSTOR when an exception is pending. This
    allows a process to determine portions of the state of
    floating point instructions of other processes.

  - CVE-2006-1242
    Marco Ivaldi discovered that there was an unintended
    information disclosure allowing remote attackers to
    bypass protections against Idle Scans (nmap -sI) by
    abusing the ID field of IP packets and bypassing the
    zero IP ID in DF packet countermeasure. This was a
    result of the ip_push_pending_frames function improperly
    incremented the IP ID field when sending a RST after
    receiving unsolicited TCP SYN-ACK packets.

  - CVE-2006-1368
    Shaun Tancheff discovered a buffer overflow (boundary
    condition error) in the USB Gadget RNDIS implementation
    allowing remote attackers to cause a DoS. While creating
    a reply message, the driver allocated memory for the
    reply data, but not for the reply structure. The kernel
    fails to properly bounds-check user-supplied data before
    copying it to an insufficiently sized memory buffer.
    Attackers could crash the system, or possibly execute
    arbitrary machine code.

  - CVE-2006-1523
    Oleg Nesterov reported an unsafe BUG_ON call in signal.c
    which was introduced by RCU signal handling. The BUG_ON
    code is protected by siglock while the code in
    switch_exit_pids() uses tasklist_lock. It may be
    possible for local users to exploit this to initiate a
    denial of service attack (DoS).

  - CVE-2006-1524
    Hugh Dickins discovered an issue in the madvise_remove()
    function wherein file and mmap restrictions are not
    followed, allowing local users to bypass IPC permissions
    and replace portions of readonly tmpfs files with
    zeroes.

  - CVE-2006-1525
    Alexandra Kossovsky reported a NULL pointer dereference
    condition in ip_route_input() that can be triggered by a
    local user by requesting a route for a multicast IP
    address, resulting in a denial of service (panic).

  - CVE-2006-1857
    Vlad Yasevich reported a data validation issue in the
    SCTP subsystem that may allow a remote user to overflow
    a buffer using a badly formatted HB-ACK chunk, resulting
    in a denial of service.

  - CVE-2006-1858
    Vlad Yasevich reported a bug in the bounds checking code
    in the SCTP subsystem that may allow a remote attacker
    to trigger a denial of service attack when rounded
    parameter lengths are used to calculate parameter
    lengths instead of the actual values.

  - CVE-2006-1863
    Mark Mosely discovered that chroots residing on an CIFS
    share can be escaped with specially crafted 'cd'
    sequences.

  - CVE-2006-1864
    Mark Mosely discovered that chroots residing on an SMB
    share can be escaped with specially crafted 'cd'
    sequences.

  - CVE-2006-2271
    The 'Mu security team' discovered that carefully crafted
    ECNE chunks can cause a kernel crash by accessing
    incorrect state stable entries in the SCTP networking
    subsystem, which allows denial of service.

  - CVE-2006-2272
    The 'Mu security team' discovered that fragmented SCTP
    control chunks can trigger kernel panics, which allows
    for denial of service attacks.

  - CVE-2006-2274
    It was discovered that SCTP packets with two initial
    bundled data packets can lead to infinite recursion,
    which allows for denial of service attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1103"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel package immediately and reboot the machine. If you
have built a custom kernel from the kernel source package, you will
need to rebuild to take advantage of these fixes.

The following matrix explains which kernel version for which
architecture fix the problems mentioned above :

                               Debian 3.1 (sarge)           
  Source                       2.6.8-16sarge3               
  Alpha architecture           2.6.8-16sarge3               
  HP Precision architecture    2.6.8-6sarge3                
  Intel IA-32 architecture     2.6.8-16sarge3               
  Intel IA-64 architecture     2.6.8-14sarge3               
  Motorola 680x0 architecture  2.6.8-4sarge3                
  PowerPC architecture         2.6.8-12sarge3               
  IBM S/390 architecture       2.6.8-5sarge3                
  Sun Sparc architecture       2.6.8-15sarge3               
Due to technical problems the built amd64 packages couldn't be
processed by the archive script. Once this problem is resolved, an
updated DSA 1103-2 will be sent out with the checksums for amd64.

The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update :

                      Debian 3.1 (sarge)  
  fai-kernels         1.9.1sarge2"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 189, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.6.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3", reference:"2.6.8-15sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power3", reference:"2.6.8-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power3-smp", reference:"2.6.8-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power4", reference:"2.6.8-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power4-smp", reference:"2.6.8-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-powerpc", reference:"2.6.8-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-powerpc-smp", reference:"2.6.8-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.6.8", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium-smp", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley-smp", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3", reference:"2.6.8-15sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-32", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-32-smp", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-386", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-64", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-64-smp", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-686", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-686-smp", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-generic", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-itanium", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-itanium-smp", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-k7", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-k7-smp", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-mckinley", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-mckinley-smp", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-smp", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc32", reference:"2.6.8-15sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc64", reference:"2.6.8-15sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc64-smp", reference:"2.6.8-15sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium-smp", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley-smp", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-32", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-32-smp", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-386", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-64", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-64-smp", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-686", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-686-smp", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-generic", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-itanium", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-itanium-smp", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-k7", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-k7-smp", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-mckinley", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-mckinley-smp", reference:"2.6.8-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power3", reference:"2.6.8-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power3-smp", reference:"2.6.8-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power4", reference:"2.6.8-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power4-smp", reference:"2.6.8-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-powerpc", reference:"2.6.8-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-powerpc-smp", reference:"2.6.8-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390", reference:"2.6.8-5sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390-tape", reference:"2.6.8-5sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390x", reference:"2.6.8-5sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-smp", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc32", reference:"2.6.8-15sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc64", reference:"2.6.8-15sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc64-smp", reference:"2.6.8-15sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-amiga", reference:"2.6.8-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-atari", reference:"2.6.8-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-bvme6000", reference:"2.6.8-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-hp", reference:"2.6.8-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mac", reference:"2.6.8-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme147", reference:"2.6.8-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme16x", reference:"2.6.8-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-q40", reference:"2.6.8-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-sun3", reference:"2.6.8-4sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.6.8-s390", reference:"2.6.8-5sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-debian-2.6.8", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-source-2.6.8", reference:"2.6.8-16sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-tree-2.6.8", reference:"2.6.8-16sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
