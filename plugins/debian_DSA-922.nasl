#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-922. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22788);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2004-2302", "CVE-2005-0756", "CVE-2005-0757", "CVE-2005-1265", "CVE-2005-1761", "CVE-2005-1762", "CVE-2005-1763", "CVE-2005-1765", "CVE-2005-1767", "CVE-2005-2456", "CVE-2005-2458", "CVE-2005-2459", "CVE-2005-2548", "CVE-2005-2801", "CVE-2005-2872", "CVE-2005-3105", "CVE-2005-3106", "CVE-2005-3107", "CVE-2005-3108", "CVE-2005-3109", "CVE-2005-3110", "CVE-2005-3271", "CVE-2005-3272", "CVE-2005-3273", "CVE-2005-3274", "CVE-2005-3275", "CVE-2005-3276");
  script_bugtraq_id(14477, 15527, 15528, 15533);
  script_osvdb_id(14864, 16687, 17233, 17234, 17479, 17545, 17546, 17693, 18555, 18700, 18702, 18808, 19026, 19028, 19314, 19430, 19927, 19928, 19929, 19930, 19931, 19932, 20009, 21278, 21279, 21280, 21281, 21282);
  script_xref(name:"DSA", value:"922");

  script_name(english:"Debian DSA-922-1 : kernel-source-2.6.8 - several vulnerabilities");
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

  - CVE-2004-2302
    A race condition in the sysfs filesystem allows local
    users to read kernel memory and cause a denial of
    service (crash).

  - CVE-2005-0756
    Alexander Nyberg discovered that the ptrace() system
    call does not properly verify addresses on the amd64
    architecture which can be exploited by a local attacker
    to crash the kernel.

  - CVE-2005-0757
    A problem in the offset handling in the xattr file
    system code for ext3 has been discovered that may allow
    users on 64-bit systems that have access to an ext3
    filesystem with extended attributes to cause the kernel
    to crash.

  - CVE-2005-1265
    Chris Wright discovered that the mmap() function could
    create illegal memory maps that could be exploited by a
    local user to crash the kernel or potentially execute
    arbitrary code.

  - CVE-2005-1761
    A vulnerability on the IA-64 architecture can lead local
    attackers to overwrite kernel memory and crash the
    kernel.

  - CVE-2005-1762
    A vulnerability has been discovered in the ptrace()
    system call on the amd64 architecture that allows a
    local attacker to cause the kernel to crash.

  - CVE-2005-1763
    A buffer overflow in the ptrace system call for 64-bit
    architectures allows local users to write bytes into
    arbitrary kernel memory.

  - CVE-2005-1765
    Zou Nan Hai has discovered that a local user could cause
    the kernel to hang on the amd64 architecture after
    invoking syscall() with specially crafted arguments.

  - CVE-2005-1767
    A vulnerability has been discovered in the stack segment
    fault handler that could allow a local attacker to cause
    a stack exception that will lead the kernel to crash
    under certain circumstances.

  - CVE-2005-2456
    Balazs Scheidler discovered that a local attacker could
    call setsockopt() with an invalid xfrm_user policy
    message which would cause the kernel to write beyond the
    boundaries of an array and crash.

  - CVE-2005-2458
    Vladimir Volovich discovered a bug in the zlib routines
    which are also present in the Linux kernel and allows
    remote attackers to crash the kernel.

  - CVE-2005-2459
    Another vulnerability has been discovered in the zlib
    routines which are also present in the Linux kernel and
    allows remote attackers to crash the kernel.

  - CVE-2005-2548
    Peter Sandstrom noticed that snmpwalk from a remote host
    could cause a denial of service (kernel oops from null
    dereference) via certain UDP packets that lead to a
    function call with the wrong argument.

  - CVE-2005-2801
    Andreas Gruenbacher discovered a bug in the ext2 and
    ext3 file systems. When data areas are to be shared
    among two inodes not all information were compared for
    equality, which could expose wrong ACLs for files.

  - CVE-2005-2872
    Chad Walstrom discovered that the ipt_recent kernel
    module on 64-bit processors such as AMD64 allows remote
    attackers to cause a denial of service (kernel panic)
    via certain attacks such as SSH brute force.

  - CVE-2005-3105
    The mprotect code on Itanium IA-64 Montecito processors
    does not properly maintain cache coherency as required
    by the architecture, which allows local users to cause a
    denial of service and possibly corrupt data by modifying
    PTE protections.

  - CVE-2005-3106
    A race condition in the thread management may allow
    local users to cause a denial of service (deadlock) when
    threads are sharing memory and waiting for a thread that
    has just performed an exec.

  - CVE-2005-3107
    When one thread is tracing another thread that shares
    the same memory map a local user could cause a denial of
    service (deadlock) by forcing a core dump when the
    traced thread is in the TASK_TRACED state.

  - CVE-2005-3108
    A bug in the ioremap() system call has been discovered
    on the amd64 architecture that could allow local users
    to cause a denial of service or an information leak when
    performing a lookup of a non-existent memory page.

  - CVE-2005-3109
    The HFS and HFS+ (hfsplus) modules allow local attackers
    to cause a denial of service (oops) by using hfsplus to
    mount a filesystem that is not hfsplus.

  - CVE-2005-3110
    A race condition in the ebtables netfilter module on an
    SMP system running under high load may allow remote
    attackers to cause a denial of service (crash).

  - CVE-2005-3271
    Roland McGrath discovered that exec() does not properly
    clear posix-timers in multi-threaded environments, which
    results in a resource leak and could allow a large
    number of multiple local users to cause a denial of
    service by using more posix-timers than specified by the
    quota for a single user.

  - CVE-2005-3272
    The kernel allows remote attackers to poison the bridge
    forwarding table using frames that have already been
    dropped by filtering, which can cause the bridge to
    forward spoofed packets.

  - CVE-2005-3273
    The ioctl for the packet radio ROSE protocol does not
    properly verify the arguments when setting a new router,
    which allows attackers to trigger out-of-bounds errors.

  - CVE-2005-3274
    A race condition on SMP systems allows local users to
    cause a denial of service (null dereference) by causing
    a connection timer to expire while the connection table
    is being flushed before the appropriate lock is
    acquired.

  - CVE-2005-3275
    An error in the NAT code allows remote attackers to
    cause a denial of service (memory corruption) by causing
    two packets for the same protocol to be NATed at the
    same time, which leads to memory corruption.

  - CVE-2005-3276
    A missing memory cleanup in the thread handling routines
    before copying data into userspace allows a user process
    to obtain sensitive information.

This update also contains a number of corrections for issues that
turned out to have no security implication afterwards."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=309308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=311164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=321401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=322237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=322339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-922"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel package immediately and reboot the machine.

The following matrix explains which kernel version for which
architecture fix the problems mentioned above :

                               Debian 3.1 (sarge)           
  Source                       2.6.8-16sarge1               
  Alpha architecture           2.6.8-16sarge1               
  AMD64 architecture           2.6.8-16sarge1               
  HP Precision architecture    2.6.8-6sarge1                
  Intel IA-32 architecture     2.6.8-16sarge1               
  Intel IA-64 architecture     2.6.8-14sarge1               
  Motorola 680x0 architecture  2.6.8-4sarge1                
  PowerPC architecture         2.6.8-12sarge1               
  IBM S/390 architecture       2.6.8-5sarge1                
  Sun Sparc architecture       2.6.8-15sarge1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.6.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/01");
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
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-2", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-power3", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-power3-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-power4", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-power4-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-powerpc", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-powerpc-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.6.8", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium-smp", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley-smp", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-amd64-generic", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-amd64-k8", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-amd64-k8-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-em64t-p4", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-em64t-p4-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-32", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-32-smp", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-386", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-64", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-64-smp", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-686", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-686-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-generic", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-itanium", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-itanium-smp", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-k7", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-k7-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-mckinley", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-mckinley-smp", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-sparc32", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-sparc64", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-sparc64-smp", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium-smp", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley-smp", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-amd64-generic", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-amd64-k8", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-amd64-k8-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-em64t-p4", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-em64t-p4-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-32", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-32-smp", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-386", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-64", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-64-smp", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-686", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-686-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-generic", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-itanium", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-itanium-smp", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-k7", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-k7-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-mckinley", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-mckinley-smp", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-s390", reference:"2.6.8-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-s390-tape", reference:"2.6.8-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-s390x", reference:"2.6.8-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-sparc32", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-sparc64", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-sparc64-smp", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-amiga", reference:"2.6.8-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-atari", reference:"2.6.8-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-bvme6000", reference:"2.6.8-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-hp", reference:"2.6.8-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mac", reference:"2.6.8-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme147", reference:"2.6.8-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme16x", reference:"2.6.8-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-power3", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-power3-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-power4", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-power4-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-powerpc", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-powerpc-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-q40", reference:"2.6.8-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-sun3", reference:"2.6.8-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.6.8-s390", reference:"2.6.8-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-debian-2.6.8", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-source-2.6.8", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-tree-2.6.8", reference:"2.6.8-16sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
