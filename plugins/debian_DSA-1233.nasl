#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1233. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(23846);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2006-3741", "CVE-2006-4538", "CVE-2006-4813", "CVE-2006-4997", "CVE-2006-5871");
  script_osvdb_id(28936, 29537, 29538, 29539, 30002, 30725, 31373, 31374, 31376);
  script_xref(name:"DSA", value:"1233");

  script_name(english:"Debian DSA-1233-1 : kernel-source-2.6.8 - several vulnerabilities");
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

  - CVE-2006-3741
    Stephane Eranian discovered a local DoS (Denial of
    Service) vulnerability on the ia64 architecture. A local
    user could exhaust the available file descriptors by
    exploiting a counting error in the permonctl() system
    call.

  - CVE-2006-4538
    Kirill Korotaev reported a local DoS (Denial of Service)
    vulnerability on the ia64 and sparc architectures. A
    user could cause the system to crash by executing a
    malformed ELF binary due to insufficient verification of
    the memory layout.

  - CVE-2006-4813
    Dmitriy Monakhov reported a potential memory leak in the
    __block_prepare_write function. __block_prepare_write
    does not properly sanitize kernel buffers during error
    recovery, which could be exploited by local users to
    gain access to sensitive kernel memory.

  - CVE-2006-4997
    ADLab Venustech Info Ltd reported a potential remote DoS
    (Denial of Service) vulnerability in the IP over ATM
    subsystem. A remote system could cause the system to
    crash by sending specially crafted packets that would
    trigger an attempt to free an already-freed pointer
    resulting in a system crash.

  - CVE-2006-5174
    Martin Schwidefsky reported a potential leak of
    sensitive information on s390 systems. The
    copy_from_user function did not clear the remaining
    bytes of the kernel buffer after receiving a fault on
    the userspace address, resulting in a leak of
    uninitialized kernel memory. A local user could exploit
    this by appending to a file from a bad address.

  - CVE-2006-5619
    James Morris reported a potential local DoS (Denial of
    Service) vulnerability that could be used to hang or
    oops a system. The seqfile handling for
    /proc/net/ip6_flowlabel has a flaw that can be exploited
    to cause an infinite loop by reading this file after
    creating a flowlabel.

  - CVE-2006-5649
    Fabio Massimo Di Nitto reported a potential remote DoS
    (Denial of Service) vulnerability on powerpc systems.
    The alignment exception only checked the exception table
    for -EFAULT, not for other errors. This can be exploited
    by a local user to cause a system crash (panic).

  - CVE-2006-5751
    Eugene Teo reported a vulnerability in the
    get_fdb_entries function that could potentially be
    exploited to allow arbitrary code execution with
    escalated privileges.

  - CVE-2006-5871
    Bill Allombert reported that various mount options are
    ignored by smbfs when UNIX extensions are enabled. This
    includes the uid, gid and mode options. Client systems
    would silently use the server-provided settings instead
    of honoring these options, changing the security model.
    This update includes a fix from Haroldo Gamal that
    forces the kernel to honor these mount options. Note
    that, since the current versions of smbmount always pass
    values for these options to the kernel, it is not
    currently possible to activate unix extensions by
    omitting mount options. However, this behavior is
    currently consistent with the current behavior of the
    next Debian release, 'etch'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1233"
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
  Source                       2.6.8-16sarge6               
  Alpha architecture           2.6.8-16sarge6               
  AMD64 architecture           2.6.8-16sarge6               
  HP Precision architecture    2.6.8-6sarge6                
  Intel IA-32 architecture     2.6.8-16sarge6               
  Intel IA-64 architecture     2.6.8-14sarge6               
  Motorola 680x0 architecture  2.6.8-4sarge6                
  PowerPC architecture         2.6.8-12sarge6               
  IBM S/390 architecture       2.6.8-5sarge6                
  Sun Sparc architecture       2.6.8-15sarge6               
The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update :

                      Debian 3.1 (sarge)  
  fai-kernels         1.9.1sarge5"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.6.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"fai-kernels", reference:"1.9.1sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3", reference:"2.6.8-15sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power3", reference:"2.6.8-12sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power3-smp", reference:"2.6.8-12sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power4", reference:"2.6.8-12sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power4-smp", reference:"2.6.8-12sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-powerpc", reference:"2.6.8-12sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-powerpc-smp", reference:"2.6.8-12sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.6.8", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium-smp", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley-smp", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-amd64-generic", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-amd64-k8", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-amd64-k8-smp", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-em64t-p4", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-em64t-p4-smp", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3", reference:"2.6.8-15sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-32", reference:"2.6.8-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-32-smp", reference:"2.6.8-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-386", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-64", reference:"2.6.8-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-64-smp", reference:"2.6.8-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-686", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-686-smp", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-generic", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-itanium", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-itanium-smp", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-k7", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-k7-smp", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-mckinley", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-mckinley-smp", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-smp", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc32", reference:"2.6.8-15sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc64", reference:"2.6.8-15sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc64-smp", reference:"2.6.8-15sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium-smp", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley-smp", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-amd64-generic", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-amd64-k8", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-amd64-k8-smp", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-em64t-p4", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-em64t-p4-smp", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-32", reference:"2.6.8-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-32-smp", reference:"2.6.8-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-386", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-64", reference:"2.6.8-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-64-smp", reference:"2.6.8-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-686", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-686-smp", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-generic", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-itanium", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-itanium-smp", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-k7", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-k7-smp", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-mckinley", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-mckinley-smp", reference:"2.6.8-14sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power3", reference:"2.6.8-12sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power3-smp", reference:"2.6.8-12sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power4", reference:"2.6.8-12sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power4-smp", reference:"2.6.8-12sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-powerpc", reference:"2.6.8-12sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-powerpc-smp", reference:"2.6.8-12sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390", reference:"2.6.8-5sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390-tape", reference:"2.6.8-5sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390x", reference:"2.6.8-5sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-smp", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc32", reference:"2.6.8-15sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc64", reference:"2.6.8-15sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc64-smp", reference:"2.6.8-15sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-amiga", reference:"2.6.8-4sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-atari", reference:"2.6.8-4sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-bvme6000", reference:"2.6.8-4sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-hp", reference:"2.6.8-4sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mac", reference:"2.6.8-4sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme147", reference:"2.6.8-4sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme16x", reference:"2.6.8-4sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-q40", reference:"2.6.8-4sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-sun3", reference:"2.6.8-4sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.6.8-s390", reference:"2.6.8-5sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-debian-2.6.8", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-source-2.6.8", reference:"2.6.8-16sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-tree-2.6.8", reference:"2.6.8-16sarge6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
