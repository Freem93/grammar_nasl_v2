#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1237. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(23911);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2006-4093", "CVE-2006-4538", "CVE-2006-4997", "CVE-2006-5174", "CVE-2006-5871");
  script_osvdb_id(21527, 28034, 28936, 29537, 29539, 31373, 31374);
  script_xref(name:"DSA", value:"1237");

  script_name(english:"Debian DSA-1237-1 : kernel-source-2.4.27 - several vulnerabilities");
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

  - CVE-2005-4093
    Olof Johansson reported a local DoS (Denial of Service)
    vulnerability on the PPC970 platform. Unprivileged users
    can hang the system by executing the 'attn' instruction,
    which was not being disabled at boot.

  - CVE-2006-4538
    Kirill Korotaev reported a local DoS (Denial of Service)
    vulnerability on the ia64 and sparc architectures. A
    user could cause the system to crash by executing a
    malformed ELF binary due to insufficient verification of
    the memory layout.

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

  - CVE-2006-5649
    Fabio Massimo Di Nitto reported a potential remote DoS
    (Denial of Service) vulnerability on powerpc systems.
    The alignment exception only checked the exception table
    for -EFAULT, not for other errors. This can be exploited
    by a local user to cause a system crash (panic).

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
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4538"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1237"
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
  Source                       2.4.27-10sarge5              
  Alpha architecture           2.4.27-10sarge5              
  ARM architecture             2.4.27-2sarge5               
  Intel IA-32 architecture     2.4.27-10sarge5              
  Intel IA-64 architecture     2.4.27-10sarge5              
  Motorola 680x0 architecture  2.4.27-3sarge5               
  Big endian MIPS              2.4.27-10.sarge4.040815-2    
  Little endian MIPS           2.4.27-10.sarge4.040815-2    
  PowerPC architecture         2.4.27-10sarge5              
  IBM S/390 architecture       2.4.27-2sarge5               
  Sun Sparc architecture       2.4.27-9sarge5               
The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update :

                               Debian 3.1 (sarge)           
  fai-kernels                  1.9.1sarge5                  
  kernel-image-2.4.27-speakup  2.4.27-1.1sarge4             
  mindi-kernel                 2.4.27-2sarge4               
  systemimager                 3.2.3-6sarge4"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.4.27");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/07");
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
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27", reference:"2.4.27-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-2", reference:"2.4.27-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-3", reference:"2.4.27-9sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-apus", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-nubus", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc-small", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.4.27", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.4.27-speakup", reference:"2.4.27-1.1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27", reference:"2.4.27-10.sarge4.040815-2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2", reference:"2.4.27-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-386", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-586tsc", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-686", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-686-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-generic", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-itanium", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-itanium-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-k6", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-k7", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-k7-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-mckinley", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-mckinley-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-sparc32", reference:"2.4.27-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-sparc32-smp", reference:"2.4.27-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-sparc64", reference:"2.4.27-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-2-sparc64-smp", reference:"2.4.27-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3", reference:"2.4.27-9sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-386", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-586tsc", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-686", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-686-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-generic", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-itanium", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-itanium-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-k6", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-k7", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-k7-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-mckinley", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-mckinley-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-sparc32", reference:"2.4.27-9sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-sparc32-smp", reference:"2.4.27-9sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-sparc64", reference:"2.4.27-9sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-sparc64-smp", reference:"2.4.27-9sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-apus", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-nubus", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-powerpc", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-speakup", reference:"2.4.27-1.1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-itanium", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-itanium-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-mckinley", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-mckinley-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-386", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-586tsc", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-686", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-686-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-generic", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-itanium", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-itanium-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-k6", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-k7", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-k7-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-mckinley", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-mckinley-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-s390", reference:"2.4.27-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-s390-tape", reference:"2.4.27-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-s390x", reference:"2.4.27-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-sparc32", reference:"2.4.27-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-sparc32-smp", reference:"2.4.27-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-sparc64", reference:"2.4.27-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-2-sparc64-smp", reference:"2.4.27-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-386", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-586tsc", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-686", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-686-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-generic", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-itanium", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-itanium-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-k6", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-k7", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-k7-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-mckinley", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-mckinley-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-s390", reference:"2.4.27-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-s390-tape", reference:"2.4.27-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-s390x", reference:"2.4.27-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-sparc32", reference:"2.4.27-9sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-sparc32-smp", reference:"2.4.27-9sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-sparc64", reference:"2.4.27-9sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-sparc64-smp", reference:"2.4.27-9sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-amiga", reference:"2.4.27-3sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-apus", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-atari", reference:"2.4.27-3sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-bast", reference:"2.4.27-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-bvme6000", reference:"2.4.27-3sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-lart", reference:"2.4.27-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mac", reference:"2.4.27-3sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mvme147", reference:"2.4.27-3sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mvme16x", reference:"2.4.27-3sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-netwinder", reference:"2.4.27-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-nubus", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc-small", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-q40", reference:"2.4.27-3sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r3k-kn02", reference:"2.4.27-10.sarge4.040815-2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r4k-ip22", reference:"2.4.27-10.sarge4.040815-2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r4k-kn04", reference:"2.4.27-10.sarge4.040815-2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-cobalt", reference:"2.4.27-10.sarge4.040815-2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-ip22", reference:"2.4.27-10.sarge4.040815-2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-lasat", reference:"2.4.27-10.sarge4.040815-2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-riscpc", reference:"2.4.27-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-riscstation", reference:"2.4.27-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-sb1-swarm-bn", reference:"2.4.27-10.sarge4.040815-2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-speakup", reference:"2.4.27-1.1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-xxs1500", reference:"2.4.27-10.sarge4.040815-2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-apus", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-nubus", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-powerpc", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-debian-2.4.27", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-386", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-586tsc", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-686", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-686-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-k6", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-k7", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-k7-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-386", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-586tsc", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-686", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-686-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-k6", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-k7", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-k7-smp", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-source-2.4.27", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-tree-2.4.27", reference:"2.4.27-10sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"mindi-kernel", reference:"2.4.27-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"mips-tools", reference:"2.4.27-10.sarge4.040815-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
