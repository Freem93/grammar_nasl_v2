#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-921. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22787);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-0756", "CVE-2005-0757", "CVE-2005-1762", "CVE-2005-1767", "CVE-2005-1768", "CVE-2005-2456", "CVE-2005-2458", "CVE-2005-2459", "CVE-2005-2553", "CVE-2005-2801", "CVE-2005-2872", "CVE-2005-3275");
  script_bugtraq_id(14477);
  script_osvdb_id(16687, 17233, 17693, 17803, 18555, 18702, 18807, 19026, 19028, 19314, 19430, 21279);
  script_xref(name:"DSA", value:"921");

  script_name(english:"Debian DSA-921-1 : kernel-source-2.4.27 - several vulnerabilities");
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

  - CVE-2005-1762
    A vulnerability has been discovered in the ptrace()
    system call on the amd64 architecture that allows a
    local attacker to cause the kernel to crash.

  - CVE-2005-1767
    A vulnerability has been discovered in the stack segment
    fault handler that could allow a local attacker to cause
    a stack exception that will lead the kernel to crash
    under certain circumstances.

  - CVE-2005-1768
    Ilja van Sprundel discovered a race condition in the
    IA32 (x86) compatibility execve() systemcall for amd64
    and IA64 that allows local attackers to cause the kernel
    to panic and possibly execute arbitrary code.

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

  - CVE-2005-2553
    A NULL pointer dereference in ptrace when tracing a
    64-bit executable can cause the kernel to crash.

  - CVE-2005-2801
    Andreas Gruenbacher discovered a bug in the ext2 and
    ext3 file systems. When data areas are to be shared
    among two inodes not all information were compared for
    equality, which could expose wrong ACLs for files.

  - CVE-2005-2872
    Chad Walstrom discovered that the ipt_recent kernel
    module to stop SSH bruteforce attacks could cause the
    kernel to crash on 64-bit architectures.

  - CVE-2005-3275
    An error in the NAT code allows remote attackers to
    cause a denial of service (memory corruption) by causing
    two packets for the same protocol to be NATed at the
    same time, which leads to memory corruption."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=311164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=319629"
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
    value:"http://www.debian.org/security/2005/dsa-921"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel package immediately and reboot the machine.

The following matrix explains which kernel version for which
architecture fix the problems mentioned above :

                                   Debian 3.1 (sarge)               
  Source                           2.4.27-10sarge1                  
  Alpha architecture               2.4.27-10sarge1                  
  ARM architecture                 2.4.27-2sarge1                   
  Intel IA-32 architecture         2.4.27-10sarge1                  
  Intel IA-64 architecture         2.4.27-10sarge1                  
  Motorola 680x0 architecture      2.4.27-3sarge1                   
  Big endian MIPS architecture     2.4.27-10.sarge1.040815-1        
  Little endian MIPS architecture  2.4.27-10.sarge1.040815-1        
  PowerPC architecture             2.4.27-10sarge1                  
  IBM S/390 architecture           2.4.27-2sarge1                   
  Sun Sparc architecture           2.4.27-9sarge1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.4.27");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/06");
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
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27", reference:"2.4.27-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-2", reference:"2.4.27-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-apus", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-nubus", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc-small", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.4.27", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27", reference:"2.4.27-10.sarge1.040815-1")) flag++;
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
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-apus", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-nubus", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-powerpc", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-itanium", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-itanium-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-mckinley", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-mckinley-smp", reference:"2.4.27-10sarge1")) flag++;
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
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-amiga", reference:"2.4.27-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-apus", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-atari", reference:"2.4.27-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-bast", reference:"2.4.27-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-bvme6000", reference:"2.4.27-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-lart", reference:"2.4.27-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mac", reference:"2.4.27-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mvme147", reference:"2.4.27-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mvme16x", reference:"2.4.27-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-netwinder", reference:"2.4.27-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-nubus", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc-small", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-q40", reference:"2.4.27-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r3k-kn02", reference:"2.4.27-10.sarge1.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r4k-ip22", reference:"2.4.27-10.sarge1.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r4k-kn04", reference:"2.4.27-10.sarge1.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-cobalt", reference:"2.4.27-10.sarge1.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-ip22", reference:"2.4.27-10.sarge1.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-lasat", reference:"2.4.27-10.sarge1.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-riscpc", reference:"2.4.27-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-riscstation", reference:"2.4.27-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-sb1-swarm-bn", reference:"2.4.27-10.sarge1.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-xxs1500", reference:"2.4.27-10.sarge1.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-apus", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-arm", reference:"2.4.27-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-nubus", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-powerpc", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-debian-2.4.27", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-386", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-586tsc", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-686", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-686-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-k6", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-k7", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-k7-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-source-2.4.27", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-tree-2.4.27", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"mips-tools", reference:"2.4.27-10.sarge1.040815-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
