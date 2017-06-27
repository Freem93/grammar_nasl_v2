#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1018. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22560);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/03 11:14:57 $");

  script_cve_id("CVE-2004-0887", "CVE-2004-1058", "CVE-2004-2607", "CVE-2005-0449", "CVE-2005-1761", "CVE-2005-2457", "CVE-2005-2555", "CVE-2005-2709", "CVE-2005-2973", "CVE-2005-3257", "CVE-2005-3783", "CVE-2005-3806", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858", "CVE-2005-4618");
  script_osvdb_id(6573, 11015, 12562, 13850, 17479, 18978, 19027, 20061, 20163, 20676, 21283, 21285, 21516, 22215, 22506, 22507);
  script_xref(name:"DSA", value:"1018");

  script_name(english:"Debian DSA-1018-2 : kernel-source-2.4.27 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The original update lacked recompiled ALSA modules against the new
 kernel ABI. Furthermore, kernel-latest-2.4-sparc now correctly
 depends on the updated packages. For completeness we're providing the
 original problem description :

  Several local and remote vulnerabilities have been discovered in the
  Linux kernel that may lead to a denial of service or the execution
  of arbitrary code. The Common Vulnerabilities and Exposures project
  identifies the following problems :

    - CVE-2004-0887
      Martin Schwidefsky discovered that the privileged
      instruction SACF (Set Address Space Control Fast) on
      the S/390 platform is not handled properly, allowing
      for a local user to gain root privileges.

    - CVE-2004-1058
      A race condition allows for a local user to read the
      environment variables of another process that is still
      spawning through /proc/.../cmdline.

    - CVE-2004-2607
      A numeric casting discrepancy in sdla_xfer allows
      local users to read portions of kernel memory via a
      large len argument which is received as an int but
      cast to a short, preventing read loop from filling a
      buffer.

    - CVE-2005-0449
      An error in the skb_checksum_help() function from the
      netfilter framework has been discovered that allows
      the bypass of packet filter rules or a denial of
      service attack.

    - CVE-2005-1761
      A vulnerability in the ptrace subsystem of the IA-64
      architecture can allow local attackers to overwrite
      kernel memory and crash the kernel.

    - CVE-2005-2457
      Tim Yamin discovered that insufficient input
      validation in the compressed ISO file system (zisofs)
      allows a denial of service attack through maliciously
      crafted ISO images.

    - CVE-2005-2555
      Herbert Xu discovered that the setsockopt() function
      was not restricted to users/processes with the
      CAP_NET_ADMIN capability. This allows attackers to
      manipulate IPSEC policies or initiate a denial of
      service attack.

    - CVE-2005-2709
      Al Viro discovered a race condition in the /proc
      handling of network devices. A (local) attacker could
      exploit the stale reference after interface shutdown
      to cause a denial of service or possibly execute code
      in kernel mode.

    - CVE-2005-2973
      Tetsuo Handa discovered that the udp_v6_get_port()
      function from the IPv6 code can be forced into an
      endless loop, which allows a denial of service attack.

    - CVE-2005-3257
      Rudolf Polzer discovered that the kernel improperly
      restricts access to the KDSKBSENT ioctl, which can
      possibly lead to privilege escalation.

    - CVE-2005-3783
      The ptrace code using CLONE_THREAD didn't use the
      thread group ID to determine whether the caller is
      attaching to itself, which allows a denial of service
      attack.

    - CVE-2005-3806
      Yen Zheng discovered that the IPv6 flow label code
      modified an incorrect variable, which could lead to
      memory corruption and denial of service.

    - CVE-2005-3848
      Ollie Wild discovered a memory leak in the
      icmp_push_reply() function, which allows denial of
      service through memory consumption.

    - CVE-2005-3857
      Chris Wright discovered that excessive allocation of
      broken file lock leases in the VFS layer can exhaust
      memory and fill up the system logging, which allows
      denial of service.

    - CVE-2005-3858
      Patrick McHardy discovered a memory leak in the
      ip6_input_finish() function from the IPv6 code, which
      allows denial of service.

    - CVE-2005-4618
      Yi Ying discovered that sysctl does not properly
      enforce the size of a buffer, which allows a denial of
      service attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-0887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-2607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-0449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-1761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-2457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-2555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-2709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-2973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1018"
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
  Source                           2.4.27-10sarge2                  
  Alpha architecture               2.4.27-10sarge2                  
  ARM architecture                 2.4.27-2sarge2                   
  Intel IA-32 architecture         2.4.27-10sarge2                  
  Intel IA-64 architecture         2.4.27-10sarge2                  
  Motorola 680x0 architecture      2.4.27-3sarge2                   
  Big endian MIPS architecture     2.4.27-10.sarge1.040815-2        
  Little endian MIPS architecture  2.4.27-10.sarge1.040815-2        
  PowerPC architecture             2.4.27-10sarge2                  
  IBM S/390 architecture           2.4.27-2sarge2                   
  Sun Sparc architecture           2.4.27-9sarge2                   
The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update :

                              Debian 3.1 (sarge)          
  kernel-latest-2.4-alpha     101sarge1                   
  kernel-latest-2.4-i386      101sarge1                   
  kernel-latest-2.4-s390      2.4.27-1sarge1              
  kernel-latest-2.4-sparc     42sarge1                    
  kernel-latest-powerpc       102sarge1                   
  fai-kernels                 1.9.1sarge1                 
  i2c                         1:2.9.1-1sarge1             
  kernel-image-speakup-i386   2.4.27-1.1sasrge1           
  lm-sensors                  1:2.9.1-1sarge3             
  mindi-kernel                2.4.27-2sarge1              
  pcmcia-modules-2.4.27-i386  3.2.5+2sarge1               
  systemimager                3.2.3-6sarge1               
This update introduces a change in the kernel's binary interface, the
affected kernel packages inside Debian have been rebuilt, if you're
running local addons you'll need to rebuild these as well."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.4.27");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/16");
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
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-3-386", reference:"2.9.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-3-586tsc", reference:"2.9.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-3-686", reference:"2.9.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-3-686-smp", reference:"2.9.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-3-k6", reference:"2.9.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-3-k7", reference:"2.9.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-3-k7-smp", reference:"2.9.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-source", reference:"2.9.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27", reference:"2.4.27-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-3", reference:"2.4.27-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-apus", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-nubus", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc-small", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.4.27", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.4.27-speakup", reference:"2.4.27-1.1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-386", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-586tsc", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-686", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-686-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-generic", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-k6", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-k7", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-k7-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-s390", reference:"2.4.27-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-sparc32", reference:"42sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-sparc32-smp", reference:"42sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-sparc64", reference:"42sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-sparc64-smp", reference:"42sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27", reference:"2.4.27-10.sarge2.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3", reference:"2.4.27-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-386", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-586tsc", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-686", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-686-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-generic", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-itanium", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-itanium-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-k6", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-k7", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-k7-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-mckinley", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-mckinley-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-sparc32", reference:"2.4.27-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-sparc32-smp", reference:"2.4.27-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-sparc64", reference:"2.4.27-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-sparc64-smp", reference:"2.4.27-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-apus", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-nubus", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-powerpc", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-speakup", reference:"2.4.27-1.1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-386", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-586tsc", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-686", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-686-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-generic", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-itanium", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-itanium-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-k6", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-k7", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-k7-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-mckinley", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-mckinley-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-s390", reference:"2.4.27-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-s390x", reference:"2.4.27-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-sparc32", reference:"42sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-sparc32-smp", reference:"42sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-sparc64", reference:"42sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-sparc64-smp", reference:"42sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-386", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-586tsc", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-686", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-686-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-generic", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-itanium", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-itanium-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-k6", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-k7", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-k7-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-mckinley", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-mckinley-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-s390", reference:"2.4.27-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-s390-tape", reference:"2.4.27-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-s390x", reference:"2.4.27-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-sparc32", reference:"2.4.27-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-sparc32-smp", reference:"2.4.27-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-sparc64", reference:"2.4.27-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-sparc64-smp", reference:"2.4.27-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-amiga", reference:"2.4.27-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-apus", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-atari", reference:"2.4.27-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-bast", reference:"2.4.27-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-bvme6000", reference:"2.4.27-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-lart", reference:"2.4.27-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mac", reference:"2.4.27-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mvme147", reference:"2.4.27-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mvme16x", reference:"2.4.27-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-netwinder", reference:"2.4.27-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-nubus", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc-small", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-q40", reference:"2.4.27-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r3k-kn02", reference:"2.4.27-10.sarge2.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r4k-ip22", reference:"2.4.27-10.sarge2.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r4k-kn04", reference:"2.4.27-10.sarge2.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-cobalt", reference:"2.4.27-10.sarge2.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-ip22", reference:"2.4.27-10.sarge2.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-lasat", reference:"2.4.27-10.sarge2.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-riscpc", reference:"2.4.27-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-riscstation", reference:"2.4.27-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-sb1-swarm-bn", reference:"2.4.27-10.sarge2.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-speakup", reference:"2.4.27-1.1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-xxs1500", reference:"2.4.27-10.sarge2.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4-i2c", reference:"2.9.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4-lm-sensors", reference:"2.9.1-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-apus", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-nubus", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-powerpc", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-debian-2.4.27", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-386", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-586tsc", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-686", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-686-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-k6", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-k7", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-k7-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-386", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-586tsc", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-686", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-686-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-k6", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-k7", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-k7-smp", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-source-2.4.27", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-tree-2.4.27", reference:"2.4.27-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libsensors-dev", reference:"2.9.1-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libsensors3", reference:"2.9.1-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors", reference:"2.9.1-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-3-386", reference:"2.9.1-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-3-586tsc", reference:"2.9.1-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-3-686", reference:"2.9.1-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-3-686-smp", reference:"2.9.1-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-3-k6", reference:"2.9.1-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-3-k7", reference:"2.9.1-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-3-k7-smp", reference:"2.9.1-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-source", reference:"2.9.1-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"mindi-kernel", reference:"2.4.27-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"mips-tools", reference:"2.4.27-10.sarge2.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-3-386", reference:"3.2.5+2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-3-586tsc", reference:"3.2.5+2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-3-686", reference:"3.2.5+2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-3-686-smp", reference:"3.2.5+2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-3-k6", reference:"3.2.5+2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-3-k7", reference:"3.2.5+2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-3-k7-smp", reference:"3.2.5+2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"sensord", reference:"2.9.1-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-boot-i386-standard", reference:"3.2.3-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-boot-ia64-standard", reference:"3.2.3-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-client", reference:"3.2.3-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-common", reference:"3.2.3-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-doc", reference:"3.2.3-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-server", reference:"3.2.3-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-server-flamethrowerd", reference:"3.2.3-6sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
