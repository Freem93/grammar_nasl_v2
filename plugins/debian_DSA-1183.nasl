#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1183. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22725);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2005-4798", "CVE-2006-1528", "CVE-2006-2444", "CVE-2006-2446", "CVE-2006-2935", "CVE-2006-3745", "CVE-2006-4535");
  script_bugtraq_id(18081, 18101, 18847, 19666, 20087);
  script_osvdb_id(25744, 25750, 27540, 27781, 28119, 28551, 28937);
  script_xref(name:"CERT", value:"681569");
  script_xref(name:"DSA", value:"1183");

  script_name(english:"Debian DSA-1183-1 : kernel-source-2.4.27 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security related problems have been discovered in the Linux
kernel which may lead to a denial of service or even the execution of
arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2005-4798
    A buffer overflow in NFS readlink handling allows a
    malicious remote server to cause a denial of service.

  - CVE-2006-2935
    Diego Calleja Garcia discovered a buffer overflow in the
    DVD handling code that could be exploited by a specially
    crafted DVD USB storage device to execute arbitrary
    code.

  - CVE-2006-1528
    A bug in the SCSI driver allows a local user to cause a
    denial of service.

  - CVE-2006-2444
    Patrick McHardy discovered a bug in the SNMP NAT helper
    that allows remote attackers to cause a denial of
    service.

  - CVE-2006-2446
    A race condition in the socket buffer handling allows
    remote attackers to cause a denial of service.

  - CVE-2006-3745
    Wei Wang discovered a bug in the SCTP implementation
    that allows local users to cause a denial of service and
    possibly gain root privileges.

  - CVE-2006-4535
    David Miller reported a problem with the fix for
    CVE-2006-3745 that allows local users to crash the
    system via an SCTP socket with a certain SO_LINGER
    value.

The following matrix explains which kernel version for which
architecture fixes the problem mentioned above :

                               stable (sarge)               
  Source                       2.4.27-10sarge4              
  Alpha architecture           2.4.27-10sarge4              
  ARM architecture             2.4.27-2sarge4               
  Intel IA-32 architecture     2.4.27-10sarge4              
  Intel IA-64 architecture     2.4.27-10sarge4              
  Motorola 680x0 architecture  2.4.27-3sarge4               
  MIPS architectures           2.4.27-10.sarge4.040815-1    
  PowerPC architecture         2.4.27-10sarge4              
  IBM S/390                    2.4.27-2sarge4               
  Sun Sparc architecture       2.4.27-9sarge4               
  FAI                          1.9.1sarge4                  
  mindi-kernel                 2.4.27-2sarge3               
  kernel-image-speakup-i386    2.4.27-1.1sarge3             
  systemimager                 3.2.3-6sarge3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1183"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel package and reboot the machine. If you have built a
custom kernel from the kernel source package, you will need to rebuild
to take advantage of these fixes."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.4.27");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/27");
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
if (deb_check(release:"3.1", prefix:"fai-kernels", reference:"1.9.1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27", reference:"2.4.27-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-2", reference:"2.4.27-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-3", reference:"2.4.27-9sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-apus", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-nubus", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc-small", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.4.27", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.4.27-speakup", reference:"2.4.27-1.1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27", reference:"2.4.27-10.sarge4.040815-1")) flag++;
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
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3", reference:"2.4.27-9sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-386", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-586tsc", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-686", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-686-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-generic", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-itanium", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-itanium-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-k6", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-k7", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-k7-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-mckinley", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-mckinley-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-sparc32", reference:"2.4.27-9sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-sparc32-smp", reference:"2.4.27-9sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-sparc64", reference:"2.4.27-9sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-3-sparc64-smp", reference:"2.4.27-9sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-apus", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-nubus", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-powerpc", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-speakup", reference:"2.4.27-1.1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-itanium", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-itanium-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-mckinley", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-mckinley-smp", reference:"2.4.27-10sarge4")) flag++;
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
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-386", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-586tsc", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-686", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-686-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-generic", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-itanium", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-itanium-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-k6", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-k7", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-k7-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-mckinley", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-mckinley-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-s390", reference:"2.4.27-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-s390-tape", reference:"2.4.27-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-s390x", reference:"2.4.27-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-sparc32", reference:"2.4.27-9sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-sparc32-smp", reference:"2.4.27-9sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-sparc64", reference:"2.4.27-9sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-3-sparc64-smp", reference:"2.4.27-9sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-amiga", reference:"2.4.27-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-apus", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-atari", reference:"2.4.27-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-bast", reference:"2.4.27-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-bvme6000", reference:"2.4.27-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-lart", reference:"2.4.27-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mac", reference:"2.4.27-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mvme147", reference:"2.4.27-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mvme16x", reference:"2.4.27-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-netwinder", reference:"2.4.27-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-nubus", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc-small", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-q40", reference:"2.4.27-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r3k-kn02", reference:"2.4.27-10.sarge4.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r4k-ip22", reference:"2.4.27-10.sarge4.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r4k-kn04", reference:"2.4.27-10.sarge4.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-cobalt", reference:"2.4.27-10.sarge4.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-ip22", reference:"2.4.27-10.sarge4.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-lasat", reference:"2.4.27-10.sarge4.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-riscpc", reference:"2.4.27-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-riscstation", reference:"2.4.27-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-sb1-swarm-bn", reference:"2.4.27-10.sarge4.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-speakup", reference:"2.4.27-1.1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-xxs1500", reference:"2.4.27-10.sarge4.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-apus", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-nubus", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-powerpc", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-s390", reference:"2.4.27-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-debian-2.4.27", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-386", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-586tsc", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-686", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-686-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-k6", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-k7", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-2-k7-smp", reference:"2.4.27-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-386", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-586tsc", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-686", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-686-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-k6", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-k7", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-3-k7-smp", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-source-2.4.27", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-tree-2.4.27", reference:"2.4.27-10sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"mindi-kernel", reference:"2.4.27-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"mips-tools", reference:"2.4.27-10.sarge4.040815-1")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-boot-i386-standard", reference:"3.2.3-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-boot-ia64-standard", reference:"3.2.3-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-client", reference:"3.2.3-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-common", reference:"3.2.3-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-doc", reference:"3.2.3-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-server", reference:"3.2.3-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-server-flamethrowerd", reference:"3.2.3-6sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
