#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1503. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31147);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2004-2731", "CVE-2006-4814", "CVE-2006-5753", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6054", "CVE-2006-6106", "CVE-2007-1353", "CVE-2007-1592", "CVE-2007-2172", "CVE-2007-2525", "CVE-2007-3848", "CVE-2007-4308", "CVE-2007-4311", "CVE-2007-5093", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6694", "CVE-2008-0007");
  script_bugtraq_id(23870, 25216, 25387, 26605, 26701, 27497, 27686);
  script_osvdb_id(34365, 40911, 40913, 42716);
  script_xref(name:"DSA", value:"1503");

  script_name(english:"Debian DSA-1503-1 : kernel-source-2.4.27 - several vulnerabilities");
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

  - CVE-2004-2731
    infamous41md reported multiple integer overflows in the
    Sbus PROM driver that would allow for a DoS (Denial of
    Service) attack by a local user, and possibly the
    execution of arbitrary code.

  - CVE-2006-4814
    Doug Chapman discovered a potential local DoS (deadlock)
    in the mincore function caused by improper lock
    handling.

  - CVE-2006-5753
    Eric Sandeen provided a fix for a local memory
    corruption vulnerability resulting from a
    misinterpretation of return values when operating on
    inodes which have been marked bad.

  - CVE-2006-5823
    LMH reported a potential local DoS which could be
    exploited by a malicious user with the privileges to
    mount and read a corrupted cramfs filesystem.

  - CVE-2006-6053
    LMH reported a potential local DoS which could be
    exploited by a malicious user with the privileges to
    mount and read a corrupted ext3 filesystem.

  - CVE-2006-6054
    LMH reported a potential local DoS which could be
    exploited by a malicious user with the privileges to
    mount and read a corrupted ext2 filesystem.

  - CVE-2006-6106
    Marcel Holtman discovered multiple buffer overflows in
    the Bluetooth subsystem which can be used to trigger a
    remote DoS (crash) and potentially execute arbitrary
    code.

  - CVE-2007-1353
    Ilja van Sprundel discovered that kernel memory could be
    leaked via the Bluetooth setsockopt call due to an
    uninitialized stack buffer. This could be used by local
    attackers to read the contents of sensitive kernel
    memory.

  - CVE-2007-1592
    Masayuki Nakagawa discovered that flow labels were
    inadvertently being shared between listening sockets and
    child sockets. This defect can be exploited by local
    users to cause a DoS (Oops).

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

  - CVE-2007-3848
    Wojciech Purczynski discovered that pdeath_signal was
    not being reset properly under certain conditions which
    may allow local users to gain privileges by sending
    arbitrary signals to suid binaries.

  - CVE-2007-4308
    Alan Cox reported an issue in the aacraid driver that
    allows unprivileged local users to make ioctl calls
    which should be restricted to admin privileges.

  - CVE-2007-4311
    PaX team discovered an issue in the random driver where
    a defect in the reseeding code leads to a reduction in
    entropy.

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
  alsa-modules-i386            1.0.8+2sarge2                
  kernel-image-2.4.27-arm      2.4.27-2sarge6               
  kernel-image-2.4.27-m68k     2.4.27-3sarge6               
  kernel-image-speakup-i386    2.4.27-1.1sarge5             
  kernel-image-2.4.27-alpha    2.4.27-10sarge6              
  kernel-image-2.4.27-s390     2.4.27-2sarge6               
  kernel-image-2.4.27-sparc    2.4.27-9sarge6               
  kernel-image-2.4.27-i386     2.4.27-10sarge6              
  kernel-image-2.4.27-ia64     2.4.27-10sarge6              
  kernel-patch-2.4.27-mips     2.4.27-10.sarge4.040815-3    
  kernel-patch-powerpc-2.4.27  2.4.27-10sarge6              
  kernel-latest-2.4-alpha      101sarge3                    
  kernel-latest-2.4-i386       101sarge2                    
  kernel-latest-2.4-s390       2.4.27-1sarge2               
  kernel-latest-2.4-sparc      42sarge3                     
  i2c                          1:2.9.1-1sarge2              
  lm-sensors                   1:2.9.1-1sarge4              
  mindi-kernel                 2.4.27-2sarge5               
  pcmcia-modules-2.4.27-i386   3.2.5+2sarge2                
  hostap-modules-i386          1:0.3.7-1sarge3              
  systemimager                 3.2.3-6sarge5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-2731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1592"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4311"
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
    value:"http://www.debian.org/security/2008/dsa-1503"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel package immediately and reboot the machine. If you
have built a custom kernel from the kernel source package, you will
need to rebuild to take advantage of these fixes."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 20, 119, 189, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.4.27");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/16");
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
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-4-386", reference:"0.3.7-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-4-586tsc", reference:"0.3.7-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-4-686", reference:"0.3.7-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-4-686-smp", reference:"0.3.7-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-4-k6", reference:"0.3.7-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-4-k7", reference:"0.3.7-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-4-k7-smp", reference:"0.3.7-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-4-386", reference:"0.3.7-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-4-686", reference:"0.3.7-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-4-686-smp", reference:"0.3.7-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-4-k7", reference:"0.3.7-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-4-k7-smp", reference:"0.3.7-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-4-386", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-4-586tsc", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-4-686", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-4-686-smp", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-4-k6", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-4-k7", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-2.4.27-4-k7-smp", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"i2c-source", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27", reference:"2.4.27-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-4", reference:"2.4.27-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-apus", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-nubus", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc-small", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.4.27-powerpc-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.4.27", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.4.27-speakup", reference:"2.4.27-1.1sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-386", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-586tsc", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-686", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-686-smp", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-generic", reference:"101sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-k6", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-k7", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-k7-smp", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-s390", reference:"2.4.27-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-smp", reference:"101sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-sparc32", reference:"42sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-sparc32-smp", reference:"42sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-sparc64", reference:"42sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4-sparc64-smp", reference:"42sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27", reference:"2.4.27-10.sarge4.040815-3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4", reference:"2.4.27-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-386", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-586tsc", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-686", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-686-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-generic", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-itanium", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-itanium-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-k6", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-k7", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-k7-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-mckinley", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-mckinley-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-sparc32", reference:"2.4.27-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-sparc32-smp", reference:"2.4.27-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-sparc64", reference:"2.4.27-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-4-sparc64-smp", reference:"2.4.27-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-apus", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-nubus", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-powerpc", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4.27-speakup", reference:"2.4.27-1.1sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-386", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-586tsc", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-686", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-686-smp", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-generic", reference:"101sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-itanium", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-itanium-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-k6", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-k7", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-k7-smp", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-mckinley", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-mckinley-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-s390", reference:"2.4.27-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-s390x", reference:"2.4.27-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-smp", reference:"101sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-sparc32", reference:"42sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-sparc32-smp", reference:"42sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-sparc64", reference:"42sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-sparc64-smp", reference:"42sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-386", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-586tsc", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-686", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-686-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-generic", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-itanium", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-itanium-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-k6", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-k7", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-k7-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-mckinley", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-mckinley-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-s390", reference:"2.4.27-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-s390-tape", reference:"2.4.27-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-s390x", reference:"2.4.27-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-sparc32", reference:"2.4.27-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-sparc32-smp", reference:"2.4.27-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-sparc64", reference:"2.4.27-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-4-sparc64-smp", reference:"2.4.27-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-amiga", reference:"2.4.27-3sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-apus", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-atari", reference:"2.4.27-3sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-bast", reference:"2.4.27-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-bvme6000", reference:"2.4.27-3sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-lart", reference:"2.4.27-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mac", reference:"2.4.27-3sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mvme147", reference:"2.4.27-3sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-mvme16x", reference:"2.4.27-3sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-netwinder", reference:"2.4.27-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-nubus", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc-small", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-powerpc-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-q40", reference:"2.4.27-3sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r3k-kn02", reference:"2.4.27-10.sarge4.040815-3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r4k-ip22", reference:"2.4.27-10.sarge4.040815-3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r4k-kn04", reference:"2.4.27-10.sarge4.040815-3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-cobalt", reference:"2.4.27-10.sarge4.040815-3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-ip22", reference:"2.4.27-10.sarge4.040815-3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-r5k-lasat", reference:"2.4.27-10.sarge4.040815-3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-riscpc", reference:"2.4.27-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-riscstation", reference:"2.4.27-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-sb1-swarm-bn", reference:"2.4.27-10.sarge4.040815-3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-speakup", reference:"2.4.27-1.1sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4.27-xxs1500", reference:"2.4.27-10.sarge4.040815-3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4-i2c", reference:"2.9.1-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4-lm-sensors", reference:"2.9.1-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-apus", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-nubus", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.4.27-powerpc", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-debian-2.4.27", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-386", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-586tsc", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-686", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-686-smp", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-k6", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-k7", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4-k7-smp", reference:"101sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-4-386", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-4-586tsc", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-4-686", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-4-686-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-4-k6", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-4-k7", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-pcmcia-modules-2.4.27-4-k7-smp", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-source-2.4.27", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-tree-2.4.27", reference:"2.4.27-10sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libsensors-dev", reference:"2.9.1-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"libsensors3", reference:"2.9.1-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors", reference:"2.9.1-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-4-386", reference:"2.9.1-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-4-586tsc", reference:"2.9.1-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-4-686", reference:"2.9.1-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-4-686-smp", reference:"2.9.1-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-4-k6", reference:"2.9.1-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-4-k7", reference:"2.9.1-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-2.4.27-4-k7-smp", reference:"2.9.1-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"lm-sensors-source", reference:"2.9.1-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"mindi-kernel", reference:"2.4.27-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"mips-tools", reference:"2.4.27-10.sarge4.040815-3")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-4-386", reference:"3.2.5+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-4-586tsc", reference:"3.2.5+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-4-686", reference:"3.2.5+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-4-686-smp", reference:"3.2.5+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-4-k6", reference:"3.2.5+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-4-k7", reference:"3.2.5+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"pcmcia-modules-2.4.27-4-k7-smp", reference:"3.2.5+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"sensord", reference:"2.9.1-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-boot-i386-standard", reference:"3.2.3-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-boot-ia64-standard", reference:"3.2.3-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-client", reference:"3.2.3-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-common", reference:"3.2.3-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-doc", reference:"3.2.3-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-server", reference:"3.2.3-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"systemimager-server-flamethrowerd", reference:"3.2.3-6sarge5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
