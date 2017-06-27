#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1017. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22559);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/06 20:12:49 $");

  script_cve_id("CVE-2004-1017", "CVE-2005-0124", "CVE-2005-0449", "CVE-2005-2457", "CVE-2005-2490", "CVE-2005-2555", "CVE-2005-2709", "CVE-2005-2800", "CVE-2005-2973", "CVE-2005-3044", "CVE-2005-3053", "CVE-2005-3055", "CVE-2005-3180", "CVE-2005-3181", "CVE-2005-3257", "CVE-2005-3356", "CVE-2005-3358", "CVE-2005-3783", "CVE-2005-3784", "CVE-2005-3806", "CVE-2005-3847", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858", "CVE-2005-4605", "CVE-2005-4618", "CVE-2006-0095", "CVE-2006-0096", "CVE-2006-0482", "CVE-2006-1066");
  script_osvdb_id(12349, 13533, 13850, 18978, 19027, 19260, 19316, 19597, 19598, 19702, 19734, 19924, 19925, 20061, 20163, 20676, 21283, 21284, 21285, 21516, 22212, 22213, 22215, 22418, 22419, 22506, 22507, 22822, 22902, 24098, 59802);
  script_xref(name:"DSA", value:"1017");

  script_name(english:"Debian DSA-1017-1 : kernel-source-2.6.8 - several vulnerabilities");
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

  - CVE-2004-1017
    Multiple overflows exist in the io_edgeport driver which
    might be usable as a denial of service attack vector.

  - CVE-2005-0124
    Bryan Fulton reported a bounds checking bug in the
    coda_pioctl function which may allow local users to
    execute arbitrary code or trigger a denial of service
    attack.

  - CVE-2005-0449
    An error in the skb_checksum_help() function from the
    netfilter framework has been discovered that allows the
    bypass of packet filter rules or a denial of service
    attack.

  - CVE-2005-2457
    Tim Yamin discovered that insufficient input validation
    in the zisofs driver for compressed ISO file systems
    allows a denial of service attack through maliciously
    crafted ISO images.

  - CVE-2005-2490
    A buffer overflow in the sendmsg() function allows local
    users to execute arbitrary code.

  - CVE-2005-2555
    Herbert Xu discovered that the setsockopt() function was
    not restricted to users/processes with the CAP_NET_ADMIN
    capability. This allows attackers to manipulate IPSEC
    policies or initiate a denial of service attack. 

  - CVE-2005-2709
    Al Viro discovered a race condition in the /proc
    handling of network devices. A (local) attacker could
    exploit the stale reference after interface shutdown to
    cause a denial of service or possibly execute code in
    kernel mode.

  - CVE-2005-2800
    Jan Blunck discovered that repeated failed reads of
    /proc/scsi/sg/devices leak memory, which allows a denial
    of service attack.

  - CVE-2005-2973
    Tetsuo Handa discovered that the udp_v6_get_port()
    function from the IPv6 code can be forced into an
    endless loop, which allows a denial of service attack.

  - CVE-2005-3044
    Vasiliy Averin discovered that the reference counters
    from sockfd_put() and fput() can be forced into
    overlapping, which allows a denial of service attack
    through a NULL pointer dereference.

  - CVE-2005-3053
    Eric Dumazet discovered that the set_mempolicy() system
    call accepts a negative value for its first argument,
    which triggers a BUG() assert. This allows a denial of
    service attack.

  - CVE-2005-3055
    Harald Welte discovered that if a process issues a USB
    Request Block (URB) to a device and terminates before
    the URB completes, a stale pointer would be
    dereferenced. This could be used to trigger a denial of
    service attack.

  - CVE-2005-3180
    Pavel Roskin discovered that the driver for Orinoco
    wireless cards clears its buffers insufficiently. This
    could leak sensitive information into user space.

  - CVE-2005-3181
    Robert Derr discovered that the audit subsystem uses an
    incorrect function to free memory, which allows a denial
    of service attack.

  - CVE-2005-3257
    Rudolf Polzer discovered that the kernel improperly
    restricts access to the KDSKBSENT ioctl, which can
    possibly lead to privilege escalation.

  - CVE-2005-3356
    Doug Chapman discovered that the mq_open syscall can be
    tricked into decrementing an internal counter twice,
    which allows a denial of service attack through a kernel
    panic.

  - CVE-2005-3358
    Doug Chapman discovered that passing a zero bitmask to
    the set_mempolicy() system call leads to a kernel panic,
    which allows a denial of service attack.

  - CVE-2005-3783
    The ptrace code using CLONE_THREAD didn't use the thread
    group ID to determine whether the caller is attaching to
    itself, which allows a denial of service attack.

  - CVE-2005-3784
    The auto-reaping of child processes functionality
    included ptraced-attached processes, which allows denial
    of service through dangling references.

  - CVE-2005-3806
    Yen Zheng discovered that the IPv6 flow label code
    modified an incorrect variable, which could lead to
    memory corruption and denial of service.

  - CVE-2005-3847
    It was discovered that a threaded real-time process,
    which is currently dumping core can be forced into a
    dead-lock situation by sending it a SIGKILL signal,
    which allows a denial of service attack. 

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

  - CVE-2005-4605
    Karl Janmar discovered that a signedness error in the
    procfs code can be exploited to read kernel memory,
    which may disclose sensitive information.

  - CVE-2005-4618
    Yi Ying discovered that sysctl does not properly enforce
    the size of a buffer, which allows a denial of service
    attack.

  - CVE-2006-0095
    Stefan Rompf discovered that dm_crypt does not clear an
    internal struct before freeing it, which might disclose
    sensitive information.

  - CVE-2006-0096
    It was discovered that the SDLA driver's capability
    checks were too lax for firmware upgrades.

  - CVE-2006-0482
    Ludovic Courtes discovered that get_compat_timespec()
    performs insufficient input sanitizing, which allows a
    local denial of service attack.

  - CVE-2006-1066
    It was discovered that ptrace() on the ia64 architecture
    allows a local denial of service attack, when preemption
    is enabled."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=295949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=334113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=330287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=332587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=332596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=330343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=330353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=327416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-0124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-0449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-2457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-2490"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2005-2800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-2973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3847"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1017"
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
  Source                       2.6.8-16sarge2               
  Alpha architecture           2.6.8-16sarge2               
  AMD64 architecture           2.6.8-16sarge2               
  HP Precision architecture    2.6.8-6sarge2                
  Intel IA-32 architecture     2.6.8-16sarge2               
  Intel IA-64 architecture     2.6.8-14sarge2               
  Motorola 680x0 architecture  2.6.8-4sarge2                
  PowerPC architecture         2.6.8-12sarge2               
  IBM S/390 architecture       2.6.8-5sarge2                
  Sun Sparc architecture       2.6.8-15sarge2               
The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update :

                            Debian 3.1 (sarge)        
  kernel-latest-2.6-alpha   101sarge1                 
  kernel-latest-2.6-amd64   103sarge1                 
  kernel-latest-2.6-hppa    2.6.8-1sarge1             
  kernel-latest-2.6-sparc   101sarge1                 
  kernel-latest-2.6-i386    101sarge1                 
  kernel-latest-powerpc     102sarge1                 
  fai-kernels               1.9.1sarge1               
  hostap-modules-i386       0.3.7-1sarge1             
  mol-modules-2.6.8         0.9.70+2.6.8+12sarge1     
  ndiswrapper-modules-i386  1.1-2sarge1               
This update introduces a change in the kernel's binary interface, the
affected kernel packages inside Debian have been rebuilt, if you're
running local addons you'll need to rebuild these as well. Due to the
change in the package name you need to use apt-get dist-upgrade to
update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.6.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/10");
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
if (deb_check(release:"3.1", prefix:"fai-kernels", reference:"1.9.1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-386", reference:"0.3.7-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-586tsc", reference:"0.3.7-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-686", reference:"0.3.7-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-686-smp", reference:"0.3.7-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-k6", reference:"0.3.7-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-k7", reference:"0.3.7-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-k7-smp", reference:"0.3.7-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-3-386", reference:"0.3.7-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-3-686", reference:"0.3.7-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-3-686-smp", reference:"0.3.7-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-3-k7", reference:"0.3.7-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-3-k7-smp", reference:"0.3.7-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-2", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3", reference:"2.6.8-15sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power3", reference:"2.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power3-smp", reference:"2.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power4", reference:"2.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power4-smp", reference:"2.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-powerpc", reference:"2.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-powerpc-smp", reference:"2.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-power3", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-power3-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-power4", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-power4-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-powerpc", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-powerpc-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.6.8", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.4", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-32", reference:"2.6.8-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-32-smp", reference:"2.6.8-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-386", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-64", reference:"2.6.8-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-64-smp", reference:"2.6.8-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-686", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-686-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-amd64-generic", reference:"103sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-amd64-k8", reference:"103sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-amd64-k8-smp", reference:"103sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-em64t-p4", reference:"103sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-em64t-p4-smp", reference:"103sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-generic", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium-smp", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-k7", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-k7-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley-smp", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-sparc32", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-sparc64", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-sparc64-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-amd64-generic", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-amd64-k8", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-amd64-k8-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-em64t-p4", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-em64t-p4-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-amd64-generic", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-amd64-k8", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-amd64-k8-smp", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-em64t-p4", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-em64t-p4-smp", reference:"2.6.8-16sarge2")) flag++;
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
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3", reference:"2.6.8-15sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-32", reference:"2.6.8-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-32-smp", reference:"2.6.8-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-386", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-64", reference:"2.6.8-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-64-smp", reference:"2.6.8-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-686", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-686-smp", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-generic", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-itanium", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-itanium-smp", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-k7", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-k7-smp", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-mckinley", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-mckinley-smp", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-smp", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc32", reference:"2.6.8-15sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc64", reference:"2.6.8-15sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc64-smp", reference:"2.6.8-15sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-powerpc", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.4-powerpc-smp", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-32", reference:"2.6.8-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-32-smp", reference:"2.6.8-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-386", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-64", reference:"2.6.8-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-64-smp", reference:"2.6.8-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-686", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-686-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-amd64-generic", reference:"103sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-amd64-k8", reference:"103sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-amd64-k8-smp", reference:"103sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-em64t-p4", reference:"103sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-em64t-p4-smp", reference:"103sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-generic", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium-smp", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-k7", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-k7-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley-smp", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-power3", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-power3-smp", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-power4", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-power4-smp", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-powerpc", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-powerpc-smp", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-sparc32", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-sparc64", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-sparc64-smp", reference:"101sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-amd64-generic", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-amd64-k8", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-amd64-k8-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-em64t-p4", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-em64t-p4-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-amd64-generic", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-amd64-k8", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-amd64-k8-smp", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-em64t-p4", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-em64t-p4-smp", reference:"2.6.8-16sarge2")) flag++;
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
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-32", reference:"2.6.8-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-32-smp", reference:"2.6.8-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-386", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-64", reference:"2.6.8-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-64-smp", reference:"2.6.8-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-686", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-686-smp", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-generic", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-itanium", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-itanium-smp", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-k7", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-k7-smp", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-mckinley", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-mckinley-smp", reference:"2.6.8-14sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power3", reference:"2.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power3-smp", reference:"2.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power4", reference:"2.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power4-smp", reference:"2.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-powerpc", reference:"2.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-powerpc-smp", reference:"2.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390", reference:"2.6.8-5sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390-tape", reference:"2.6.8-5sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390x", reference:"2.6.8-5sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-smp", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc32", reference:"2.6.8-15sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc64", reference:"2.6.8-15sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc64-smp", reference:"2.6.8-15sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-amiga", reference:"2.6.8-4sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-atari", reference:"2.6.8-4sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-bvme6000", reference:"2.6.8-4sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-hp", reference:"2.6.8-4sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mac", reference:"2.6.8-4sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme147", reference:"2.6.8-4sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme16x", reference:"2.6.8-4sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-power3", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-power3-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-power4", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-power4-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-powerpc", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-powerpc-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-q40", reference:"2.6.8-4sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-sun3", reference:"2.6.8-4sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-power3", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-power3-smp", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-power4", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-power4-smp", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-powerpc", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-powerpc-smp", reference:"102sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.6.8-s390", reference:"2.6.8-5sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-debian-2.6.8", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-source-2.6.8", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-tree-2.6.8", reference:"2.6.8-16sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mol-modules-2.6.8-3-powerpc", reference:"0.9.70+2.6.8+12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"mol-modules-2.6.8-3-powerpc-smp", reference:"0.9.70+2.6.8+12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ndiswrapper-modules-2.6.8-3-386", reference:"1.1-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ndiswrapper-modules-2.6.8-3-686", reference:"1.1-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ndiswrapper-modules-2.6.8-3-686-smp", reference:"1.1-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ndiswrapper-modules-2.6.8-3-k7", reference:"1.1-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ndiswrapper-modules-2.6.8-3-k7-smp", reference:"1.1-2sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
