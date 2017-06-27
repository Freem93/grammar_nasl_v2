#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2240. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55028);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/08/18 13:36:11 $");

  script_cve_id("CVE-2010-3875", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0726", "CVE-2011-1016", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1090", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1478", "CVE-2011-1493", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1585", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1748", "CVE-2011-1759", "CVE-2011-1767", "CVE-2011-1770", "CVE-2011-1776", "CVE-2011-2022");
  script_bugtraq_id(44630, 46417, 46557, 46616, 46766, 46839, 46866, 46878, 46919, 46935, 46980, 47003, 47007, 47009, 47056, 47185, 47381, 47497, 47503, 47534, 47535, 47645, 47769, 47791, 47796, 47835, 47843, 47852);
  script_osvdb_id(69161, 70950, 71480, 71604, 71653, 71656, 71884, 71992, 72995, 73040, 73041, 73042, 73043, 73045, 73046, 73047, 73048, 73295, 73296, 73297, 73298, 73449, 73872, 74636, 74637, 74638, 74639, 74640, 74642, 74650, 74651, 74654, 74661);
  script_xref(name:"DSA", value:"2240");

  script_name(english:"Debian DSA-2240-1 : linux-2.6 - privilege escalation/denial of service/information leak");
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

  - CVE-2010-3875
    Vasiliy Kulikov discovered an issue in the Linux
    implementation of the Amateur Radio AX.25 Level 2
    protocol. Local users may obtain access to sensitive
    kernel memory.

  - CVE-2011-0695
    Jens Kuehnel reported an issue in the InfiniBand stack.
    Remote attackers can exploit a race condition to cause a
    denial of service (kernel panic).

  - CVE-2011-0711
    Dan Rosenberg reported an issue in the XFS filesystem.
    Local users may obtain access to sensitive kernel
    memory.

  - CVE-2011-0726
    Kees Cook reported an issue in the /proc/pid/stat
    implementation. Local users could learn the text
    location of a process, defeating protections provided by
    address space layout randomization (ASLR).

  - CVE-2011-1016
    Marek Olsak discovered an issue in the driver for
    ATI/AMD Radeon video chips. Local users could pass
    arbitrary values to video memory and the graphics
    translation table, resulting in denial of service or
    escalated privileges. On default Debian installations,
    this is exploitable only by members of the 'video'
    group.

  - CVE-2011-1078
    Vasiliy Kulikov discovered an issue in the Bluetooth
    subsystem. Local users can obtain access to sensitive
    kernel memory.

  - CVE-2011-1079
    Vasiliy Kulikov discovered an issue in the Bluetooth
    subsystem. Local users with the CAP_NET_ADMIN capability
    can cause a denial of service (kernel Oops).

  - CVE-2011-1080
    Vasiliy Kulikov discovered an issue in the Netfilter
    subsystem. Local users can obtain access to sensitive
    kernel memory.

  - CVE-2011-1090
    Neil Horman discovered a memory leak in the setacl()
    call on NFSv4 filesystems. Local users can exploit this
    to cause a denial of service (Oops).

  - CVE-2011-1160
    Peter Huewe reported an issue in the Linux kernel's
    support for TPM security chips. Local users with
    permission to open the device can gain access to
    sensitive kernel memory.

  - CVE-2011-1163
    Timo Warns reported an issue in the kernel support for
    Alpha OSF format disk partitions. Users with physical
    access can gain access to sensitive kernel memory by
    adding a storage device with a specially crafted OSF
    partition.

  - CVE-2011-1170
    Vasiliy Kulikov reported an issue in the Netfilter ARP
    table implementation. Local users with the CAP_NET_ADMIN
    capability can gain access to sensitive kernel memory.

  - CVE-2011-1171
    Vasiliy Kulikov reported an issue in the Netfilter IP
    table implementation. Local users with the CAP_NET_ADMIN
    capability can gain access to sensitive kernel memory.

  - CVE-2011-1172
    Vasiliy Kulikov reported an issue in the Netfilter IPv6
    table implementation. Local users with the CAP_NET_ADMIN
    capability can gain access to sensitive kernel memory.

  - CVE-2011-1173
    Vasiliy Kulikov reported an issue in the Acorn Econet
    protocol implementation. Local users can obtain access
    to sensitive kernel memory on systems that use this rare
    hardware.

  - CVE-2011-1180
    Dan Rosenberg reported a buffer overflow in the
    Information Access Service of the IrDA protocol, used
    for Infrared devices. Remote attackers within IR device
    range can cause a denial of service or possibly gain
    elevated privileges.

  - CVE-2011-1182
    Julien Tinnes reported an issue in the rt_sigqueueinfo
    interface. Local users can generate signals with
    falsified source pid and uid information.

  - CVE-2011-1476
    Dan Rosenberg reported issues in the Open Sound System
    MIDI interface that allow local users to cause a denial
    of service. This issue does not affect official Debian
    Linux image packages as they no longer provide support
    for OSS. However, custom kernels built from Debian's
    linux-source-2.6.32 may have enabled this configuration
    and would therefore be vulnerable.

  - CVE-2011-1477
    Dan Rosenberg reported issues in the Open Sound System
    driver for cards that include a Yamaha FM synthesizer
    chip. Local users can cause memory corruption resulting
    in a denial of service. This issue does not affect
    official Debian Linux image packages as they no longer
    provide support for OSS. However, custom kernels built
    from Debian's linux-source-2.6.32 may have enabled this
    configuration and would therefore be vulnerable.

  - CVE-2011-1478
    Ryan Sweat reported an issue in the Generic Receive
    Offload (GRO) support in the Linux networking subsystem.
    If an interface has GRO enabled and is running in
    promiscuous mode, remote users can cause a denial of
    service (NULL pointer dereference) by sending packets on
    an unknown VLAN.

  - CVE-2011-1493
    Dan Rosenburg reported two issues in the Linux
    implementation of the Amateur Radio X.25 PLP (Rose)
    protocol. A remote user can cause a denial of service by
    providing specially crafted facilities fields.

  - CVE-2011-1494
    Dan Rosenberg reported an issue in the /dev/mpt2ctl
    interface provided by the driver for LSI MPT Fusion SAS
    2.0 controllers. Local users can obtain elevated
    privileges by specially crafted ioctl calls. On default
    Debian installations this is not exploitable as this
    interface is only accessible to root.

  - CVE-2011-1495
    Dan Rosenberg reported two additional issues in the
    /dev/mpt2ctl interface provided by the driver for LSI
    MPT Fusion SAS 2.0 controllers. Local users can obtain
    elevated privileges and read arbitrary kernel memory by
    using specially crafted ioctl calls. On default Debian
    installations this is not exploitable as this interface
    is only accessible to root.

  - CVE-2011-1585
    Jeff Layton reported an issue in the Common Internet
    File System (CIFS). Local users can bypass
    authentication requirements for shares that are already
    mounted by another user.

  - CVE-2011-1593
    Robert Swiecki reported a signedness issue in the
    next_pidmap() function, which can be exploited by local
    users to cause a denial of service.

  - CVE-2011-1598
    Dave Jones reported an issue in the Broadcast Manager
    Controller Area Network (CAN/BCM) protocol that may
    allow local users to cause a NULL pointer dereference,
    resulting in a denial of service.

  - CVE-2011-1745
    Vasiliy Kulikov reported an issue in the Linux support
    for AGP devices. Local users can obtain elevated
    privileges or cause a denial of service due to missing
    bounds checking in the AGPIOC_BIND ioctl. On default
    Debian installations, this is exploitable only by users
    in the 'video' group.

  - CVE-2011-1746
    Vasiliy Kulikov reported an issue in the Linux support
    for AGP devices. Local users can obtain elevated
    privileges or cause a denial of service due to missing
    bounds checking in the agp_allocate_memory and
    agp_create_user_memory routines. On default Debian
    installations, this is exploitable only by users in the
    'video' group.

  - CVE-2011-1748
    Oliver Kartkopp reported an issue in the Controller Area
    Network (CAN) raw socket implementation which permits
    local users to cause a NULL pointer dereference,
    resulting in a denial of service.

  - CVE-2011-1759
    Dan Rosenberg reported an issue in the support for
    executing 'old ABI' binaries on ARM processors. Local
    users can obtain elevated privileges due to insufficient
    bounds checking in the semtimedop system call.

  - CVE-2011-1767
    Alexecy Dobriyan reported an issue in the GRE over IP
    implementation. Remote users can cause a denial of
    service by sending a packet during module
    initialization.

  - CVE-2011-1770
    Dan Rosenberg reported an issue in the Datagram
    Congestion Control Protocol (DCCP). Remote users can
    cause a denial of service or potentially obtain access
    to sensitive kernel memory.

  - CVE-2011-1776
    Timo Warns reported an issue in the Linux implementation
    for GUID partitions. Users with physical access can gain
    access to sensitive kernel memory by adding a storage
    device with a specially crafted corrupted invalid
    partition table.

  - CVE-2011-2022
    Vasiliy Kulikov reported an issue in the Linux support
    for AGP devices. Local users can obtain elevated
    privileges or cause a denial of service due to missing
    bounds checking in the AGPIOC_UNBIND ioctl. On default
    Debian installations, this is exploitable only by users
    in the video group.

This update also includes changes queued for the next point release of
Debian 6.0, which also fix various non-security issues. These
additional changes are described in the package changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2022"
  );
  # https://packages.debian.org/changelogs/pool/main/l/linux-2.6/linux-2.6_2.6.32-34/changelog
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?761a8c38"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/linux-2.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2240"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the stable distribution (squeeze), these problems have been fixed
in version 2.6.32-34squeeze1. Updates for issues impacting the
oldstable distribution (lenny) will be available soon.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                          Debian 6.0 (squeeze)     
  user-mode-linux          2.6.32-1um-4+34squeeze1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"firmware-linux-free", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-base", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-doc-2.6.32", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-486", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-4kc-malta", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-5kc-malta", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686-bigmem", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-amd64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-armel", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-i386", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-ia64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-mips", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-mipsel", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-powerpc", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-s390", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-sparc", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-amd64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-openvz", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-vserver", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-xen", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-iop32x", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-itanium", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-ixp4xx", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-kirkwood", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-mckinley", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-686", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-amd64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-orion5x", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc-smp", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r4k-ip22", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r5k-cobalt", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r5k-ip32", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-s390x", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sb1-bcm91250a", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sb1a-bcm91480b", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sparc64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sparc64-smp", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-versatile", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-amd64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-itanium", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-mckinley", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-powerpc", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-powerpc64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-s390x", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-sparc64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-686", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-amd64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-486", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-4kc-malta", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-5kc-malta", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem-dbg", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64-dbg", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-iop32x", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-itanium", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-ixp4xx", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-kirkwood", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-mckinley", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686-dbg", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64-dbg", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-orion5x", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc-smp", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r4k-ip22", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r5k-cobalt", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r5k-ip32", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-s390x", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-s390x-tape", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sb1-bcm91250a", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sb1a-bcm91480b", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sparc64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sparc64-smp", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-versatile", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64-dbg", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-itanium", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-mckinley", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-powerpc", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-powerpc64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-s390x", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-sparc64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686-dbg", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64-dbg", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-libc-dev", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-manual-2.6.32", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-patch-debian-2.6.32", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-source-2.6.32", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-support-2.6.32-5", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-tools-2.6.32", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-686", reference:"2.6.32-34squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-amd64", reference:"2.6.32-34squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
