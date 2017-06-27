#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2264. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55170);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2010-2524", "CVE-2010-3875", "CVE-2010-4075", "CVE-2010-4655", "CVE-2011-0695", "CVE-2011-0710", "CVE-2011-0711", "CVE-2011-0726", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1017", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1090", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1477", "CVE-2011-1493", "CVE-2011-1577", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1748", "CVE-2011-1759", "CVE-2011-1767", "CVE-2011-1768", "CVE-2011-1776", "CVE-2011-2022", "CVE-2011-2182");
  script_bugtraq_id(41904, 43806, 44630, 45972, 46417, 46421, 46492, 46512, 46616, 46766, 46793, 46839, 46866, 46878, 46919, 46935, 46980, 47003, 47009, 47343, 47497, 47503, 47534, 47535, 47645, 47791, 47796, 47835, 47843, 47852, 47853, 47990);
  script_osvdb_id(66582, 69161, 69522, 70950, 71359, 71480, 71599, 71601, 71653, 71656, 71884, 71992, 72996, 73037, 73040, 73041, 73042, 73043, 73045, 73046, 73049, 73295, 73296, 73297, 73298, 73872, 73882, 74636, 74637, 74639, 74640, 74642, 74650, 74651, 74652, 74654, 74662);
  script_xref(name:"DSA", value:"2264");

  script_name(english:"Debian DSA-2264-1 : linux-2.6 - privilege escalation/denial of service/information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leak. The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2010-2524
    David Howells reported an issue in the Common Internet
    File System (CIFS). Local users could cause arbitrary
    CIFS shares to be mounted by introducing malicious
    redirects.

  - CVE-2010-3875
    Vasiliy Kulikov discovered an issue in the Linux
    implementation of the Amateur Radio AX.25 Level 2
    protocol. Local users may obtain access to sensitive
    kernel memory.

  - CVE-2010-4075
    Dan Rosenberg reported an issue in the tty layer that
    may allow local users to obtain access to sensitive
    kernel memory.

  - CVE-2010-4655
    Kees Cook discovered several issues in the ethtool
    interface which may allow local users with the
    CAP_NET_ADMIN capability to obtain access to sensitive
    kernel memory.

  - CVE-2011-0695
    Jens Kuehnel reported an issue in the InfiniBand stack.
    Remote attackers can exploit a race condition to cause a
    denial of service (kernel panic).

  - CVE-2011-0710
    Al Viro reported an issue in the /proc/<pid>/status
    interface on the s390 architecture. Local users could
    gain access to sensitive memory in processes they do not
    own via the task_show_regs entry.

  - CVE-2011-0711
    Dan Rosenberg reported an issue in the XFS filesystem.
    Local users may obtain access to sensitive kernel
    memory.

  - CVE-2011-0726
    Kees Cook reported an issue in the /proc/<pid>/stat
    implementation. Local users could learn the text
    location of a process, defeating protections provided by
    address space layout randomization (ASLR).

  - CVE-2011-1010
    Timo Warns reported an issue in the Linux support for
    Mac partition tables. Local users with physical access
    could cause a denial of service (panic) by adding a
    storage device with a malicious map_count value.

  - CVE-2011-1012
    Timo Warns reported an issue in the Linux support for
    LDM partition tables. Local users with physical access
    could cause a denial of service (Oops) by adding a
    storage device with an invalid VBLK value in the VMDB
    structure.

  - CVE-2011-1017
    Timo Warns reported an issue in the Linux support for
    LDM partition tables. Users with physical access can
    gain access to sensitive kernel memory or gain elevated
    privileges by adding a storage device with a specially
    crafted LDM partition.

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

  - CVE-2011-1093
    Johan Hovold reported an issue in the Datagram
    Congestion Control Protocol (DCCP) implementation.
    Remote users could cause a denial of service by sending
    data after closing a socket.

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
    Vasiliy Kulikov reported an issue in the Netfilter arp
    table implementation. Local users with the CAP_NET_ADMIN
    capability can gain access to sensitive kernel memory.

  - CVE-2011-1171
    Vasiliy Kulikov reported an issue in the Netfilter IP
    table implementation. Local users with the CAP_NET_ADMIN
    capability can gain access to sensitive kernel memory.

  - CVE-2011-1172
    Vasiliy Kulikov reported an issue in the Netfilter IP6
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

  - CVE-2011-1477
    Dan Rosenberg reported issues in the Open Sound System
    driver for cards that include a Yamaha FM synthesizer
    chip. Local users can cause memory corruption resulting
    in a denial of service. This issue does not affect
    official Debian Linux image packages as they no longer
    provide support for OSS. However, custom kernels built
    from Debians linux-source-2.6.26 may have enabled this
    configuration and would therefore be vulnerable.

  - CVE-2011-1493
    Dan Rosenburg reported two issues in the Linux
    implementation of the Amateur Radio X.25 PLP (Rose)
    protocol. A remote user can cause a denial of service by
    providing specially crafted facilities fields.

  - CVE-2011-1577
    Timo Warns reported an issue in the Linux support for
    GPT partition tables. Local users with physical access
    could cause a denial of service (Oops) by adding a
    storage device with a malicious partition table header.

  - CVE-2011-1593
    Robert Swiecki reported a signednes issue in the
    next_pidmap() function, which can be exploited my local
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
    in the video group.

  - CVE-2011-1746
    Vasiliy Kulikov reported an issue in the Linux support
    for AGP devices. Local users can obtain elevated
    privileges or cause a denial of service due to missing
    bounds checking in the agp_allocate_memory and
    agp_create_user_memory. On default Debian installations,
    this is exploitable only by users in the video group.

  - CVE-2011-1748
    Oliver Kartkopp reported an issue in the Controller Area
    Network (CAN) raw socket implementation which permits
    ocal users to cause a NULL pointer dereference,
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

  - CVE-2011-1768
    Alexecy Dobriyan reported an issue in the IP tunnels
    implementation. Remote users can cause a denial of
    service by sending a packet during module
    initialization.

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

  - CVE-2011-2182
    Ben Hutchings reported an issue with the fix for
    CVE-2011-1017 (see above) that made it insufficient to
    resolve the issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=618485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0710"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1017"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1093"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1577"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2264"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages. These updates will
not become active until after the system is rebooted.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.6.26-26lenny3. Updates for arm and hppa are not yet
available, but will be released as soon as possible.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                         Debian 5.0 (lenny)     
  user-mode-linux        2.6.26-1um-2+26lenny3  
Note: Debian carefully tracks all known security issues across every
Linux kernel package in all releases under active security support.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, updates for lower priority issues will normally not
be released for all kernels at the same time. Rather, they will be
released in a staggered or 'leap-frog' fashion."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/20");
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
if (deb_check(release:"5.0", prefix:"linux-base", reference:"2.6.26-26lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
