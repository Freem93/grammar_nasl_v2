#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2668. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66431);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2012-2121", "CVE-2012-3552", "CVE-2012-4461", "CVE-2012-4508", "CVE-2012-6537", "CVE-2012-6539", "CVE-2012-6540", "CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2012-6548", "CVE-2012-6549", "CVE-2013-0349", "CVE-2013-0914", "CVE-2013-1767", "CVE-2013-1773", "CVE-2013-1774", "CVE-2013-1792", "CVE-2013-1796", "CVE-2013-1798", "CVE-2013-1826", "CVE-2013-1860", "CVE-2013-1928", "CVE-2013-1929", "CVE-2013-2015", "CVE-2013-2634", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3234", "CVE-2013-3235");
  script_bugtraq_id(53162, 55359, 56238, 56414, 58112, 58177, 58200, 58202, 58368, 58381, 58426, 58510, 58597, 58604, 58607, 58906, 58908, 58985, 58986, 58989, 58990, 58991, 58992, 58994, 59377, 59380, 59381, 59383, 59385, 59389, 59390, 59393, 59397, 59512);
  script_osvdb_id(81442, 85723, 87098, 88156, 90553, 90665, 90675, 90678, 90951, 90957, 90959, 90961, 90962, 90964, 90965, 90967, 90970, 90971, 91271, 91422, 91561, 91563, 91566, 92021, 92027, 92656, 92657, 92660, 92661, 92664, 92666, 92667, 92669, 92851);
  script_xref(name:"DSA", value:"2668");

  script_name(english:"Debian DSA-2668-1 : linux-2.6 - privilege escalation/denial of service/information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service, information leak or privilege
escalation. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2012-2121
    Benjamin Herrenschmidt and Jason Baron discovered issues
    with the IOMMU mapping of memory slots used in KVM
    device assignment. Local users with the ability to
    assign devices could cause a denial of service due to a
    memory page leak.

  - CVE-2012-3552
    Hafid Lin reported an issue in the IP networking
    subsystem. A remote user can cause a denial of service
    (system crash) on servers running applications that set
    options on sockets which are actively being processed.

  - CVE-2012-4461
    Jon Howell reported a denial of service issue in the KVM
    subsystem. On systems that do not support the XSAVE
    feature, local users with access to the /dev/kvm
    interface can cause a system crash.

  - CVE-2012-4508
    Dmitry Monakhov and Theodore Ts'o reported a race
    condition in the ext4 filesystem. Local users could gain
    access to sensitive kernel memory.

  - CVE-2012-6537
    Mathias Krause discovered information leak issues in the
    Transformation user configuration interface. Local users
    with the CAP_NET_ADMIN capability can gain access to
    sensitive kernel memory.

  - CVE-2012-6539
    Mathias Krause discovered an issue in the networking
    subsystem. Local users on 64-bit systems can gain access
    to sensitive kernel memory.

  - CVE-2012-6540
    Mathias Krause discovered an issue in the Linux virtual
    server subsystem. Local users can gain access to
    sensitive kernel memory. Note: this issue does not
    affect Debian provided kernels, but may affect custom
    kernels built from Debian's linux-source-2.6.32 package.

  - CVE-2012-6542
    Mathias Krause discovered an issue in the LLC protocol
    support code. Local users can gain access to sensitive
    kernel memory.

  - CVE-2012-6544
    Mathias Krause discovered issues in the Bluetooth
    subsystem. Local users can gain access to sensitive
    kernel memory.

  - CVE-2012-6545
    Mathias Krause discovered issues in the Bluetooth RFCOMM
    protocol support. Local users can gain access to
    sensitive kernel memory.

  - CVE-2012-6546
    Mathias Krause discovered issues in the ATM networking
    support. Local users can gain access to sensitive kernel
    memory.

  - CVE-2012-6548
    Mathias Krause discovered an issue in the UDF file
    system support. Local users can obtain access to
    sensitive kernel memory.

  - CVE-2012-6549
    Mathias Krause discovered an issue in the isofs file
    system support. Local users can obtain access to
    sensitive kernel memory.

  - CVE-2013-0349
    Anderson Lizardo discovered an issue in the Bluetooth
    Human Interface Device Protocol (HIDP) stack. Local
    users can obtain access to sensitive kernel memory.

  - CVE-2013-0914
    Emese Revfy discovered an issue in the signal
    implementation. Local users may be able to bypass the
    address space layout randomization (ASLR) facility due
    to a leaking of information to child processes.

  - CVE-2013-1767
    Greg Thelen reported an issue in the tmpfs virtual
    memory filesystem. Local users with sufficient privilege
    to mount filesystems can cause a denial of service or
    possibly elevated privileges due to a use-after free
    defect.

  - CVE-2013-1773
    Alan Stern provided a fix for a defect in the
    UTF8->UTF16 string conversion facility used by the VFAT
    filesystem. A local user could cause a buffer overflow
    condition, resulting in a denial of service or
    potentially elevated privileges.

  - CVE-2013-1774
    Wolfgang Frisch provided a fix for a NULL pointer
    dereference defect in the driver for some serial USB
    devices from Inside Out Networks. Local users with
    permission to access these devices can create a denial
    of service (kernel oops) by causing the device to be
    removed while it is in use.

  - CVE-2013-1792
    Mateusz Guzik of Red Hat EMEA GSS SEG Team discovered a
    race condition in the access key retention support in
    the kernel. A local user could cause a denial of service
    (NULL pointer dereference).

  - CVE-2013-1796
    Andrew Honig of Google reported an issue in the KVM
    subsystem. A user in a guest operating system could
    corrupt kernel memory, resulting in a denial of service.

  - CVE-2013-1798
    Andrew Honig of Google reported an issue in the KVM
    subsystem. A user in a guest operating system could
    cause a denial of service due to a use after-free
    defect.

  - CVE-2013-1826
    Mathias Krause discovered an issue in the Transformation
    (XFRM) user configuration interface of the networking
    stack. A user with the CAP_NET_ADMIN capability may be
    able to gain elevated privileges.

  - CVE-2013-1860
    Oliver Neukum discovered an issue in the USB CDC WCM
    Device Management driver. Local users with the ability
    to attach devices can cause a denial of service (kernel
    crash) or potentially gain elevated privileges.

  - CVE-2013-1928
    Kees Cook provided a fix for an information leak in the
    VIDEO_SET_SPU_PALETTE ioctl for 32-bit applications
    running on a 64-bit kernel. Local users can gain access
    to sensitive kernel memory.

  - CVE-2013-1929
    Oded Horovitz and Brad Spengler reported an issue in the
    device driver for Broadcom Tigon3 based gigabit
    Ethernet. Users with the ability to attach untrusted
    devices can create an overflow condition, resulting in a
    denial of service or elevated privileges.

  - CVE-2013-2015
    Theodore Ts'o provided a fix for an issue in the ext4
    filesystem. Local users with the ability to mount a
    specially crafted filesystem can cause a denial of
    service (infinite loop).

  - CVE-2013-2634
    Mathias Krause discovered a few issues in the Data
    Center Bridging (DCB) netlink interface. Local users can
    gain access to sensitive kernel memory.

  - CVE-2013-3222
    Mathias Krause discovered an issue in the Asynchronous
    Transfer Mode (ATM) protocol support. Local users can
    gain access to sensitive kernel memory.

  - CVE-2013-3223
    Mathias Krause discovered an issue in the Amateur Radio
    AX.25 protocol support. Local users can gain access to
    sensitive kernel memory.

  - CVE-2013-3224
    Mathias Krause discovered an issue in the Bluetooth
    subsystem. Local users can gain access to sensitive
    kernel memory.

  - CVE-2013-3225
    Mathias Krause discovered an issue in the Bluetooth
    RFCOMM protocol support. Local users can gain access to
    sensitive kernel memory.

  - CVE-2013-3228
    Mathias Krause discovered an issue in the IrDA
    (infrared) subsystem support. Local users can gain
    access to sensitive kernel memory.

  - CVE-2013-3229
    Mathias Krause discovered an issue in the IUCV support
    on s390 systems. Local users can gain access to
    sensitive kernel memory.

  - CVE-2013-3231
    Mathias Krause discovered an issue in the ANSI/IEEE
    802.2 LLC type 2 protocol support. Local users can gain
    access to sensitive kernel memory.

  - CVE-2013-3234
    Mathias Krause discovered an issue in the Amateur Radio
    X.25 PLP (Rose) protocol support. Local users can gain
    access to sensitive kernel memory.

  - CVE-2013-3235
    Mathias Krause discovered an issue in the Transparent
    Inter Process Communication (TIPC) protocol support.
    Local users can gain access to sensitive kernel memory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-6537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-6539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-6540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-6542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-6544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-6545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-6546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-6548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-6549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-3222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-3223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-3224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-3225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-3228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-3229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-3231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-3234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-3235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/linux-2.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2668"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 2.6.32-48squeeze3.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                           Debian 6.0 (squeeze)     
  user-mode-linux          2.6.32-1um-4+48squeeze3  
Note: Debian carefully tracks all known security issues across every
linux kernel package in all releases under active security support.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, updates for lower priority issues will normally not
be released for all kernels at the same time. Rather, they will be
released in a staggered or 'leap-frog' fashion."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"firmware-linux-free", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-base", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-doc-2.6.32", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-486", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-4kc-malta", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-5kc-malta", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686-bigmem", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-amd64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-armel", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-i386", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-ia64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-mips", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-mipsel", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-powerpc", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-s390", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-sparc", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-amd64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-openvz", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-vserver", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-xen", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-iop32x", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-itanium", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-ixp4xx", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-kirkwood", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-mckinley", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-686", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-amd64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-orion5x", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc-smp", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r4k-ip22", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r5k-cobalt", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r5k-ip32", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-s390x", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sb1-bcm91250a", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sb1a-bcm91480b", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sparc64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sparc64-smp", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-versatile", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-amd64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-itanium", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-mckinley", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-powerpc", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-powerpc64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-s390x", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-sparc64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-686", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-486", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-4kc-malta", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-5kc-malta", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem-dbg", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64-dbg", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-iop32x", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-itanium", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-ixp4xx", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-kirkwood", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-mckinley", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686-dbg", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64-dbg", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-orion5x", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc-smp", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r4k-ip22", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r5k-cobalt", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r5k-ip32", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-s390x", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-s390x-tape", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sb1-bcm91250a", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sb1a-bcm91480b", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sparc64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sparc64-smp", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-versatile", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64-dbg", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-itanium", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-mckinley", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-powerpc", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-powerpc64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-s390x", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-sparc64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686-dbg", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64-dbg", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-libc-dev", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-manual-2.6.32", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-patch-debian-2.6.32", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-source-2.6.32", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-support-2.6.32-5", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"linux-tools-2.6.32", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-686", reference:"2.6.32-48squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
