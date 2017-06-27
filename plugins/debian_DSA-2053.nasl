#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2053. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(46725);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2009-4537", "CVE-2010-0727", "CVE-2010-1083", "CVE-2010-1084", "CVE-2010-1086", "CVE-2010-1087", "CVE-2010-1088", "CVE-2010-1162", "CVE-2010-1173", "CVE-2010-1187", "CVE-2010-1437", "CVE-2010-1446", "CVE-2010-1451");
  script_bugtraq_id(37521, 38393, 38479, 38898, 39042, 39044, 39101, 39120, 39480, 39569, 39719, 39794, 39798);
  script_osvdb_id(62387);
  script_xref(name:"DSA", value:"2053");

  script_name(english:"Debian DSA-2053-1 : linux-2.6 - privilege escalation/denial of service/information leak");
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

  - CVE-2009-4537
    Fabian Yamaguchi reported a missing check for Ethernet
    frames larger than the MTU in the r8169 driver. This may
    allow users on the local network to crash a system,
    resulting in a denial of service.

  - CVE-2010-0727
    Sachin Prabhu reported an issue in the GFS2 filesystem.
    Local users can trigger a BUG() altering the permissions
    on a locked file, resulting in a denial of service.

  - CVE-2010-1083
    Linus Torvalds reported an issue in the USB subsystem,
    which may allow local users to obtain portions of
    sensitive kernel memory.

  - CVE-2010-1084
    Neil Brown reported an issue in the Bluetooth subsystem
    that may permit remote attackers to overwrite memory
    through the creation of large numbers of sockets,
    resulting in a denial of service.

  - CVE-2010-1086
    Ang Way Chuang reported an issue in the DVB subsystem
    for Digital TV adapters. By creating a specially-encoded
    MPEG2-TS frame, a remote attacker could cause the
    receiver to enter an endless loop, resulting in a denial
    of service.

  - CVE-2010-1087
    Trond Myklebust reported an issue in the NFS filesystem.
    A local user may cause an oops by sending a fatal signal
    during a file truncation operation, resulting in a
    denial of service.

  - CVE-2010-1088
    Al Viro reported an issue where automount symlinks may
    not be followed when LOOKUP_FOLLOW is not set. This has
    an unknown security impact.

  - CVE-2010-1162
    Catalin Marinas reported an issue in the tty subsystem
    that allows local attackers to cause a kernel memory
    leak, possibly resulting in a denial of service.

  - CVE-2010-1173
    Chris Guo from Nokia China and Jukka Taimisto and Olli
    Jarva from Codenomicon Ltd reported an issue in the SCTP
    subsystem that allows a remote attacker to cause a
    denial of service using a malformed init package.

  - CVE-2010-1187
    Neil Hormon reported an issue in the TIPC subsystem.
    Local users can cause a denial of service by way of a
    NULL pointer dereference by sending datagrams through
    AF_TIPC before entering network mode.

  - CVE-2010-1437
    Toshiyuki Okajima reported a race condition in the
    keyring subsystem. Local users can cause memory
    corruption via keyctl commands that access a keyring in
    the process of being deleted, resulting in a denial of
    service.

  - CVE-2010-1446
    Wufei reported an issue with kgdb on the PowerPC
    architecture, allowing local users to write to kernel
    memory. Note: this issue does not affect binary kernels
    provided by Debian. The fix is provided for the benefit
    of users who build their own kernels from Debian source.

  - CVE-2010-1451
    Brad Spengler reported an issue on the SPARC
    architecture that allows local users to execute
    non-executable pages.

This update also includes fixes a regression introduced by a previous
update. See the referenced Debian bug page for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=573071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2053"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the stable distribution (lenny), these problems have been fixed in
version 2.6.26-22lenny1.

The user-mode-linux source package was additional rebuilt for
compatibility to take advantage of this update. The updated version of
the package is 2.6.26-1um-2+22lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"linux-doc-2.6.26", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-486", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-4kc-malta", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-5kc-malta", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686-bigmem", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-alpha", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-amd64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-arm", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-armel", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-hppa", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-i386", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-ia64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-mips", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-mipsel", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-powerpc", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-s390", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-sparc", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-generic", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-legacy", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-smp", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-amd64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-openvz", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-vserver", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-xen", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-footbridge", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-iop32x", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-itanium", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-ixp4xx", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-mckinley", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-686", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-amd64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-orion5x", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc-smp", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64-smp", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc-smp", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r4k-ip22", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r5k-cobalt", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r5k-ip32", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-s390", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-s390x", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sb1-bcm91250a", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sb1a-bcm91480b", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sparc64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sparc64-smp", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-versatile", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-amd64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-itanium", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-mckinley", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-s390x", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-sparc64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-686", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-amd64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-486", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-4kc-malta", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-5kc-malta", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686-bigmem", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-generic", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-legacy", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-smp", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-amd64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-footbridge", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-iop32x", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-itanium", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-ixp4xx", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-mckinley", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-686", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-amd64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-orion5x", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc-smp", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64-smp", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc-smp", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r4k-ip22", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r5k-cobalt", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r5k-ip32", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390-tape", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390x", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sb1-bcm91250a", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sb1a-bcm91480b", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sparc64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sparc64-smp", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-versatile", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-amd64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-itanium", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-mckinley", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-s390x", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-sparc64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-686", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-amd64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-libc-dev", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-manual-2.6.26", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-686", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-amd64", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-patch-debian-2.6.26", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-source-2.6.26", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-support-2.6.26-2", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-tree-2.6.26", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-686", reference:"2.6.26-22lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-amd64", reference:"2.6.26-22lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
