#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2303. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56130);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2011-1020", "CVE-2011-1576", "CVE-2011-2484", "CVE-2011-2491", "CVE-2011-2492", "CVE-2011-2495", "CVE-2011-2496", "CVE-2011-2497", "CVE-2011-2517", "CVE-2011-2525", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2905", "CVE-2011-2909", "CVE-2011-2918", "CVE-2011-2928", "CVE-2011-3188", "CVE-2011-3191");
  script_bugtraq_id(46567, 47321, 48383, 48441, 48472, 48538, 48641, 48804, 48907, 48929, 49140, 49141, 49152, 49256, 49289, 49295, 49408, 49411);
  script_xref(name:"DSA", value:"2303");

  script_name(english:"Debian DSA-2303-2 : linux-2.6 - privilege escalation/denial of service/information leak");
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

  - CVE-2011-1020
    Kees Cook discovered an issue in the /proc filesystem
    that allows local users to gain access to sensitive
    process information after execution of a setuid binary.

  - CVE-2011-1576
    Ryan Sweat discovered an issue in the VLAN
    implementation. Local users may be able to cause a
    kernel memory leak, resulting in a denial of service.

  - CVE-2011-2484
    Vasiliy Kulikov of Openwall discovered that the number
    of exit handlers that a process can register is not
    capped, resulting in local denial of service through
    resource exhaustion (CPU time and memory).

  - CVE-2011-2491
    Vasily Averin discovered an issue with the NFS locking
    implementation. A malicious NFS server can cause a
    client to hang indefinitely in an unlock call.

  - CVE-2011-2492
    Marek Kroemeke and Filip Palian discovered that
    uninitialized struct elements in the Bluetooth subsystem
    could lead to a leak of sensitive kernel memory through
    leaked stack memory.

  - CVE-2011-2495
    Vasiliy Kulikov of Openwall discovered that the io file
    of a process' proc directory was world-readable,
    resulting in local information disclosure of information
    such as password lengths.

  - CVE-2011-2496
    Robert Swiecki discovered that mremap() could be abused
    for local denial of service by triggering a BUG_ON
    assert.

  - CVE-2011-2497
    Dan Rosenberg discovered an integer underflow in the
    Bluetooth subsystem, which could lead to denial of
    service or privilege escalation.

  - CVE-2011-2517
    It was discovered that the netlink-based wireless
    configuration interface performed insufficient length
    validation when parsing SSIDs, resulting in buffer
    overflows. Local users with the CAP_NET_ADMIN capability
    can cause a denial of service.

  - CVE-2011-2525
    Ben Pfaff reported an issue in the network scheduling
    code. A local user could cause a denial of service (NULL
    pointer dereference) by sending a specially crafted
    netlink message.

  - CVE-2011-2700
    Mauro Carvalho Chehab of Red Hat reported a buffer
    overflow issue in the driver for the Si4713 FM Radio
    Transmitter driver used by N900 devices. Local users
    could exploit this issue to cause a denial of service or
    potentially gain elevated privileges.

  - CVE-2011-2723
    Brent Meshier reported an issue in the GRO (generic
    receive offload) implementation. This can be exploited
    by remote users to create a denial of service (system
    crash) in certain network device configurations.

  - CVE-2011-2905
    Christian Ohm discovered that the 'perf' analysis tool
    searches for its config files in the current working
    directory. This could lead to denial of service or
    potential privilege escalation if a user with elevated
    privileges is tricked into running 'perf' in a directory
    under the control of the attacker.

  - CVE-2011-2909
    Vasiliy Kulikov of Openwall discovered that a
    programming error in the Comedi driver could lead to the
    information disclosure through leaked stack memory.

  - CVE-2011-2918
    Vince Weaver discovered that incorrect handling of
    software event overflows in the 'perf' analysis tool
    could lead to local denial of service.

  - CVE-2011-2928
    Timo Warns discovered that insufficient validation of Be
    filesystem images could lead to local denial of service
    if a malformed filesystem image is mounted.

  - CVE-2011-3188
    Dan Kaminsky reported a weakness of the sequence number
    generation in the TCP protocol implementation. This can
    be used by remote attackers to inject packets into an
    active session.

  - CVE-2011-3191
    Darren Lavender reported an issue in the Common Internet
    File System (CIFS). A malicious file server could cause
    memory corruption leading to a denial of service.

This update also includes a fix for a regression introduced with the
previous security fix for CVE-2011-1768 (Debian bug #633738)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=633738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/linux-2.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2303"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.6.32-35squeeze2. Updates for issues impacting the oldstable
distribution (lenny) will be available soon.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                           Debian 6.0 (squeeze)     
  user-mode-linux          2.6.32-1um-4+35squeeze2"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/09");
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
if (deb_check(release:"6.0", prefix:"firmware-linux-free", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-base", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-doc-2.6.32", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-486", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-4kc-malta", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-5kc-malta", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686-bigmem", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-amd64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-armel", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-i386", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-ia64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-mips", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-mipsel", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-powerpc", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-s390", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-sparc", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-amd64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-openvz", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-vserver", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-xen", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-iop32x", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-itanium", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-ixp4xx", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-kirkwood", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-mckinley", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-686", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-amd64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-orion5x", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc-smp", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r4k-ip22", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r5k-cobalt", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r5k-ip32", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-s390x", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sb1-bcm91250a", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sb1a-bcm91480b", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sparc64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sparc64-smp", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-versatile", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-amd64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-itanium", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-mckinley", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-powerpc", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-powerpc64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-s390x", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-sparc64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-686", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-amd64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-486", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-4kc-malta", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-5kc-malta", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem-dbg", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64-dbg", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-iop32x", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-itanium", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-ixp4xx", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-kirkwood", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-mckinley", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686-dbg", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64-dbg", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-orion5x", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc-smp", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r4k-ip22", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r5k-cobalt", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r5k-ip32", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-s390x", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-s390x-tape", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sb1-bcm91250a", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sb1a-bcm91480b", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sparc64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sparc64-smp", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-versatile", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64-dbg", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-itanium", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-mckinley", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-powerpc", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-powerpc64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-s390x", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-sparc64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686-dbg", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64-dbg", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-libc-dev", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-manual-2.6.32", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-patch-debian-2.6.32", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-source-2.6.32", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-support-2.6.32-5", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"linux-tools-2.6.32", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-686", reference:"2.6.32-35squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-amd64", reference:"2.6.32-35squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
