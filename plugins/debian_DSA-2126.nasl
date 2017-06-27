#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2126. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(50825);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2010-2963", "CVE-2010-3067", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3310", "CVE-2010-3432", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3448", "CVE-2010-3477", "CVE-2010-3705", "CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-3858", "CVE-2010-3859", "CVE-2010-3873", "CVE-2010-3874", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4074", "CVE-2010-4078", "CVE-2010-4079", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4083", "CVE-2010-4164");
  script_bugtraq_id(38607, 42529, 43221, 43229, 43353, 43368, 43480, 43551, 43701, 43787, 43809, 43810, 44242, 44301, 44354, 44630, 44642, 44661, 44665, 45054, 45055, 45058, 45062, 45063);
  script_osvdb_id(68163, 68177, 68306, 68370, 69424, 69551, 69788, 70226, 70262, 70290);
  script_xref(name:"DSA", value:"2126");

  script_name(english:"Debian DSA-2126-1 : linux-2.6 - privilege escalation/denial of service/information leak");
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

  - CVE-2010-2963
    Kees Cook discovered an issue in the v4l 32-bit
    compatibility layer for 64-bit systems that allows local
    users with /dev/video write permission to overwrite
    arbitrary kernel memory, potentially leading to a
    privilege escalation. On Debian systems, access to
    /dev/video devices is restricted to members of the
    'video' group by default.

  - CVE-2010-3067
    Tavis Ormandy discovered an issue in the io_submit
    system call. Local users can cause an integer overflow
    resulting in a denial of service.

  - CVE-2010-3296
    Dan Rosenberg discovered an issue in the cxgb network
    driver that allows unprivileged users to obtain the
    contents of sensitive kernel memory.

  - CVE-2010-3297
    Dan Rosenberg discovered an issue in the eql network
    driver that allows local users to obtain the contents of
    sensitive kernel memory.

  - CVE-2010-3310
    Dan Rosenberg discovered an issue in the ROSE socket
    implementation. On systems with a rose device, local
    users can cause a denial of service (kernel memory
    corruption).

  - CVE-2010-3432
    Thomas Dreibholz discovered an issue in the SCTP
    protocol that permits a remote user to cause a denial of
    service (kernel panic).

  - CVE-2010-3437
    Dan Rosenberg discovered an issue in the pktcdvd driver.
    Local users with permission to open /dev/pktcdvd/control
    can obtain the contents of sensitive kernel memory or
    cause a denial of service. By default on Debian systems,
    this access is restricted to members of the group
    'cdrom'.

  - CVE-2010-3442
    Dan Rosenberg discovered an issue in the ALSA sound
    system. Local users with permission to open
    /dev/snd/controlC0 can create an integer overflow
    condition that causes a denial of service. By default on
    Debian systems, this access is restricted to members of
    the group 'audio'.

  - CVE-2010-3448
    Dan Jacobson reported an issue in the thinkpad-acpi
    driver. On certain Thinkpad systems, local users can
    cause a denial of service (X.org crash) by reading
    /proc/acpi/ibm/video.

  - CVE-2010-3477
    Jeff Mahoney discovered an issue in the Traffic Policing
    (act_police) module that allows local users to obtain
    the contents of sensitive kernel memory.

  - CVE-2010-3705
    Dan Rosenberg reported an issue in the HMAC processing
    code in the SCTP protocol that allows remote users to
    create a denial of service (memory corruption).

  - CVE-2010-3848
    Nelson Elhage discovered an issue in the Econet
    protocol. Local users can cause a stack overflow
    condition with large msg->msgiovlen values that can
    result in a denial of service or privilege escalation.

  - CVE-2010-3849
    Nelson Elhage discovered an issue in the Econet
    protocol. Local users can cause a denial of service
    (oops) if a NULL remote addr value is passed as a
    parameter to sendmsg().

  - CVE-2010-3850
    Nelson Elhage discovered an issue in the Econet
    protocol. Local users can assign econet addresses to
    arbitrary interfaces due to a missing capabilities
    check.

  - CVE-2010-3858
    Brad Spengler reported an issue in the setup_arg_pages()
    function. Due to a bounds-checking failure, local users
    can create a denial of service (kernel oops).

  - CVE-2010-3859
    Dan Rosenberg reported an issue in the TIPC protocol.
    When the tipc module is loaded, local users can gain
    elevated privileges via the sendmsg() system call.

  - CVE-2010-3873
    Dan Rosenberg reported an issue in the X.25 network
    protocol. Local users can cause heap corruption,
    resulting in a denial of service (kernel panic).

  - CVE-2010-3874
    Dan Rosenberg discovered an issue in the Control Area
    Network (CAN) subsystem on 64-bit systems. Local users
    may be able to cause a denial of service (heap
    corruption).

  - CVE-2010-3875
    Vasiliy Kulikov discovered an issue in the AX.25
    protocol. Local users can obtain the contents of
    sensitive kernel memory.

  - CVE-2010-3876
    Vasiliy Kulikov discovered an issue in the Packet
    protocol. Local users can obtain the contents of
    sensitive kernel memory.

  - CVE-2010-3877
    Vasiliy Kulikov discovered an issue in the TIPC
    protocol. Local users can obtain the contents of
    sensitive kernel memory.

  - CVE-2010-3880
    Nelson Elhage discovered an issue in the INET_DIAG
    subsystem. Local users can cause the kernel to execute
    unaudited INET_DIAG bytecode, resulting in a denial of
    service.

  - CVE-2010-4072
    Kees Cook discovered an issue in the System V shared
    memory subsystem. Local users can obtain the contents of
    sensitive kernel memory.

  - CVE-2010-4073
    Dan Rosenberg discovered an issue in the System V shared
    memory subsystem. Local users on 64-bit system can
    obtain the contents of sensitive kernel memory via the
    32-bit compatible semctl() system call.

  - CVE-2010-4074
    Dan Rosenberg reported issues in the mos7720 and mos7840
    drivers for USB serial converter devices. Local users
    with access to these devices can obtain the contents of
    sensitive kernel memory.

  - CVE-2010-4078
    Dan Rosenberg reported an issue in the framebuffer
    driver for SiS graphics chipsets (sisfb). Local users
    with access to the framebuffer device can obtain the
    contents of sensitive kernel memory via the
    FBIOGET_VBLANK ioctl.

  - CVE-2010-4079
    Dan Rosenberg reported an issue in the ivtvfb driver
    used for the Hauppauge PVR-350 card. Local users with
    access to the framebuffer device can obtain the contents
    of sensitive kernel memory via the FBIOGET_VBLANK ioctl.

  - CVE-2010-4080
    Dan Rosenberg discovered an issue in the ALSA driver for
    RME Hammerfall DSP audio devices. Local users with
    access to the audio device can obtain the contents of
    sensitive kernel memory via the
    SNDRV_HDSP_IOCTL_GET_CONFIG_INFO ioctl.

  - CVE-2010-4081
    Dan Rosenberg discovered an issue in the ALSA driver for
    RME Hammerfall DSP MADI audio devices. Local users with
    access to the audio device can obtain the contents of
    sensitive kernel memory via the
    SNDRV_HDSP_IOCTL_GET_CONFIG_INFO ioctl.

  - CVE-2010-4083
    Dan Rosenberg discovered an issue in the semctl system
    call. Local users can obtain the contents of sensitive
    kernel memory through usage of the semid_ds structure.

  - CVE-2010-4164
    Dan Rosenberg discovered an issue in the X.25 network
    protocol. Remote users can achieve a denial of service
    (infinite loop) by taking advantage of an integer
    underflow in the facility parsing code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2126"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the stable distribution (lenny), this problem has been fixed in
version 2.6.26-26lenny1.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                         Debian 5.0 (lenny)     
  user-mode-linux        2.6.26-1um-2+26lenny1"
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/29");
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
if (deb_check(release:"5.0", prefix:"linux-doc-2.6.26", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-486", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-4kc-malta", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-5kc-malta", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686-bigmem", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-alpha", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-amd64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-arm", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-armel", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-hppa", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-i386", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-ia64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-mipsel", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-powerpc", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-s390", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-sparc", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-generic", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-legacy", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-smp", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-amd64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-openvz", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-vserver", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-xen", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-footbridge", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-iop32x", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-itanium", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-ixp4xx", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-mckinley", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-686", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-amd64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-orion5x", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc-smp", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64-smp", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc-smp", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r5k-cobalt", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-s390", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-s390x", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sb1-bcm91250a", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sb1a-bcm91480b", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sparc64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sparc64-smp", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-versatile", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-amd64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-itanium", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-mckinley", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-s390x", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-sparc64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-686", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-amd64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-486", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-4kc-malta", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-5kc-malta", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686-bigmem", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-generic", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-legacy", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-smp", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-amd64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-footbridge", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-iop32x", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-itanium", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-ixp4xx", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-mckinley", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-686", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-amd64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-orion5x", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc-smp", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64-smp", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc-smp", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r5k-cobalt", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390-tape", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390x", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sb1-bcm91250a", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sb1a-bcm91480b", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sparc64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sparc64-smp", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-versatile", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-amd64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-itanium", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-mckinley", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-s390x", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-sparc64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-686", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-amd64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-libc-dev", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-manual-2.6.26", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-686", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-amd64", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-patch-debian-2.6.26", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-source-2.6.26", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-support-2.6.26-2", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-tree-2.6.26", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-686", reference:"2.6.26-26lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-amd64", reference:"2.6.26-26lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
