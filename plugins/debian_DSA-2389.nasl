#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2389. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57583);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2011-2183", "CVE-2011-2213", "CVE-2011-2898", "CVE-2011-3353", "CVE-2011-4077", "CVE-2011-4110", "CVE-2011-4127", "CVE-2011-4611", "CVE-2011-4622", "CVE-2011-4914");
  script_bugtraq_id(46935, 48101, 48333, 48986, 49527, 50370, 50755, 51081, 51172, 51176);
  script_osvdb_id(78621, 78622);
  script_xref(name:"DSA", value:"2389");

  script_name(english:"Debian DSA-2389-1 : linux-2.6 - privilege escalation/denial of service/information leak");
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

  - CVE-2011-2183
    Andrea Righi reported an issue in KSM, a memory-saving
    de-duplication feature. By exploiting a race with
    exiting tasks, local users can cause a kernel oops,
    resulting in a denial of service.

  - CVE-2011-2213
    Dan Rosenberg discovered an issue in the INET socket
    monitoring interface. Local users could cause a denial
    of service by injecting code and causing the kernel to
    execute an infinite loop.

  - CVE-2011-2898
    Eric Dumazet reported an information leak in the raw
    packet socket implementation.

  - CVE-2011-3353
    Han-Wen Nienhuys reported a local denial of service
    issue in the FUSE (Filesystem in Userspace) support in
    the Linux kernel. Local users could cause a buffer
    overflow, leading to a kernel oops and resulting in a
    denial of service.

  - CVE-2011-4077
    Carlos Maiolino reported an issue in the XFS filesystem.
    A local user with the ability to mount a filesystem
    could corrupt memory resulting in a denial of service or
    possibly gain elevated privileges.

  - CVE-2011-4110
    David Howells reported an issue in the kernel's access
    key retention system which allow local users to cause a
    kernel oops leading to a denial of service.

  - CVE-2011-4127
    Paolo Bonzini of Red Hat reported an issue in the ioctl
    passthrough support for SCSI devices. Users with
    permission to access restricted portions of a device
    (e.g. a partition or a logical volume) can obtain access
    to the entire device by way of the SG_IO ioctl. This
    could be exploited by a local user or privileged VM
    guest to achieve a privilege escalation.

  - CVE-2011-4611
    Maynard Johnson reported an issue with the perf support
    on POWER7 systems that allows local users to cause a
    denial of service.

  - CVE-2011-4622
    Jan Kiszka reported an issue in the KVM PIT timer
    support. Local users with the permission to use KVM can
    cause a denial of service by starting a PIT timer
    without first setting up the irqchip.

  - CVE-2011-4914
    Ben Hutchings reported various bounds checking issues
    within the ROSE protocol support in the kernel. Remote
    users could possibly use this to gain access to
    sensitive memory or cause a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/linux-2.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2389"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.6.32-39squeeze1. Updates for issues impacting the oldstable
distribution (lenny) will be available soon.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                           Debian 6.0 (squeeze)     
  user-mode-linux          2.6.32-1um-4+39squeeze1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"firmware-linux-free", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-base", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-doc-2.6.32", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-486", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-4kc-malta", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-5kc-malta", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686-bigmem", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-amd64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-armel", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-i386", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-ia64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-mips", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-mipsel", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-powerpc", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-s390", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-sparc", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-amd64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-openvz", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-vserver", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-xen", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-iop32x", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-itanium", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-ixp4xx", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-kirkwood", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-mckinley", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-686", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-amd64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-orion5x", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc-smp", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r4k-ip22", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r5k-cobalt", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r5k-ip32", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-s390x", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sb1-bcm91250a", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sb1a-bcm91480b", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sparc64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sparc64-smp", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-versatile", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-amd64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-itanium", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-mckinley", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-powerpc", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-powerpc64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-s390x", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-sparc64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-686", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-amd64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-486", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-4kc-malta", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-5kc-malta", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem-dbg", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64-dbg", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-iop32x", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-itanium", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-ixp4xx", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-kirkwood", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-mckinley", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686-dbg", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64-dbg", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-orion5x", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc-smp", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r4k-ip22", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r5k-cobalt", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r5k-ip32", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-s390x", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-s390x-tape", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sb1-bcm91250a", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sb1a-bcm91480b", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sparc64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sparc64-smp", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-versatile", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64-dbg", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-itanium", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-mckinley", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-powerpc", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-powerpc64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-s390x", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-sparc64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686-dbg", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64-dbg", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-libc-dev", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-manual-2.6.32", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-patch-debian-2.6.32", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-source-2.6.32", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-support-2.6.32-5", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-tools-2.6.32", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-686", reference:"2.6.32-39squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-amd64", reference:"2.6.32-39squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
