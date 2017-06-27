#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1749. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35987);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-0029", "CVE-2009-0031", "CVE-2009-0065", "CVE-2009-0269", "CVE-2009-0322", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0745", "CVE-2009-0746", "CVE-2009-0747", "CVE-2009-0748");
  script_bugtraq_id(33113, 33846);
  script_xref(name:"DSA", value:"1749");

  script_name(english:"Debian DSA-1749-1 : linux-2.6 - denial of service/privilege escalation/sensitive memory leak");
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

  - CVE-2009-0029
    Christian Borntraeger discovered an issue effecting the
    alpha, mips, powerpc, s390 and sparc64 architectures
    that allows local users to cause a denial of service or
    potentially gain elevated privileges.

  - CVE-2009-0031
    Vegard Nossum discovered a memory leak in the keyctl
    subsystem that allows local users to cause a denial of
    service by consuming all of kernel memory.

  - CVE-2009-0065
    Wei Yongjun discovered a memory overflow in the SCTP
    implementation that can be triggered by remote users.

  - CVE-2009-0269
    Duane Griffin provided a fix for an issue in the
    eCryptfs subsystem which allows local users to cause a
    denial of service (fault or memory corruption).

  - CVE-2009-0322
    Pavel Roskin provided a fix for an issue in the dell_rbu
    driver that allows a local user to cause a denial of
    service (oops) by reading 0 bytes from a sysfs entry.

  - CVE-2009-0676
    Clement LECIGNE discovered a bug in the sock_getsockopt
    function that may result in leaking sensitive kernel
    memory.

  - CVE-2009-0675
    Roel Kluin discovered inverted logic in the skfddi
    driver that permits local, unprivileged users to reset
    the driver statistics.

  - CVE-2009-0745
    Peter Kerwien discovered an issue in the ext4 filesystem
    that allows local users to cause a denial of service
    (kernel oops) during a resize operation.

  - CVE-2009-0746
    Sami Liedes reported an issue in the ext4 filesystem
    that allows local users to cause a denial of service
    (kernel oops) when accessing a specially crafted corrupt
    filesystem.

  - CVE-2009-0747
    David Maciejak reported an issue in the ext4 filesystem
    that allows local users to cause a denial of service
    (kernel oops) when mounting a specially crafted corrupt
    filesystem.

  - CVE-2009-0748
    David Maciejak reported an additional issue in the ext4
    filesystem that allows local users to cause a denial of
    service (kernel oops) when mounting a specially crafted
    corrupt filesystem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1749"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 packages.

For the oldstable distribution (etch), these problems, where
applicable, will be fixed in future updates to linux-2.6 and
linux-2.6.24.

For the stable distribution (lenny), these problems have been fixed in
version 2.6.26-13lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"linux-doc-2.6.26", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-486", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-4kc-malta", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-5kc-malta", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-686", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-686-bigmem", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-all", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-all-alpha", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-all-amd64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-all-arm", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-all-armel", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-all-hppa", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-all-i386", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-all-ia64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-all-mips", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-all-mipsel", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-all-powerpc", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-all-s390", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-all-sparc", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-alpha-generic", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-alpha-legacy", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-alpha-smp", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-amd64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-common", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-common-openvz", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-common-vserver", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-common-xen", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-footbridge", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-iop32x", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-itanium", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-ixp4xx", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-mckinley", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-openvz-686", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-openvz-amd64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-orion5x", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-parisc", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-parisc-smp", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-parisc64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-parisc64-smp", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-powerpc", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-powerpc-smp", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-powerpc64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-r4k-ip22", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-r5k-cobalt", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-r5k-ip32", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-s390", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-s390x", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-sb1-bcm91250a", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-sb1a-bcm91480b", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-sparc64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-sparc64-smp", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-versatile", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-vserver-686", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-vserver-686-bigmem", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-vserver-amd64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-vserver-itanium", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-vserver-mckinley", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-vserver-powerpc", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-vserver-powerpc64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-vserver-s390x", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-vserver-sparc64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-xen-686", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-1-xen-amd64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-486", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-4kc-malta", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-5kc-malta", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-686", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-686-bigmem", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-alpha-generic", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-alpha-legacy", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-alpha-smp", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-amd64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-footbridge", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-iop32x", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-itanium", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-ixp4xx", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-mckinley", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-openvz-686", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-openvz-amd64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-orion5x", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-parisc", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-parisc-smp", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-parisc64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-parisc64-smp", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-powerpc", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-powerpc-smp", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-powerpc64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-r4k-ip22", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-r5k-cobalt", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-r5k-ip32", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-s390", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-s390-tape", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-s390x", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-sb1-bcm91250a", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-sb1a-bcm91480b", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-sparc64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-sparc64-smp", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-versatile", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-vserver-686", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-vserver-686-bigmem", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-vserver-amd64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-vserver-itanium", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-vserver-mckinley", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-vserver-powerpc", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-vserver-powerpc64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-vserver-s390x", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-vserver-sparc64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-xen-686", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-1-xen-amd64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-libc-dev", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-manual-2.6.26", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-1-xen-686", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-1-xen-amd64", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-patch-debian-2.6.26", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-source-2.6.26", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-support-2.6.26-1", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-tree-2.6.26", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-1-xen-686", reference:"2.6.26-13lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-1-xen-amd64", reference:"2.6.26-13lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
