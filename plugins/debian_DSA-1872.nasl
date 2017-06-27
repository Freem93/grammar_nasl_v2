#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1872. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44737);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2009-2698", "CVE-2009-2846", "CVE-2009-2847", "CVE-2009-2848", "CVE-2009-2849");
  script_bugtraq_id(35930, 36004, 36108);
  script_xref(name:"DSA", value:"1872");

  script_name(english:"Debian DSA-1872-1 : linux-2.6 - denial of service/privilege escalation/information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to denial of service, privilege escalation or a leak of
sensitive memory. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2009-2698
    Herbert Xu discovered an issue in the way UDP tracks
    corking status that could allow local users to cause a
    denial of service (system crash). Tavis Ormandy and
    Julien Tinnes discovered that this issue could also be
    used by local users to gain elevated privileges.

  - CVE-2009-2846
    Michael Buesch noticed a typing issue in the eisa-eeprom
    driver for the hppa architecture. Local users could
    exploit this issue to gain access to restricted memory.

  - CVE-2009-2847
    Ulrich Drepper noticed an issue in the do_sigalstack
    routine on 64-bit systems. This issue allows local users
    to gain access to potentially sensitive memory on the
    kernel stack.

  - CVE-2009-2848
    Eric Dumazet discovered an issue in the execve path,
    where the clear_child_tid variable was not being
    properly cleared. Local users could exploit this issue
    to cause a denial of service (memory corruption).

  - CVE-2009-2849
    Neil Brown discovered an issue in the sysfs interface to
    md devices. When md arrays are not active, local users
    can exploit this vulnerability to cause a denial of
    service (oops)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1872"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6, fai-kernels, and user-mode-linux packages.

For the oldstable distribution (etch), this problem has been fixed in
version 2.6.18.dfsg.1-24etch4.

Note: Debian carefully tracks all known security issues across every
linux kernel package in all releases under active security support.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, updates for lower priority issues will normally not
be released for all kernels at the same time. Rather, they will be
released in a staggered or 'leap-frog' fashion.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                            Debian 4.0 (etch)         
  fai-kernels               1.17+etch.24etch4         
  user-mode-linux           2.6.18-1um-2etch.24etch4"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
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
if (deb_check(release:"4.0", prefix:"fai-kernels", reference:"1.17+etch.24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.18", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-486", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-686", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-686-bigmem", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-alpha", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-amd64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-arm", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-hppa", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-i386", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-ia64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-mips", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-mipsel", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-powerpc", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-s390", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-sparc", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-generic", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-legacy", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-smp", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-amd64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-footbridge", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-iop32x", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-itanium", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-ixp4xx", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-k7", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-mckinley", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc-smp", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc64-smp", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc-miboot", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc-smp", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-prep", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-qemu", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r3k-kn02", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r4k-ip22", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r4k-kn04", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r5k-cobalt", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r5k-ip32", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-rpc", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s390", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s390x", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s3c2410", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sb1-bcm91250a", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sparc32", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sparc64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sparc64-smp", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-686", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-alpha", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-amd64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-k7", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-powerpc", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-powerpc64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-s390x", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-sparc64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-486", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-686", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-686-bigmem", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-generic", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-legacy", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-smp", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-amd64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-footbridge", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-iop32x", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-itanium", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-ixp4xx", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-k7", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-mckinley", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc-smp", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc64-smp", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc-miboot", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc-smp", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-prep", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-qemu", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r3k-kn02", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r4k-ip22", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r4k-kn04", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r5k-cobalt", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r5k-ip32", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-rpc", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390-tape", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390x", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s3c2410", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sb1-bcm91250a", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sparc32", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sparc64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sparc64-smp", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-686", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-alpha", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-amd64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-k7", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-powerpc", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-powerpc64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-s390x", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-sparc64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.18", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.18", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.18", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.18-6", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.18", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"user-mode-linux", reference:"2.6.18-1um-2etch.24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-24etch4")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-24etch4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
