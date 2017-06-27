#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1809. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38990);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-1630", "CVE-2009-1633", "CVE-2009-1758");
  script_xref(name:"DSA", value:"1809");

  script_name(english:"Debian DSA-1809-1 : linux-2.6 - denial of service, privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service, or privilege escalation. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2009-1630
    Frank Filz discovered that local users may be able to
    execute files without execute permission when accessed
    via an nfs4 mount.

  - CVE-2009-1633
    Jeff Layton and Suresh Jayaraman fixed several buffer
    overflows in the CIFS filesystem which allow remote
    servers to cause memory corruption.

  - CVE-2009-1758
    Jan Beulich discovered an issue in Xen where local guest
    users may cause a denial of service (oops).

This update also fixes a regression introduced by the fix for
CVE-2009-1184 in 2.6.26-15lenny3. This prevents a boot time panic on
systems with SELinux enabled."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1809"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the oldstable distribution (etch), these problems, where
applicable, will be fixed in future updates to linux-2.6 and
linux-2.6.24.

For the stable distribution (lenny), these problems have been fixed in
version 2.6.26-15lenny3.

Note: Debian carefully tracks all known security issues across every
linux kernel package in all releases under active security support.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, updates for lower priority issues will normally not
be released for all kernels at the same time. Rather, they will be
released in a staggered or 'leap-frog' fashion."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(119, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/03");
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
if (deb_check(release:"5.0", prefix:"linux-doc-2.6.26", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-486", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-4kc-malta", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-5kc-malta", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686-bigmem", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-alpha", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-amd64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-arm", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-armel", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-hppa", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-i386", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-ia64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-mips", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-mipsel", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-powerpc", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-s390", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-sparc", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-generic", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-legacy", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-smp", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-amd64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-openvz", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-vserver", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-xen", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-footbridge", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-iop32x", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-itanium", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-ixp4xx", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-mckinley", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-686", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-amd64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-orion5x", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc-smp", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64-smp", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc-smp", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r4k-ip22", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r5k-cobalt", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r5k-ip32", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-s390", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-s390x", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sb1-bcm91250a", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sb1a-bcm91480b", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sparc64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sparc64-smp", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-versatile", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-amd64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-itanium", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-mckinley", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-s390x", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-sparc64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-686", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-amd64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-486", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-4kc-malta", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-5kc-malta", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686-bigmem", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-generic", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-legacy", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-smp", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-amd64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-footbridge", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-iop32x", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-itanium", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-ixp4xx", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-mckinley", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-686", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-amd64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-orion5x", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc-smp", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64-smp", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc-smp", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r4k-ip22", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r5k-cobalt", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r5k-ip32", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390-tape", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390x", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sb1-bcm91250a", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sb1a-bcm91480b", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sparc64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sparc64-smp", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-versatile", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-amd64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-itanium", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-mckinley", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-s390x", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-sparc64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-686", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-amd64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-libc-dev", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-manual-2.6.26", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-686", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-amd64", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-patch-debian-2.6.26", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-source-2.6.26", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-support-2.6.26-2", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-tree-2.6.26", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"user-mode-linux", reference:"2.6.26-1um-2+15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-686", reference:"2.6.26-15lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-amd64", reference:"2.6.26-15lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
