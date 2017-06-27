#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1289. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25226);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1861");
  script_osvdb_id(33027, 33028, 34741);
  script_xref(name:"DSA", value:"1289");

  script_name(english:"Debian DSA-1289-1 : linux-2.6 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local and remote vulnerabilities have been discovered in the
Linux kernel that may lead to a denial of service or the execution of
arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2007-1496
    Michal Miroslaw reported a DoS vulnerability (crash) in
    netfilter. A remote attacker can cause a NULL pointer
    dereference in the nfnetlink_log function.

  - CVE-2007-1497
    Patrick McHardy reported an vulnerability in netfilter
    that may allow attackers to bypass certain firewall
    rules. The nfctinfo value of reassembled IPv6 packet
    fragments were incorrectly initialized to 0 which
    allowed these packets to become tracked as ESTABLISHED.

  - CVE-2007-1861
    Jaco Kroon reported a bug in which NETLINK_FIB_LOOKUP
    packages were incorrectly routed back to the kernel
    resulting in an infinite recursion condition. Local
    users can exploit this behavior to cause a DoS (crash)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1289"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel package immediately and reboot the machine. If you
have built a custom kernel from the kernel source package, you will
need to rebuild to take advantage of these fixes.

For the stable distribution (etch) these problems have been fixed in
version 2.6.18.dfsg.1-12etch2.

The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update :

                       Debian 4.0 (etch)    
  fai-kernels          1.17+etch2           
  user-mode-linux      2.6.18-1um-2etch2    
  kernel-patch-openvz  028.18.1etch1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"fai-kernels", reference:"1.17+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-patch-openvz", reference:"028.18.1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.18", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-486", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-686", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-686-bigmem", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-alpha", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-amd64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-arm", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-hppa", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-i386", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-ia64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-mips", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-mipsel", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-powerpc", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-s390", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-sparc", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-alpha-generic", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-alpha-legacy", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-alpha-smp", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-amd64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-footbridge", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-iop32x", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-itanium", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-ixp4xx", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-k7", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-mckinley", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-parisc", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-parisc-smp", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-parisc64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-parisc64-smp", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-powerpc", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-powerpc-miboot", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-powerpc-smp", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-powerpc64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-prep", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-qemu", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-r3k-kn02", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-r4k-ip22", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-r4k-kn04", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-r5k-cobalt", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-r5k-ip32", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-rpc", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-s390", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-s390x", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-s3c2410", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-sb1-bcm91250a", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-sparc32", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-sparc64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-sparc64-smp", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-686", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-alpha", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-amd64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-k7", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-powerpc", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-powerpc64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-s390x", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-sparc64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-xen", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-xen-686", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-xen-amd64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-xen-vserver", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-xen-vserver-686", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-xen-vserver-amd64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-486", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-686", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-686-bigmem", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-alpha-generic", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-alpha-legacy", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-alpha-smp", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-amd64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-footbridge", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-iop32x", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-itanium", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-ixp4xx", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-k7", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-mckinley", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-parisc", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-parisc-smp", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-parisc64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-parisc64-smp", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-powerpc", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-powerpc-miboot", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-powerpc-smp", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-powerpc64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-prep", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-qemu", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-r3k-kn02", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-r4k-ip22", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-r4k-kn04", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-r5k-cobalt", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-r5k-ip32", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-rpc", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-s390", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-s390-tape", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-s390x", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-s3c2410", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-sb1-bcm91250a", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-sparc32", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-sparc64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-sparc64-smp", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-686", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-alpha", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-amd64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-k7", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-powerpc", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-powerpc64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-s390x", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-sparc64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-xen-686", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-xen-amd64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-xen-vserver-686", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-xen-vserver-amd64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.18", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-4-xen-686", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-4-xen-amd64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-4-xen-vserver-686", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-4-xen-vserver-amd64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.18", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.18", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.18-4", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.18", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"user-mode-linux", reference:"2.6.18-1um-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-4-xen-686", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-4-xen-amd64", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-4-xen-vserver-686", reference:"2.6.18.dfsg.1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-4-xen-vserver-amd64", reference:"2.6.18.dfsg.1-12etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
