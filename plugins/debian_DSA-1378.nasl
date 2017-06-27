#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1378. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26208);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-3731", "CVE-2007-3739", "CVE-2007-3740", "CVE-2007-4573");
  script_osvdb_id(37285, 37286, 37287, 40564, 40597);
  script_xref(name:"DSA", value:"1378");

  script_name(english:"Debian DSA-1378-2 : linux-2.6 - several vulnerabilities");
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

  - CVE-2007-3731
    Evan Teran discovered a potential local denial of
    service (oops) in the handling of PTRACE_SETREGS and
    PTRACE_SINGLESTEP requests.

  - CVE-2007-3739
    Adam Litke reported a potential local denial of service
    (oops) on powerpc platforms resulting from unchecked VMA
    expansion into address space reserved for hugetlb pages.

  - CVE-2007-3740
    Matt Keenan reported that CIFS filesystems with CAP_UNIX
    enabled were not honoring a process' umask which may
    lead to unintentionally relaxed permissions.

  - CVE-2007-4573
    Wojciech Purczynski discovered a vulnerability that can
    be exploited by a local user to obtain superuser
    privileges on x86_64 systems. This resulted from
    improper clearing of the high bits of registers during
    ia32 system call emulation. This vulnerability is
    relevant to the Debian amd64 port as well as users of
    the i386 port who run the amd64 linux-image flavour.

  - CVE-2007-4849
    Michael Stone reported an issue with the JFFS2
    filesystem. Legacy modes for inodes that were created
    with POSIX ACL support enabled were not being written
    out to the medium, resulting in incorrect permissions
    upon remount.

These problems have been fixed in the stable distribution in version
2.6.18.dfsg.1-13etch3.

This advisory has been updated to include a build for the arm
architecture, which was not yet available at the time of DSA-1378-1.

The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update :

                           Debian 4.0 (etch)         
  fai-kernels               1.17+etch.13etch3         
  user-mode-linux           2.6.18-1um-2etch.13etch3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1378"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel package immediately and reboot the machine. If you
have built a custom kernel from the kernel source package, you will
need to rebuild to take advantage of these fixes."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"fai-kernels", reference:"1.17+etch.13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.18", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-486", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-686", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-686-bigmem", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-alpha", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-amd64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-arm", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-hppa", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-i386", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-ia64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-mips", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-mipsel", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-powerpc", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-s390", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-sparc", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-alpha-generic", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-alpha-legacy", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-alpha-smp", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-amd64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-footbridge", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-iop32x", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-itanium", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-ixp4xx", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-k7", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-mckinley", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-parisc", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-parisc-smp", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-parisc64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-parisc64-smp", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-powerpc", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-powerpc-miboot", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-powerpc-smp", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-powerpc64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-prep", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-qemu", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-r3k-kn02", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-r4k-ip22", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-r4k-kn04", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-r5k-cobalt", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-r5k-ip32", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-rpc", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-s390", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-s390x", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-s3c2410", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-sb1-bcm91250a", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-sparc32", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-sparc64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-sparc64-smp", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-686", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-alpha", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-amd64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-k7", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-powerpc", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-powerpc64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-s390x", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-sparc64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-xen", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-xen-686", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-xen-amd64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-xen-vserver", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-xen-vserver-686", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-xen-vserver-amd64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-486", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-686", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-686-bigmem", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-alpha-generic", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-alpha-legacy", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-alpha-smp", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-amd64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-footbridge", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-iop32x", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-itanium", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-ixp4xx", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-k7", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-mckinley", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-parisc", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-parisc-smp", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-parisc64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-parisc64-smp", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-powerpc", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-powerpc-miboot", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-powerpc-smp", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-powerpc64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-prep", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-qemu", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-r3k-kn02", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-r4k-ip22", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-r4k-kn04", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-r5k-cobalt", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-r5k-ip32", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-rpc", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-s390", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-s390-tape", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-s390x", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-s3c2410", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-sb1-bcm91250a", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-sparc32", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-sparc64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-sparc64-smp", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-686", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-alpha", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-amd64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-k7", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-powerpc", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-powerpc64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-s390x", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-sparc64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-xen-686", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-xen-amd64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-xen-vserver-686", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-xen-vserver-amd64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.18", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-5-xen-686", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-5-xen-amd64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-5-xen-vserver-686", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-5-xen-vserver-amd64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.18", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.18", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.18-5", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.18", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"user-mode-linux", reference:"2.6.18-1um-2etch.13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-5-xen-686", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-5-xen-amd64", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-5-xen-vserver-686", reference:"2.6.18.dfsg.1-13etch3")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-5-xen-vserver-amd64", reference:"2.6.18.dfsg.1-13etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
