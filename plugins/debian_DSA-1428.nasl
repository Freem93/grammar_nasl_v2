#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1428. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29263);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-3104", "CVE-2007-4997", "CVE-2007-5500", "CVE-2007-5904");
  script_osvdb_id(37115, 39236, 39238, 39246);
  script_xref(name:"DSA", value:"1428");

  script_name(english:"Debian DSA-1428-2 : linux-2.6 - several vulnerabilities");
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

This is an update to DSA 1428-1 which omitted a reference to
CVE-2007-5904.

  - CVE-2007-3104
    Eric Sandeen provided a backport of Tejun Heo's fix for
    a local denial of service vulnerability in sysfs. Under
    memory pressure, a dentry structure maybe reclaimed
    resulting in a bad pointer dereference causing an oops
    during a readdir.

  - CVE-2007-4997
    Chris Evans discovered an issue with certain drivers
    that make use of the Linux kernel's ieee80211 layer. A
    remote user could generate a malicious 802.11 frame that
    could result in a denial of service (crash). The ipw2100
    driver is known to be affected by this issue, while the
    ipw2200 is believed not to be.

  - CVE-2007-5500
    Scott James Remnant diagnosed a coding error in the
    implementation of ptrace which could be used by a local
    user to cause the kernel to enter an infinite loop.

  - CVE-2007-5904
    Przemyslaw Wegrzyn discovered an issue in the CIFS
    filesystem that could allow a malicious server to cause
    a denial of service (crash) by overflowing a buffer.

These problems have been fixed in the stable distribution in version
2.6.18.dfsg.1-13etch5.

The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update :

                           Debian 4.0 (etch)         
  fai-kernels               1.17+etch.13etch5         
  user-mode-linux           2.6.18-1um-2etch.13etch5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1428"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel package immediately and reboot the machine. If you
have built a custom kernel from the kernel source package, you will
need to rebuild to take advantage of these fixes."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/04");
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
if (deb_check(release:"4.0", prefix:"fai-kernels", reference:"1.17+etch.13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.18", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-486", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-686", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-686-bigmem", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-alpha", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-amd64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-arm", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-hppa", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-i386", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-ia64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-mips", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-mipsel", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-powerpc", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-s390", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-all-sparc", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-alpha-generic", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-alpha-legacy", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-alpha-smp", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-amd64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-footbridge", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-iop32x", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-itanium", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-ixp4xx", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-k7", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-mckinley", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-parisc", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-parisc-smp", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-parisc64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-parisc64-smp", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-powerpc", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-powerpc-miboot", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-powerpc-smp", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-powerpc64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-prep", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-qemu", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-r3k-kn02", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-r4k-ip22", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-r4k-kn04", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-r5k-cobalt", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-r5k-ip32", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-rpc", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-s390", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-s390x", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-s3c2410", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-sb1-bcm91250a", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-sparc32", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-sparc64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-sparc64-smp", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-686", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-alpha", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-amd64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-k7", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-powerpc", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-powerpc64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-s390x", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-vserver-sparc64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-xen", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-xen-686", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-xen-amd64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-xen-vserver", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-xen-vserver-686", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-5-xen-vserver-amd64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-486", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-686", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-686-bigmem", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-alpha-generic", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-alpha-legacy", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-alpha-smp", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-amd64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-footbridge", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-iop32x", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-itanium", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-ixp4xx", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-k7", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-mckinley", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-parisc", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-parisc-smp", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-parisc64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-parisc64-smp", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-powerpc", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-powerpc-miboot", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-powerpc-smp", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-powerpc64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-prep", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-qemu", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-r3k-kn02", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-r4k-ip22", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-r4k-kn04", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-r5k-cobalt", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-r5k-ip32", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-rpc", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-s390", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-s390-tape", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-s390x", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-s3c2410", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-sb1-bcm91250a", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-sparc32", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-sparc64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-sparc64-smp", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-686", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-alpha", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-amd64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-k7", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-powerpc", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-powerpc64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-s390x", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-vserver-sparc64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-xen-686", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-xen-amd64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-xen-vserver-686", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-5-xen-vserver-amd64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.18", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-5-xen-686", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-5-xen-amd64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-5-xen-vserver-686", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-5-xen-vserver-amd64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.18", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.18", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.18-5", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.18", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"user-mode-linux", reference:"2.6.18-1um-2etch.13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-5-xen-686", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-5-xen-amd64", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-5-xen-vserver-686", reference:"2.6.18.dfsg.1-13etch5")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-5-xen-vserver-amd64", reference:"2.6.18.dfsg.1-13etch5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
