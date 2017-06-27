#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1494. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31028);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2008-0010", "CVE-2008-0163", "CVE-2008-0600");
  script_osvdb_id(43220);
  script_xref(name:"DSA", value:"1494");

  script_name(english:"Debian DSA-1494-2 : linux-2.6 - missing access checks");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The vmsplice system call did not properly verify address arguments
passed by user space processes, which allowed local attackers to
overwrite arbitrary kernel memory, gaining root privileges
(CVE-2008-0010, CVE-2008-0600 ).

In the vserver-enabled kernels, a missing access check on certain
symlinks in /proc enabled local attackers to access resources in other
vservers (CVE-2008-0163 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1494"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6, fai-kernels, and user-mode-linux packages.

The old stable distribution (sarge) is not affected by this problem.

For the stable distribution (etch), this problem has been fixed in
version 2.6.18.dfsg.1-18etch1.

In addition to these fixes, this update also incorporates changes from
the upcoming point release of the stable distribution.

Some architecture builds were not yet available at the time of
DSA-1494-1. This update to DSA-1494 provides linux-2.6 packages for
these remaining architectures, as well as additional binary packages
that are built from source code provided by linux-2.6."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 59, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"fai-kernels", reference:"1.17+etch.18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.18", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-486", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-686", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-686-bigmem", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-alpha", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-amd64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-arm", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-hppa", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-i386", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-ia64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-mips", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-mipsel", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-powerpc", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-s390", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-sparc", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-generic", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-legacy", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-smp", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-amd64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-footbridge", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-iop32x", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-itanium", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-ixp4xx", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-k7", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-mckinley", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc-smp", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc64-smp", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc-miboot", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc-smp", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-prep", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-qemu", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r3k-kn02", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r4k-ip22", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r4k-kn04", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r5k-cobalt", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r5k-ip32", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-rpc", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s390", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s390x", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s3c2410", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sb1-bcm91250a", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sparc32", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sparc64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sparc64-smp", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-686", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-alpha", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-amd64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-k7", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-powerpc", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-powerpc64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-s390x", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-sparc64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-486", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-686", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-686-bigmem", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-generic", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-legacy", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-smp", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-amd64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-footbridge", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-iop32x", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-itanium", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-ixp4xx", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-k7", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-mckinley", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc-smp", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc64-smp", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc-miboot", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc-smp", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-prep", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-qemu", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r3k-kn02", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r4k-ip22", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r4k-kn04", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r5k-cobalt", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r5k-ip32", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-rpc", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390-tape", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390x", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s3c2410", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sb1-bcm91250a", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sparc32", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sparc64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sparc64-smp", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-686", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-alpha", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-amd64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-k7", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-powerpc", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-powerpc64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-s390x", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-sparc64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.18", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.18", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.18", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.18-6", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.18", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"user-mode-linux", reference:"2.6.18-1um-2etch.18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-18etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-18etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
