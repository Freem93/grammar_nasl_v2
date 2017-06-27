#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1286. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25153);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-0005", "CVE-2007-0958", "CVE-2007-1357", "CVE-2007-1592");
  script_bugtraq_id(23104);
  script_osvdb_id(33023, 33032, 34365, 34737);
  script_xref(name:"DSA", value:"1286");

  script_name(english:"Debian DSA-1286-1 : linux-2.6 - several vulnerabilities");
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

  - CVE-2007-0005
    Daniel Roethlisberger discovered two buffer overflows in
    the cm4040 driver for the Omnikey CardMan 4040 device. A
    local user or malicious device could exploit this to
    execute arbitrary code in kernel space.

  - CVE-2007-0958
    Santosh Eraniose reported a vulnerability that allows
    local users to read otherwise unreadable files by
    triggering a core dump while using PT_INTERP. This is
    related to CVE-2004-1073.

  - CVE-2007-1357
    Jean Delvare reported a vulnerability in the appletalk
    subsystem. Systems with the appletalk module loaded can
    be triggered to crash by other systems on the local
    network via a malformed frame.

  - CVE-2007-1592
    Masayuki Nakagawa discovered that flow labels were
    inadvertently being shared between listening sockets and
    child sockets. This defect can be exploited by local
    users to cause a DoS (Oops)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1286"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel package immediately and reboot the machine. If you
have built a custom kernel from the kernel source package, you will
need to rebuild to take advantage of these fixes.

This problem has been fixed in the stable distribution in version
2.6.18.dfsg.1-12etch1.

The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update :

                     Debian 4.0 (etch)  
  fai-kernels        1.17etch1          
  user-mode-linux    2.6.18-1um-2etch1  
Updated packages for the mips and mipsel architectures are not yet
available. They will be provided later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/10");
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
if (deb_check(release:"4.0", prefix:"fai-kernels", reference:"1.17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.18", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-486", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-686", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-686-bigmem", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-alpha", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-amd64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-arm", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-hppa", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-i386", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-ia64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-powerpc", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-s390", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-all-sparc", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-alpha-generic", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-alpha-legacy", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-alpha-smp", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-amd64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-footbridge", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-iop32x", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-itanium", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-ixp4xx", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-k7", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-mckinley", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-parisc", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-parisc-smp", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-parisc64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-parisc64-smp", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-powerpc", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-powerpc-miboot", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-powerpc-smp", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-powerpc64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-prep", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-rpc", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-s390", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-s390x", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-s3c2410", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-sparc32", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-sparc64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-sparc64-smp", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-686", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-alpha", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-amd64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-k7", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-powerpc", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-powerpc64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-s390x", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-vserver-sparc64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-xen", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-xen-686", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-xen-amd64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-xen-vserver", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-xen-vserver-686", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-4-xen-vserver-amd64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-486", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-686", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-686-bigmem", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-alpha-generic", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-alpha-legacy", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-alpha-smp", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-amd64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-footbridge", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-iop32x", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-itanium", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-ixp4xx", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-k7", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-mckinley", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-parisc", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-parisc-smp", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-parisc64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-parisc64-smp", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-powerpc", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-powerpc-miboot", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-powerpc-smp", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-powerpc64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-prep", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-rpc", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-s390", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-s390-tape", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-s390x", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-s3c2410", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-sparc32", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-sparc64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-sparc64-smp", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-686", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-alpha", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-amd64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-k7", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-powerpc", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-powerpc64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-s390x", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-vserver-sparc64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-xen-686", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-xen-amd64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-xen-vserver-686", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-4-xen-vserver-amd64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.18", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-4-xen-686", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-4-xen-amd64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-4-xen-vserver-686", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-4-xen-vserver-amd64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.18", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.18", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.18-4", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.18", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"user-mode-linux", reference:"2.6.18-1um-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-4-xen-686", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-4-xen-amd64", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-4-xen-vserver-686", reference:"2.6.18.dfsg.1-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-4-xen-vserver-amd64", reference:"2.6.18.dfsg.1-12etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
