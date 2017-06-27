#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2928. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74027);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2014-0196", "CVE-2014-1737", "CVE-2014-1738");
  script_bugtraq_id(67199, 67300, 67302);
  script_osvdb_id(106646);
  script_xref(name:"DSA", value:"2928");

  script_name(english:"Debian DSA-2928-1 : linux-2.6 - privilege escalation/denial of service/information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service, information leak or privilege
escalation. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2014-0196
    Jiri Slaby discovered a race condition in the pty layer,
    which could lead to a denial of service or privilege
    escalation.

  - CVE-2014-1737 CVE-2014-1738
    Matthew Daley discovered an information leak and missing
    input sanitising in the FDRAWCMD ioctl of the floppy
    driver. This could result in a privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/linux-2.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2928"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 2.6.32-48squeeze6.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                           Debian 6.0 (squeeze)     
  user-mode-linux          2.6.32-1um-4+48squeeze6  
Note: Debian carefully tracks all known security issues across every
linux kernel package in all releases under active security support.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, updates for lower priority issues will normally not
be released for all kernels at the same time. Rather, they will be
released in a staggered or 'leap-frog' fashion."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"firmware-linux-free", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-base", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-doc-2.6.32", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-486", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-4kc-malta", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-5kc-malta", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686-bigmem", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-amd64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-armel", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-i386", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-ia64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-mips", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-mipsel", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-powerpc", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-s390", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-sparc", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-amd64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-openvz", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-vserver", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-xen", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-iop32x", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-itanium", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-ixp4xx", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-kirkwood", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-mckinley", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-686", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-amd64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-orion5x", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc-smp", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r4k-ip22", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r5k-cobalt", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r5k-ip32", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-s390x", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sb1-bcm91250a", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sb1a-bcm91480b", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sparc64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sparc64-smp", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-versatile", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-amd64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-itanium", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-mckinley", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-powerpc", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-powerpc64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-s390x", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-sparc64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-686", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-486", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-4kc-malta", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-5kc-malta", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem-dbg", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64-dbg", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-iop32x", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-itanium", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-ixp4xx", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-kirkwood", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-mckinley", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686-dbg", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64-dbg", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-orion5x", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc-smp", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r4k-ip22", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r5k-cobalt", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r5k-ip32", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-s390x", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-s390x-tape", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sb1-bcm91250a", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sb1a-bcm91480b", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sparc64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sparc64-smp", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-versatile", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64-dbg", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-itanium", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-mckinley", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-powerpc", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-powerpc64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-s390x", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-sparc64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686-dbg", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64-dbg", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-libc-dev", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-manual-2.6.32", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-patch-debian-2.6.32", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-source-2.6.32", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-support-2.6.32-5", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"linux-tools-2.6.32", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-686", reference:"2.6.32-48squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
