#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2926. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73971);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2014-0196", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2851", "CVE-2014-3122");
  script_bugtraq_id(66779, 67162, 67282, 67300, 67302);
  script_osvdb_id(106527, 106646);
  script_xref(name:"DSA", value:"2926");

  script_name(english:"Debian DSA-2926-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service, information leaks or privilege
escalation :

  - CVE-2014-0196
    Jiri Slaby discovered a race condition in the pty layer,
    which could lead to denial of service or privilege
    escalation.

  - CVE-2014-1737 / CVE-2014-1738
    Matthew Daley discovered that missing input sanitising
    in the FDRAWCMD ioctl and an information leak could
    result in privilege escalation.

  - CVE-2014-2851
    Incorrect reference counting in the ping_init_sock()
    function allows denial of service or privilege
    escalation.

  - CVE-2014-3122
    Incorrect locking of memory can result in local denial
    of service."
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
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2926"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (wheezy), these problems have been fixed
in version 3.2.57-3+deb7u1. This update also fixes a regression in the
isci driver and suspend problems with certain AMD CPUs (introduced in
the updated kernel from the Wheezy 7.5 point release)."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/13");
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
if (deb_check(release:"7.0", prefix:"linux-doc-3.2", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-486", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-4kc-malta", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-5kc-malta", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-686-pae", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-amd64", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-armel", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-armhf", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-i386", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-ia64", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-mips", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-mipsel", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-powerpc", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-s390", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-s390x", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-sparc", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-amd64", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-common", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-common-rt", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-iop32x", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-itanium", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-ixp4xx", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-kirkwood", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-loongson-2f", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-mckinley", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-mv78xx0", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-mx5", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-octeon", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-omap", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-orion5x", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-powerpc", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-powerpc-smp", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-powerpc64", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-r4k-ip22", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-r5k-cobalt", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-r5k-ip32", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-rt-686-pae", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-rt-amd64", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-s390x", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-sb1-bcm91250a", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-sb1a-bcm91480b", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-sparc64", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-sparc64-smp", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-versatile", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-vexpress", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-486", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-4kc-malta", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-5kc-malta", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-686-pae", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-686-pae-dbg", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-amd64", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-amd64-dbg", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-iop32x", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-itanium", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-ixp4xx", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-kirkwood", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-loongson-2f", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-mckinley", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-mv78xx0", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-mx5", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-octeon", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-omap", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-orion5x", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-powerpc", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-powerpc-smp", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-powerpc64", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-r4k-ip22", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-r5k-cobalt", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-r5k-ip32", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-rt-686-pae", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-rt-686-pae-dbg", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-rt-amd64", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-rt-amd64-dbg", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-s390x", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-s390x-dbg", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-s390x-tape", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-sb1-bcm91250a", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-sb1a-bcm91480b", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-sparc64", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-sparc64-smp", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-versatile", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-vexpress", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-libc-dev", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-manual-3.2", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-source-3.2", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-support-3.2.0-4", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-linux-system-3.2.0-4-686-pae", reference:"3.2.57-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-linux-system-3.2.0-4-amd64", reference:"3.2.57-3+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
