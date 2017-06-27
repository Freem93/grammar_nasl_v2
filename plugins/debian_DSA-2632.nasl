#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2632. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64881);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2013-0231", "CVE-2013-0871");
  script_bugtraq_id(57740, 57986);
  script_osvdb_id(89903, 90301);
  script_xref(name:"DSA", value:"2632");

  script_name(english:"Debian DSA-2632-1 : linux-2.6 - privilege escalation/denial of service");
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

  - CVE-2013-0231
    Jan Beulich provided a fix for an issue in the Xen PCI
    backend drivers. Users of guests on a system using
    passed-through PCI devices can create a denial of
    service of the host system due to the use of
    non-ratelimited kernel log messages.

  - CVE-2013-0871
    Suleiman Souhlal and Salman Qazi of Google, with help
    from Aaron Durbin and Michael Davidson of Google,
    discovered an issue in the ptrace subsystem. Due to a
    race condition with PTRACE_SETREGS, local users can
    cause kernel stack corruption and execution of arbitrary
    code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/linux-2.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2632"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.6.32-48squeeze1.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                           Debian 6.0 (squeeze)     
  user-mode-linux          2.6.32-1um-4+48squeeze1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"firmware-linux-free", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-base", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-doc-2.6.32", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-486", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-4kc-malta", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-5kc-malta", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686-bigmem", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-amd64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-armel", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-i386", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-ia64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-mips", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-mipsel", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-powerpc", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-s390", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-sparc", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-amd64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-openvz", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-vserver", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-xen", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-iop32x", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-itanium", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-ixp4xx", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-kirkwood", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-mckinley", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-686", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-amd64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-orion5x", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc-smp", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-powerpc64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r4k-ip22", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r5k-cobalt", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-r5k-ip32", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-s390x", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sb1-bcm91250a", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sb1a-bcm91480b", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sparc64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-sparc64-smp", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-versatile", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-amd64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-itanium", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-mckinley", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-powerpc", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-powerpc64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-s390x", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-sparc64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-686", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-486", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-4kc-malta", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-5kc-malta", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem-dbg", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64-dbg", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-iop32x", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-itanium", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-ixp4xx", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-kirkwood", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-mckinley", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686-dbg", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64-dbg", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-orion5x", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc-smp", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-powerpc64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r4k-ip22", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r5k-cobalt", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-r5k-ip32", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-s390x", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-s390x-tape", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sb1-bcm91250a", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sb1a-bcm91480b", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sparc64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-sparc64-smp", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-versatile", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64-dbg", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-itanium", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-mckinley", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-powerpc", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-powerpc64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-s390x", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-sparc64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686-dbg", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64-dbg", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-libc-dev", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-manual-2.6.32", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-patch-debian-2.6.32", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-source-2.6.32", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-support-2.6.32-5", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"linux-tools-2.6.32", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-686", reference:"2.6.32-48squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
