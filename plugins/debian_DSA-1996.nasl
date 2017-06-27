#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1996. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44860);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-3939", "CVE-2009-4027", "CVE-2009-4536", "CVE-2009-4538", "CVE-2010-0003", "CVE-2010-0007", "CVE-2010-0291", "CVE-2010-0298", "CVE-2010-0306", "CVE-2010-0307", "CVE-2010-0309", "CVE-2010-0410", "CVE-2010-0415");
  script_bugtraq_id(37019, 37170, 37519, 37523, 37724, 37762, 37906, 38027, 38058, 38144);
  script_osvdb_id(61670, 62079);
  script_xref(name:"DSA", value:"1996");

  script_name(english:"Debian DSA-1996-1 : linux-2.6 - privilege escalation/denial of service/sensitive memory leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service, sensitive memory leak or privilege
escalation. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2009-3939
    Joseph Malicki reported that the dbg_lvl sysfs attribute
    for the megaraid_sas device driver had world-writable
    permissions, permitting local users to modify logging
    settings.

  - CVE-2009-4027
    Lennert Buytenhek reported a race in the mac80211
    subsystem that may allow remote users to cause a denial
    of service (system crash) on a system connected to the
    same wireless network.

  - CVE-2009-4536 CVE-2009-4538
    Fabian Yamaguchi reported issues in the e1000 and e1000e
    drivers for Intel gigabit network adapters which allow
    remote users to bypass packet filters using specially
    crafted ethernet frames.

  - CVE-2010-0003
    Andi Kleen reported a defect which allows local users to
    gain read access to memory reachable by the kernel when
    the print-fatal-signals option is enabled. This option
    is disabled by default.

  - CVE-2010-0007
    Florian Westphal reported a lack of capability checking
    in the ebtables netfilter subsystem. If the ebtables
    module is loaded, local users can add and modify
    ebtables rules.

  - CVE-2010-0291
    Al Viro reported several issues with the mmap/mremap
    system calls that allow local users to cause a denial of
    service (system panic) or obtain elevated privileges.

  - CVE-2010-0298 & CVE-2010-0306
    Gleb Natapov discovered issues in the KVM subsystem
    where missing permission checks (CPL/IOPL) permit a user
    in a guest system to denial of service a guest (system
    crash) or gain escalated privileges with the guest.

  - CVE-2010-0307
    Mathias Krause reported an issue with the
    load_elf_binary code on the amd64 flavor kernels that
    allows local users to cause a denial of service (system
    crash).

  - CVE-2010-0309
    Marcelo Tosatti fixed an issue in the PIT emulation code
    in the KVM subsystem that allows privileged users in a
    guest domain to cause a denial of service (crash) of the
    host system.

  - CVE-2010-0410
    Sebastian Krahmer discovered an issue in the netlink
    connector subsystem that permits local users to allocate
    large amounts of system memory resulting in a denial of
    service (out of memory).

  - CVE-2010-0415
    Ramon de Carvalho Valle discovered an issue in the
    sys_move_pages interface, limited to amd64, ia64 and
    powerpc64 flavors in Debian. Local users can exploit
    this issue to cause a denial of service (system crash)
    or gain access to sensitive kernel memory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1996"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the stable distribution (lenny), this problem has been fixed in
version 2.6.26-21lenny3.

For the oldstable distribution (etch), these problems, where
applicable, will be fixed in updates to linux-2.6 and linux-2.6.24.

Note: Debian carefully tracks all known security issues across every
linux kernel package in all releases under active security support.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, updates for lower priority issues will normally not
be released for all kernels at the same time. Rather, they will be
released in a staggered or 'leap-frog' fashion.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                        stable/lenny           
  user-mode-linux        2.6.26-1um-2+21lenny3"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 189, 200, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/12");
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
if (deb_check(release:"5.0", prefix:"linux-doc-2.6.26", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-486", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-4kc-malta", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-5kc-malta", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686-bigmem", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-alpha", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-amd64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-arm", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-armel", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-hppa", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-i386", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-ia64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-mips", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-mipsel", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-powerpc", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-s390", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-sparc", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-generic", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-legacy", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-smp", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-amd64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-openvz", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-vserver", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-xen", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-footbridge", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-iop32x", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-itanium", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-ixp4xx", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-mckinley", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-686", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-amd64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-orion5x", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc-smp", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64-smp", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc-smp", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r4k-ip22", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r5k-cobalt", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r5k-ip32", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-s390", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-s390x", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sb1-bcm91250a", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sb1a-bcm91480b", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sparc64", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sparc64-smp", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-versatile", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-amd64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-itanium", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-mckinley", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-s390x", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-sparc64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-686", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-amd64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-486", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-4kc-malta", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-5kc-malta", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686-bigmem", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-generic", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-legacy", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-smp", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-amd64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-footbridge", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-iop32x", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-itanium", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-ixp4xx", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-mckinley", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-686", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-amd64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-orion5x", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc-smp", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64-smp", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc-smp", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r4k-ip22", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r5k-cobalt", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r5k-ip32", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390-tape", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390x", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sb1-bcm91250a", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sb1a-bcm91480b", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sparc64", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sparc64-smp", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-versatile", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-amd64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-itanium", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-mckinley", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-s390x", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-sparc64", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-686", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-amd64", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-libc-dev", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-manual-2.6.26", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-686", reference:"2.6.26-21lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-amd64", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-patch-debian-2.6.26", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-source-2.6.26", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-support-2.6.26-2", reference:"2.6.26-21lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"linux-tree-2.6.26", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-686", reference:"2.6.26-21lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-amd64", reference:"2.6.26-21lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
