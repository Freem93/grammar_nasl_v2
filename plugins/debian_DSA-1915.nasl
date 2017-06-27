#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1915. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44780);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-2695", "CVE-2009-2903", "CVE-2009-2908", "CVE-2009-2909", "CVE-2009-2910", "CVE-2009-3001", "CVE-2009-3002", "CVE-2009-3286", "CVE-2009-3290", "CVE-2009-3613");
  script_bugtraq_id(36379, 36472, 36512, 36576, 36635, 36639, 36706);
  script_xref(name:"DSA", value:"1915");

  script_name(english:"Debian DSA-1915-1 : linux-2.6 - privilege escalation/denial of service/sensitive memory leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Notice: Debian 5.0.4, the next point release of Debian 'lenny', will
include a new default value for the mmap_min_addr tunable. This change
will add an additional safeguard against a class of security
vulnerabilities known as 'NULL pointer dereference' vulnerabilities,
but it will need to be overridden when using certain applications.
Additional information about this change, including instructions for
making this change locally in advance of 5.0.4 (recommended), can be
found at: https://wiki.debian.org/mmap_min_addr.

Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service, sensitive memory leak or privilege
escalation. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2009-2695
    Eric Paris provided several fixes to increase the
    protection provided by the mmap_min_addr tunable against
    NULL pointer dereference vulnerabilities.

  - CVE-2009-2903
    Mark Smith discovered a memory leak in the appletalk
    implementation. When the appletalk and ipddp modules are
    loaded, but no ipddp'N' device is found, remote
    attackers can cause a denial of service by consuming
    large amounts of system memory.

  - CVE-2009-2908
    Loic Minier discovered an issue in the eCryptfs
    filesystem. A local user can cause a denial of service
    (kernel oops) by causing a dentry value to go negative.

  - CVE-2009-2909
    Arjan van de Ven discovered an issue in the AX.25
    protocol implementation. A specially crafted call to
    setsockopt() can result in a denial of service (kernel
    oops).

  - CVE-2009-2910
    Jan Beulich discovered the existence of a sensitive
    kernel memory leak. Systems running the 'amd64' kernel
    do not properly sanitize registers for 32-bit processes.

  - CVE-2009-3001
    Jiri Slaby fixed a sensitive memory leak issue in the
    ANSI/IEEE 802.2 LLC implementation. This is not
    exploitable in the Debian lenny kernel as root
    privileges are required to exploit this issue.

  - CVE-2009-3002
    Eric Dumazet fixed several sensitive memory leaks in the
    IrDA, X.25 PLP (Rose), NET/ROM, Acorn Econet/AUN, and
    Controller Area Network (CAN) implementations. Local
    users can exploit these issues to gain access to kernel
    memory.

  - CVE-2009-3286
    Eric Paris discovered an issue with the NFSv4 server
    implementation. When an O_EXCL create fails, files may
    be left with corrupted permissions, possibly granting
    unintentional privileges to other local users.

  - CVE-2009-3290
    Jan Kiszka noticed that the kvm_emulate_hypercall
    function in KVM does not prevent access to MMU
    hypercalls from ring 0, which allows local guest OS
    users to cause a denial of service (guest kernel crash)
    and read or write guest kernel memory.

  - CVE-2009-3613
    Alistair Strachan reported an issue in the r8169 driver.
    Remote users can cause a denial of service (IOMMU space
    exhaustion and system crash) by transmitting a large
    amount of jumbo frames."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/mmap_min_addr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1915"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the oldstable distribution (etch), these problems, where
applicable, will be fixed in updates to linux-2.6 and linux-2.6.24.

For the stable distribution (lenny), this problem has been fixed in
version 2.6.26-19lenny1.

Note: Debian carefully tracks all known security issues across every
linux kernel package in all releases under active security support.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, updates for lower priority issues will normally not
be released for all kernels at the same time. Rather, they will be
released in a staggered or 'leap-frog' fashion.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                        Debian 5.0 (lenny)     
  user-mode-linux        2.6.26-1um-2+19lenny1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/22");
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
if (deb_check(release:"5.0", prefix:"linux-doc-2.6.26", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-486", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-4kc-malta", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-5kc-malta", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686-bigmem", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-alpha", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-amd64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-arm", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-armel", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-hppa", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-i386", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-ia64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-mips", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-mipsel", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-powerpc", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-s390", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-sparc", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-generic", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-legacy", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-smp", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-amd64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-openvz", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-vserver", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-xen", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-footbridge", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-iop32x", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-itanium", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-ixp4xx", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-mckinley", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-686", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-amd64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-orion5x", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc-smp", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64-smp", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc-smp", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r4k-ip22", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r5k-cobalt", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r5k-ip32", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-s390", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-s390x", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sb1-bcm91250a", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sb1a-bcm91480b", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sparc64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sparc64-smp", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-versatile", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-amd64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-itanium", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-mckinley", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-s390x", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-sparc64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-686", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-amd64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-486", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-4kc-malta", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-5kc-malta", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686-bigmem", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-generic", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-legacy", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-smp", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-amd64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-footbridge", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-iop32x", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-itanium", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-ixp4xx", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-mckinley", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-686", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-amd64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-orion5x", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc-smp", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64-smp", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc-smp", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r4k-ip22", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r5k-cobalt", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r5k-ip32", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390-tape", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-s390x", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sb1-bcm91250a", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sb1a-bcm91480b", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sparc64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sparc64-smp", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-versatile", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-amd64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-itanium", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-mckinley", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-s390x", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-sparc64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-686", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-amd64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-libc-dev", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-manual-2.6.26", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-686", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-amd64", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-patch-debian-2.6.26", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-source-2.6.26", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-support-2.6.26-2", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-tree-2.6.26", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-686", reference:"2.6.26-19lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-amd64", reference:"2.6.26-19lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
