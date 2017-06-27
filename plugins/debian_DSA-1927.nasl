#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1927. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44792);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-3228", "CVE-2009-3238", "CVE-2009-3547", "CVE-2009-3612", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3638");
  script_bugtraq_id(36304, 36723, 36788, 36803, 36824, 36827, 36901);
  script_osvdb_id(57821, 58234, 59070, 59210, 59211, 59222, 59475, 59654);
  script_xref(name:"DSA", value:"1927");

  script_name(english:"Debian DSA-1927-1 : linux-2.6 - privilege escalation/denial of service/sensitive memory leak");
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

  - CVE-2009-3228
    Eric Dumazet reported an instance of uninitialized
    kernel memory in the network packet scheduler. Local
    users may be able to exploit this issue to read the
    contents of sensitive kernel memory.

  - CVE-2009-3238
    Linus Torvalds provided a change to the get_random_int()
    function to increase its randomness.

  - CVE-2009-3547
    Earl Chew discovered a NULL pointer dereference issue in
    the pipe_rdwr_open function which can be used by local
    users to gain elevated privileges.

  - CVE-2009-3612
    Jiri Pirko discovered a typo in the initialization of a
    structure in the netlink subsystem that may allow local
    users to gain access to sensitive kernel memory.

  - CVE-2009-3620
    Ben Hutchings discovered an issue in the DRM manager for
    ATI Rage 128 graphics adapters. Local users may be able
    to exploit this vulnerability to cause a denial of
    service (NULL pointer dereference).

  - CVE-2009-3621
    Tomoki Sekiyama discovered a deadlock condition in the
    UNIX domain socket implementation. Local users can
    exploit this vulnerability to cause a denial of service
    (system hang).

  - CVE-2009-3638
    David Wagner reported an overflow in the KVM subsystem
    on i386 systems. This issue is exploitable by local
    users with access to the /dev/kvm device file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/mmap_min_addr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1927"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the stable distribution (lenny), this problem has been fixed in
version 2.6.26-19lenny2.

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

                        Debian 5.0 (lenny)     
  user-mode-linux        2.6.26-1um-2+19lenny2"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 189, 200, 310, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/05");
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
if (deb_check(release:"5.0", prefix:"linux-doc-2.6.26", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-486", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686-bigmem", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-alpha", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-amd64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-armel", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-hppa", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-i386", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-ia64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-powerpc", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-generic", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-legacy", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-smp", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-amd64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-openvz", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-vserver", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-xen", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-iop32x", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-itanium", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-ixp4xx", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-mckinley", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-686", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-amd64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-orion5x", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc-smp", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64-smp", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc-smp", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-versatile", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-amd64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-itanium", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-mckinley", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-686", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-amd64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-486", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686-bigmem", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-generic", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-legacy", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-smp", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-amd64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-iop32x", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-itanium", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-ixp4xx", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-mckinley", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-686", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-amd64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-orion5x", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc-smp", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64-smp", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc-smp", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-versatile", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-amd64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-itanium", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-mckinley", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-686", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-amd64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-libc-dev", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-manual-2.6.26", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-686", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-amd64", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-patch-debian-2.6.26", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-source-2.6.26", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-support-2.6.26-2", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-tree-2.6.26", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-686", reference:"2.6.26-19lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-amd64", reference:"2.6.26-19lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
