#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1928. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44793);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-2846", "CVE-2009-2847", "CVE-2009-2848", "CVE-2009-2849", "CVE-2009-2903", "CVE-2009-2908", "CVE-2009-2909", "CVE-2009-2910", "CVE-2009-3001", "CVE-2009-3002", "CVE-2009-3228", "CVE-2009-3238", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3612", "CVE-2009-3613", "CVE-2009-3620", "CVE-2009-3621");
  script_bugtraq_id(35930, 36004, 36176, 36304, 36379, 36472, 36576, 36635, 36639, 36706, 36723, 36788, 36824, 36827, 36901);
  script_xref(name:"DSA", value:"1928");

  script_name(english:"Debian DSA-1928-1 : linux-2.6.24 - privilege escalation/denial of service/sensitive memory leak");
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

  - CVE-2009-2846
    Michael Buesch noticed a typing issue in the eisa-eeprom
    driver for the hppa architecture. Local users could
    exploit this issue to gain access to restricted memory.

  - CVE-2009-2847
    Ulrich Drepper noticed an issue in the do_sigalstack
    routine on 64-bit systems. This issue allows local users
    to gain access to potentially sensitive memory on the
    kernel stack.

  - CVE-2009-2848
    Eric Dumazet discovered an issue in the execve path,
    where the clear_child_tid variable was not being
    properly cleared. Local users could exploit this issue
    to cause a denial of service (memory corruption).

  - CVE-2009-2849
    Neil Brown discovered an issue in the sysfs interface to
    md devices. When md arrays are not active, local users
    can exploit this vulnerability to cause a denial of
    service (oops).

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

  - CVE-2009-3228
    Eric Dumazet reported an instance of uninitialized
    kernel memory in the network packet scheduler. Local
    users may be able to exploit this issue to read the
    contents of sensitive kernel memory.

  - CVE-2009-3238
    Linus Torvalds provided a change to the get_random_int()
    function to increase its randomness.

  - CVE-2009-3286
    Eric Paris discovered an issue with the NFSv4 server
    implementation. When an O_EXCL create fails, files may
    be left with corrupted permissions, possibly granting
    unintentional privileges to other local users.

  - CVE-2009-3547
    Earl Chew discovered a NULL pointer dereference issue in
    the pipe_rdwr_open function which can be used by local
    users to gain elevated privileges.

  - CVE-2009-3612
    Jiri Pirko discovered a typo in the initialization of a
    structure in the netlink subsystem that may allow local
    users to gain access to sensitive kernel memory.

  - CVE-2009-3613
    Alistair Strachan reported an issue in the r8169 driver.
    Remote users can cause a denial of service (IOMMU space
    exhaustion and system crash) by transmitting a large
    amount of jumbo frames.

  - CVE-2009-3620
    Ben Hutchings discovered an issue in the DRM manager for
    ATI Rage 128 graphics adapters. Local users may be able
    to exploit this vulnerability to cause a denial of
    service (NULL pointer dereference).

  - CVE-2009-3621
    Tomoki Sekiyama discovered a deadlock condition in the
    UNIX domain socket implementation. Local users can
    exploit this vulnerability to cause a denial of service
    (system hang)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2849"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3286"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3613"
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
    value:"http://www.debian.org/security/2009/dsa-1928"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6.24 packages.

For the oldstable distribution (etch), this problem has been fixed in
version 2.6.24-6~etchnhalf.9etch1.

Note: Debian 'etch' includes linux kernel packages based upon both the
2.6.18 and 2.6.24 linux releases. All known security issues are
carefully tracked against both packages and both packages will receive
security updates until security support for Debian 'etch' concludes.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, lower severity 2.6.18 and 2.6.24 updates will
typically release in a staggered or 'leap-frog' fashion."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 189, 200, 264, 310, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6.24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

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
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.24", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-486", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-4kc-malta", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-5kc-malta", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-686", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-686-bigmem", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-alpha", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-amd64", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-hppa", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-i386", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-ia64", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-mipsel", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-generic", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-legacy", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-smp", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-amd64", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-common", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-itanium", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-mckinley", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc-smp", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc64", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc64-smp", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-r5k-cobalt", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sb1-bcm91250a", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sb1a-bcm91480b", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-486", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-4kc-malta", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-5kc-malta", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-686", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-686-bigmem", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-generic", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-legacy", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-smp", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-amd64", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-itanium", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-mckinley", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc-smp", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc64", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc64-smp", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-r5k-cobalt", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sb1-bcm91250a", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sb1a-bcm91480b", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.24", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.24", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.24", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.24-etchnhalf.1", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.24", reference:"2.6.24-6~etchnhalf.9etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
