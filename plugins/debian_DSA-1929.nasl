#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1929. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44794);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-1883", "CVE-2009-2909", "CVE-2009-3001", "CVE-2009-3002", "CVE-2009-3228", "CVE-2009-3238", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3612", "CVE-2009-3621");
  script_bugtraq_id(36176, 36304, 36472, 36635, 36723, 36788, 36827, 36901);
  script_osvdb_id(57427, 57428, 57821, 58234, 58235, 58323, 59070, 59081, 59210, 59222, 59654);
  script_xref(name:"DSA", value:"1929");

  script_name(english:"Debian DSA-1929-1 : linux-2.6 - privilege escalation/denial of service/sensitive memory leak");
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

  - CVE-2009-1883
    Solar Designer discovered a missing capability check in
    the z90crypt driver or s390 systems. This vulnerability
    may allow a local user to gain elevated privileges.

  - CVE-2009-2909
    Arjan van de Ven discovered an issue in the AX.25
    protocol implementation. A specially crafted call to
    setsockopt() can result in a denial of service (kernel
    oops).

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

  - CVE-2009-3621
    Tomoki Sekiyama discovered a deadlock condition in the
    UNIX domain socket implementation. Local users can
    exploit this vulnerability to cause a denial of service
    (system hang)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2909"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1929"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6, fai-kernels, and user-mode-linux packages.

For the oldstable distribution (etch), this problem has been fixed in
version 2.6.18.dfsg.1-26etch1.

Note: Debian 'etch' includes linux kernel packages based upon both the
2.6.18 and 2.6.24 linux releases. All known security issues are
carefully tracked against both packages and both packages will receive
security updates until security support for Debian 'etch' concludes.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, lower severity 2.6.18 and 2.6.24 updates will
typically release in a staggered or 'leap-frog' fashion.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                           Debian 4.0 (etch)         
  fai-kernels               1.17+etch.26etch1         
  user-mode-linux           2.6.18-1um-2etch.26etch1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(189, 200, 264, 310, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
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
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.18", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-486", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-686", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-686-bigmem", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-alpha", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-amd64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-hppa", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-i386", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-ia64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-powerpc", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-s390", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-generic", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-legacy", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-smp", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-amd64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-itanium", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-k7", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-mckinley", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc-smp", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc64-smp", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc-miboot", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc-smp", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-prep", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s390", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s390x", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-686", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-alpha", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-amd64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-k7", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-powerpc", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-powerpc64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-s390x", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-486", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-686", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-686-bigmem", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-generic", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-legacy", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-smp", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-amd64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-itanium", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-k7", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-mckinley", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc-smp", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc64-smp", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc-miboot", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc-smp", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-prep", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390-tape", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390x", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-686", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-alpha", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-amd64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-k7", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-powerpc", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-powerpc64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-s390x", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.18", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.18", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.18", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.18-6", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.18", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-26etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-26etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
