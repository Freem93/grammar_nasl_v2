#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2110. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49276);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2010-2492", "CVE-2010-2954", "CVE-2010-3078", "CVE-2010-3080", "CVE-2010-3081");
  script_bugtraq_id(42237, 42900, 43022, 43062, 43239);
  script_xref(name:"DSA", value:"2110");

  script_name(english:"Debian DSA-2110-1 : linux-2.6 - privilege escalation/denial of service/information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leak. The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2010-2492
    Andre Osterhues reported an issue in the eCryptfs
    subsystem. A buffer overflow condition may allow local
    users to cause a denial of service or gain elevated
    privileges.

  - CVE-2010-2954
    Tavis Ormandy reported an issue in the irda subsystem
    which may allow local users to cause a denial of service
    via a NULL pointer dereference.

  - CVE-2010-3078
    Dan Rosenberg discovered an issue in the XFS file system
    that allows local users to read potentially sensitive
    kernel memory.

  - CVE-2010-3080
    Tavis Ormandy reported an issue in the ALSA sequencer
    OSS emulation layer. Local users with sufficient
    privileges to open /dev/sequencer (by default on Debian,
    this is members of the 'audio' group) can cause a denial
    of service via a NULL pointer dereference.

  - CVE-2010-3081
    Ben Hawkes discovered an issue in the 32-bit
    compatibility code for 64-bit systems. Local users can
    gain elevated privileges due to insufficient checks in
    compat_alloc_user_space allocations."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2110"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the stable distribution (lenny), this problem has been fixed in
version 2.6.26-25lenny1.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                         Debian 5.0 (lenny)     
  user-mode-linux        2.6.26-1um-2+25lenny1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/20");
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
if (deb_check(release:"5.0", prefix:"linux-doc-2.6.26", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-486", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-4kc-malta", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-5kc-malta", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-686-bigmem", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-alpha", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-amd64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-armel", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-hppa", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-i386", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-ia64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-mipsel", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-powerpc", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-all-sparc", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-generic", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-legacy", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-alpha-smp", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-amd64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-openvz", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-vserver", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-common-xen", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-iop32x", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-itanium", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-ixp4xx", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-mckinley", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-686", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-openvz-amd64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-orion5x", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc-smp", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-parisc64-smp", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc-smp", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-powerpc64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-r5k-cobalt", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sb1-bcm91250a", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sb1a-bcm91480b", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sparc64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-sparc64-smp", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-versatile", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-amd64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-itanium", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-mckinley", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-powerpc64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-vserver-sparc64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-686", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-headers-2.6.26-2-xen-amd64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-486", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-4kc-malta", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-5kc-malta", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-686-bigmem", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-generic", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-legacy", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-alpha-smp", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-amd64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-iop32x", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-itanium", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-ixp4xx", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-mckinley", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-686", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-openvz-amd64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-orion5x", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc-smp", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-parisc64-smp", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc-smp", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-powerpc64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-r5k-cobalt", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sb1-bcm91250a", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sb1a-bcm91480b", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sparc64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-sparc64-smp", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-versatile", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-686-bigmem", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-amd64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-itanium", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-mckinley", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-powerpc64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-vserver-sparc64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-686", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-image-2.6.26-2-xen-amd64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-libc-dev", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-manual-2.6.26", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-686", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-modules-2.6.26-2-xen-amd64", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-patch-debian-2.6.26", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-source-2.6.26", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-support-2.6.26-2", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-tree-2.6.26", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-686", reference:"2.6.26-25lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xen-linux-system-2.6.26-2-xen-amd64", reference:"2.6.26-25lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
