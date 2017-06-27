#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1636. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34171);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-3272", "CVE-2008-3275", "CVE-2008-3276", "CVE-2008-3526", "CVE-2008-3534", "CVE-2008-3535", "CVE-2008-3792", "CVE-2008-3915");
  script_osvdb_id(47788, 48433, 48470, 48570, 48571);
  script_xref(name:"DSA", value:"1636");

  script_name(english:"Debian DSA-1636-1 : linux-2.6.24 - denial of service/information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service or leak sensitive data. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2008-3272
    Tobias Klein reported a locally exploitable data leak in
    the snd_seq_oss_synth_make_info() function. This may
    allow local users to gain access to sensitive
    information.

  - CVE-2008-3275
    Zoltan Sogor discovered a coding error in the VFS that
    allows local users to exploit a kernel memory leak
    resulting in a denial of service.

  - CVE-2008-3276
    Eugene Teo reported an integer overflow in the DCCP
    subsystem that may allow remote attackers to cause a
    denial of service in the form of a kernel panic.

  - CVE-2008-3526
    Eugene Teo reported a missing bounds check in the SCTP
    subsystem. By exploiting an integer overflow in the
    SCTP_AUTH_KEY handling code, remote attackers may be
    able to cause a denial of service in the form of a
    kernel panic.

  - CVE-2008-3534
    Kel Modderman reported an issue in the tmpfs filesystem
    that allows local users to crash a system by triggering
    a kernel BUG() assertion.

  - CVE-2008-3535
    Alexey Dobriyan discovered an off-by-one-error in the
    iov_iter_advance function which can be exploited by
    local users to crash a system, resulting in a denial of
    service.

  - CVE-2008-3792
    Vlad Yasevich reported several NULL pointer reference
    conditions in the SCTP subsystem that can be triggered
    by entering sctp-auth codepaths when the AUTH feature is
    inactive. This may allow attackers to cause a denial of
    service condition via a system panic.

  - CVE-2008-3915
    Johann Dahm and David Richter reported an issue in the
    nfsd subsystem that may allow remote attackers to cause
    a denial of service via a buffer overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1636"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6.24 packages.

For the stable distribution (etch), these problems have been fixed in
version 2.6.24-6~etchnhalf.5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6.24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.24", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-486", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-4kc-malta", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-5kc-malta", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-686", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-686-bigmem", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-alpha", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-amd64", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-arm", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-hppa", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-i386", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-ia64", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-mips", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-mipsel", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-powerpc", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-s390", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-sparc", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-generic", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-legacy", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-smp", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-amd64", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-common", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-footbridge", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-iop32x", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-itanium", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-ixp4xx", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-mckinley", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc-smp", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc64", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc64-smp", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc-miboot", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc-smp", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc64", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-r4k-ip22", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-r5k-cobalt", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-r5k-ip32", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-s390", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-s390x", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sb1-bcm91250a", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sb1a-bcm91480b", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sparc64", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sparc64-smp", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-486", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-4kc-malta", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-5kc-malta", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-686", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-686-bigmem", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-generic", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-legacy", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-smp", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-amd64", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-footbridge", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-iop32x", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-itanium", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-ixp4xx", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-mckinley", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc-smp", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc64", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc64-smp", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc-miboot", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc-smp", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc64", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-r4k-ip22", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-r5k-cobalt", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-r5k-ip32", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-s390", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-s390-tape", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-s390x", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sb1-bcm91250a", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sb1a-bcm91480b", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sparc64", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sparc64-smp", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.24", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.24", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.24", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.24-etchnhalf.1", reference:"2.6.24-6~etchnhalf.5")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.24", reference:"2.6.24-6~etchnhalf.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
