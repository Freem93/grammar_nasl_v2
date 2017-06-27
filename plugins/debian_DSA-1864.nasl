#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1864. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44729);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/19 17:45:43 $");

  script_cve_id("CVE-2009-2692");
  script_bugtraq_id(36038);
  script_xref(name:"DSA", value:"1864");

  script_name(english:"Debian DSA-1864-1 : linux-2.6.24 - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been discovered in the Linux kernel that may lead
to privilege escalation. The Common Vulnerabilities and Exposures
project identifies the following problem :

  - CVE-2009-2692
    Tavis Ormandy and Julien Tinnes discovered an issue with
    how the sendpage function is initialized in the
    proto_ops structure. Local users can exploit this
    vulnerability to gain elevated privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1864"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6.24 packages.

For the oldstable distribution (etch), this problem has been fixed in
version 2.6.24-6~etchnhalf.8etch3.

Note: Debian 'etch' includes linux kernel packages based upon both the
2.6.18 and 2.6.24 linux releases. All known security issues are
carefully tracked against both packages and both packages will receive
security updates until security support for Debian 'etch' concludes.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, lower severity 2.6.18 and 2.6.24 updates will
typically release in a staggered or 'leap-frog' fashion."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel Sendpage Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6.24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/16");
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
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.24", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-486", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-4kc-malta", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-5kc-malta", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-686", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-686-bigmem", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-alpha", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-amd64", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-hppa", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-i386", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-ia64", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-mips", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-mipsel", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-powerpc", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-s390", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-sparc", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-generic", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-legacy", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-smp", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-amd64", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-common", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-itanium", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-mckinley", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc-smp", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc64", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc64-smp", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc-miboot", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc-smp", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc64", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-r4k-ip22", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-r5k-cobalt", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-r5k-ip32", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-s390", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-s390x", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sb1-bcm91250a", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sb1a-bcm91480b", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sparc64", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sparc64-smp", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-486", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-4kc-malta", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-5kc-malta", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-686", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-686-bigmem", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-generic", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-legacy", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-smp", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-amd64", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-itanium", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-mckinley", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc-smp", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc64", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc64-smp", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc-miboot", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc-smp", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc64", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-r4k-ip22", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-r5k-cobalt", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-r5k-ip32", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-s390", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-s390-tape", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-s390x", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sb1-bcm91250a", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sb1a-bcm91480b", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sparc64", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sparc64-smp", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.24", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.24", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.24", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.24-etchnhalf.1", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.24", reference:"2.6.24-6~etchnhalf.8etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
