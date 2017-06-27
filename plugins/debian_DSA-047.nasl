#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-047. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38953);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-0316", "CVE-2001-1390", "CVE-2001-1391", "CVE-2001-1392", "CVE-2001-1393", "CVE-2001-1394", "CVE-2001-1395", "CVE-2001-1396", "CVE-2001-1397", "CVE-2001-1398", "CVE-2001-1399", "CVE-2001-1400");
  script_bugtraq_id(2529);
  script_osvdb_id(6017);
  script_xref(name:"DSA", value:"047");

  script_name(english:"Debian DSA-047-1 : kernel");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The kernels used in Debian GNU/Linux 2.2 have been found to have
 multiple security problems. This is a list of problems based on the
 2.2.19 release notes as found on http://www.linux.org.uk/ :

  - binfmt_misc used user pages directly
  - the CPIA driver had an off-by-one error in the buffer
    code which made it possible for users to write into
    kernel memory

  - the CPUID and MSR drivers had a problem in the module
    unloading code which could cause a system crash if they
    were set to automatically load and unload (please note
    that Debian does not automatically unload kernel
    modules)

  - There was a possible hang in the classifier code

  - The getsockopt and setsockopt system calls did not
    handle sign bits correctly which made a local DoS and
    other attacks possible

  - The sysctl system call did not handle sign bits
    correctly which allowed a user to write in kernel memory

  - ptrace/exec races that could give a local user extra
    privileges

  - possible abuse of a boundary case in the sockfilter code

  - SYSV shared memory code could overwrite recently freed
    memory which might cause problems

  - The packet length checks in the masquerading code were a
    bit lax (probably not exploitable)

  - Some x86 assembly bugs caused the wrong number of bytes
    to be copied.

  - A local user could deadlock the kernel due to bugs in
    the UDP port allocation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.linux.org.uk/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-047"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All these problems are fixed in the 2.2.19 kernel, and it is highly
recommend that you upgrade machines to this kernel.


Please note that kernel upgrades are not done automatically. You will
have to explicitly tell the packaging system to install the right
kernel for your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:various kernel packages");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"kernel-doc-2.2.19", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-headers-2.2.19", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-headers-2.2.19-compact", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-headers-2.2.19-ide", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-headers-2.2.19-idepci", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-headers-2.2.19-sparc", reference:"6")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-amiga", reference:"2.2.19-1")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-atari", reference:"2.2.19-1")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-bvme6000", reference:"2.2.19-1")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-chrp", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-compact", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-generic", reference:"2.2.19-1")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-ide", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-idepci", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-jensen", reference:"2.2.19-1")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-mac", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-mvme147", reference:"2.2.19-1")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-mvme16x", reference:"2.2.19-1")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-nautilus", reference:"2.2.19-1")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-pmac", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-prep", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-riscpc", reference:"20010414")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-smp", reference:"2.2.19-1")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-sun4cdm", reference:"6")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-sun4dm-pci", reference:"6")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-sun4dm-smp", reference:"6")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-sun4u", reference:"6")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-image-2.2.19-sun4u-smp", reference:"6")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-patch-2.2.19-arm", reference:"20010414")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-patch-2.2.19-m68k", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-patch-2.2.19-powerpc", reference:"2.2.19-2")) flag++;
if (deb_check(release:"2.2", prefix:"kernel-source-2.2.19", reference:"2.2.19-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
